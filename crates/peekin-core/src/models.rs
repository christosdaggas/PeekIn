//! Face model store: a JSON list `[{id, label, time, data}]` plus a `format`
//! tag. Old dlib entries (no tag) are listed and removable but never matched.

use crate::fsutil::{atomic_write_owned, create_dir_all_mode};
use crate::paths::{validate_username, PeekinPaths};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Embeddings from `peekin-vision` (OpenCV SFace, L2-normalised).
pub const EMBEDDING_FORMAT: &str = "opencv-sface-2021dec";
pub const MAX_MODEL_FILE_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ModelError {
    #[error("no models initialised yet, run `peekin add` first")]
    NotInitialised,
    #[error("{0} has no face model")]
    NoModelForUser(String),
    #[error("no model with ID {0} exists for {1}")]
    UnknownId(String, String),
    #[error(transparent)]
    InvalidUser(#[from] crate::paths::InvalidUsername),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("model file corrupt: {0}")]
    Corrupt(#[from] serde_json::Error),
    #[error("model file exceeds {MAX_MODEL_FILE_BYTES} bytes")]
    TooLarge,
    #[error("unsafe model store entry: {0}")]
    UnsafeStore(String),
    #[error("model {0} already has {1} samples; add a new face model instead")]
    Full(i64, usize),
    #[error("model {0} is in an old format; remove it and add a new one")]
    LegacyModel(i64),
}

pub struct ModelLock {
    _file: fs::File,
}

/// Serialise a whole read/update/write of one user's models.
pub fn lock_user_models(models_dir: &Path, user: &str) -> Result<ModelLock, ModelError> {
    validate_username(user)?;
    create_dir_all_mode(models_dir, 0o750)?;
    ensure_directory(models_dir)?;
    let path = models_dir.join(format!(".{user}.lock"));
    let file = fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(ModelError::UnsafeStore(path.display().to_string()));
    }
    // SAFETY: flock operates on a live descriptor and unlocks when dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(ModelError::Io(std::io::Error::last_os_error()));
    }
    Ok(ModelLock { _file: file })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FaceModel {
    pub id: i64,
    pub label: String,
    /// Unix timestamp.
    pub time: i64,
    /// Embedding model; `None` for old dlib entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    pub data: Vec<Vec<f64>>,
}

impl FaceModel {
    /// Truncate the label and strip commas.
    pub fn sanitise_label(label: &str) -> String {
        label
            .chars()
            .filter(|c| !c.is_control() && *c != ',')
            .take(24)
            .collect::<String>()
            .trim()
            .to_string()
    }

    pub fn next_id(models: &[FaceModel]) -> i64 {
        models.last().map(|m| m.id + 1).unwrap_or(0)
    }

    pub fn is_current_format(&self) -> bool {
        self.format.as_deref() == Some(EMBEDDING_FORMAT)
    }
}

pub fn usable_embeddings(models: &[FaceModel]) -> Vec<(usize, Vec<f32>)> {
    models
        .iter()
        .enumerate()
        .filter(|(_, m)| m.is_current_format())
        .flat_map(|(i, m)| {
            m.data.iter().filter_map(move |e| {
                let converted: Vec<f32> = e.iter().map(|&x| x as f32).collect();
                valid_embedding(&converted).then_some((i, converted))
            })
        })
        .collect()
}

/// L2 norms of the samples recognition uses (SFace output normalised to 1).
const EMBEDDING_NORMS: std::ops::RangeInclusive<f32> = 0.9..=1.1;

fn embedding_norm(e: &[f32]) -> f32 {
    e.iter().map(|x| x * x).sum::<f32>().sqrt()
}

/// The one rule for a sample, at import and at recognition.
fn valid_embedding(e: &[f32]) -> bool {
    if e.len() != EMBEDDING_LEN || !e.iter().all(|x| x.is_finite()) {
        return false;
    }
    EMBEDDING_NORMS.contains(&embedding_norm(e))
}

fn model_file(models_dir: &Path, user: &str) -> Result<PathBuf, ModelError> {
    validate_username(user)?;
    Ok(models_dir.join(format!("{user}.dat")))
}

fn ensure_directory(path: &Path) -> Result<fs::Metadata, ModelError> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_dir() || metadata.file_type().is_symlink() {
        return Err(ModelError::UnsafeStore(path.display().to_string()));
    }
    Ok(metadata)
}

fn ensure_regular_file(path: &Path, user: &str) -> Result<fs::Metadata, ModelError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(metadata),
        Ok(_) => Err(ModelError::UnsafeStore(path.display().to_string())),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            Err(ModelError::NoModelForUser(user.into()))
        }
        Err(error) => Err(error.into()),
    }
}

/// Prepare the root-owned model directory for atomic writes.
pub fn prepare_model_store(
    models_dir: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), ModelError> {
    create_dir_all_mode(models_dir, 0o750)?;
    let metadata = ensure_directory(models_dir)?;
    let path = std::ffi::CString::new(models_dir.as_os_str().as_bytes())
        .map_err(|_| ModelError::UnsafeStore(models_dir.display().to_string()))?;
    if unsafe { libc::chown(path.as_ptr(), uid, gid) } != 0 {
        return Err(ModelError::Io(std::io::Error::last_os_error()));
    }
    // check_service_access refuses ACLs; new model files inherit the default one.
    for name in [ACL_XATTR, c"system.posix_acl_default"] {
        // SAFETY: both strings are NUL-terminated.
        acl_found(unsafe { libc::lremovexattr(path.as_ptr(), name.as_ptr()) } as libc::ssize_t)?;
    }
    if metadata.mode() & 0o7777 != 0o750 {
        fs::set_permissions(models_dir, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

/// Why the service group cannot read `<user>.dat`, or others could read or
/// change it, if so. PAM checks this before a scan, so a root-only store is not
/// mistaken for a dead camera and a face model others can change is not trusted.
pub fn check_service_access(
    models_dir: &Path,
    user: &str,
    service_gid: libc::gid_t,
) -> Result<(), String> {
    check_store(models_dir, user, 0, service_gid)
}

/// [`check_service_access`] for a store owned by `owner` (root when installed).
fn check_store(
    models_dir: &Path,
    user: &str,
    owner: libc::uid_t,
    service_gid: libc::gid_t,
) -> Result<(), String> {
    let path = model_file(models_dir, user).map_err(|e| e.to_string())?;
    let dir =
        fs::symlink_metadata(models_dir).map_err(|e| format!("{}: {e}", models_dir.display()))?;
    if !dir.file_type().is_dir() {
        return Err(format!("{} is not a directory", models_dir.display()));
    }
    check_entry(
        models_dir,
        &dir,
        path_has_acl(models_dir),
        owner,
        service_gid,
    )?;
    let file = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !file.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    check_entry(&path, &file, path_has_acl(&path), owner, service_gid)
}

/// The installed store's rule for its directory and each model in it: owned
/// by `owner` (root) and group `service_gid` (peekin), which may read (and
/// search) but not write it, nothing for others (only the service group reads
/// face models), and no access ACL, which can give other accounts access the
/// mode does not show.
fn check_entry(
    path: &Path,
    metadata: &fs::Metadata,
    acl: std::io::Result<bool>,
    owner: libc::uid_t,
    service_gid: libc::gid_t,
) -> Result<(), String> {
    let (read, required) = if metadata.is_dir() {
        (0o050, "0750")
    } else {
        (0o040, "0640")
    };
    let mode = metadata.mode() & 0o7777;
    if metadata.uid() != owner
        || metadata.gid() != service_gid
        || mode & read != read
        || mode & 0o027 != 0
    {
        return Err(format!(
            "{} must be owned by root:peekin with mode {required} (found uid {} gid {} mode {mode:04o})",
            path.display(),
            metadata.uid(),
            metadata.gid(),
        ));
    }
    match acl {
        Ok(false) => Ok(()),
        Ok(true) => Err(format!(
            "{} has a POSIX ACL, which can give other accounts access its mode {mode:04o} \
             does not show; it must have none",
            path.display()
        )),
        Err(error) => Err(format!(
            "cannot read the ACL of {}: {error}",
            path.display()
        )),
    }
}

/// Extended attribute holding a POSIX access ACL.
const ACL_XATTR: &std::ffi::CStr = c"system.posix_acl_access";

/// Whether the getxattr or removexattr call that returned `result` found an
/// ACL. File systems without ACL support have none.
fn acl_found(result: libc::ssize_t) -> std::io::Result<bool> {
    if result >= 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ENODATA | libc::EOPNOTSUPP) => Ok(false),
        _ => Err(error),
    }
}

fn path_has_acl(path: &Path) -> std::io::Result<bool> {
    let path = std::ffi::CString::new(path.as_os_str().as_bytes())?;
    // SAFETY: NUL-terminated strings; a null buffer of size 0 only asks for the size.
    acl_found(unsafe {
        libc::lgetxattr(path.as_ptr(), ACL_XATTR.as_ptr(), std::ptr::null_mut(), 0)
    })
}

fn file_has_acl(file: &fs::File) -> std::io::Result<bool> {
    // SAFETY: as in `path_has_acl`, on a live descriptor.
    acl_found(unsafe {
        libc::fgetxattr(
            file.as_raw_fd(),
            ACL_XATTR.as_ptr(),
            std::ptr::null_mut(),
            0,
        )
    })
}

/// Load `<models_dir>/<user>.dat`.
pub fn load_user_models(models_dir: &Path, user: &str) -> Result<Vec<FaceModel>, ModelError> {
    load_models(models_dir, user, None)
}

/// Load `user`'s models for the recognition worker. On an installed system
/// the store must pass [`check_service_access`], and the model file is checked
/// on the opened descriptor, so a file swapped in after PAM's check is refused
/// too. The worker runs with the service group as its effective group.
pub fn load_service_models(paths: &PeekinPaths, user: &str) -> Result<Vec<FaceModel>, ModelError> {
    // SAFETY: getegid cannot fail.
    let service = paths
        .sealed_models_dir()
        .map(|_| (0, unsafe { libc::getegid() }));
    load_models(paths.user_models_dir(), user, service)
}

/// `service`: the owner and group an installed store must have.
fn load_models(
    models_dir: &Path,
    user: &str,
    service: Option<(libc::uid_t, libc::gid_t)>,
) -> Result<Vec<FaceModel>, ModelError> {
    let path = model_file(models_dir, user)?;
    if !models_dir.exists() {
        return Err(ModelError::NotInitialised);
    }
    let dir = ensure_directory(models_dir)?;
    if let Some((owner, gid)) = service {
        check_entry(models_dir, &dir, path_has_acl(models_dir), owner, gid)
            .map_err(ModelError::UnsafeStore)?;
    }
    let metadata = ensure_regular_file(&path, user)?;
    if metadata.len() > MAX_MODEL_FILE_BYTES {
        return Err(ModelError::TooLarge);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(ModelError::UnsafeStore(path.display().to_string()));
    }
    if let Some((owner, gid)) = service {
        check_entry(&path, &opened, file_has_acl(&file), owner, gid)
            .map_err(ModelError::UnsafeStore)?;
    }
    let mut raw = String::new();
    file.take(MAX_MODEL_FILE_BYTES + 1)
        .read_to_string(&mut raw)?;
    if raw.len() as u64 > MAX_MODEL_FILE_BYTES {
        return Err(ModelError::TooLarge);
    }
    Ok(serde_json::from_str(&raw)?)
}

/// Root-owned directory 0750 and files 0640, readable by the service group.
pub fn save_user_models(
    models_dir: &Path,
    user: &str,
    models: &[FaceModel],
) -> Result<(), ModelError> {
    save_user_models_owned(
        models_dir,
        user,
        models,
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
    )
}

pub fn save_user_models_owned(
    models_dir: &Path,
    user: &str,
    models: &[FaceModel],
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), ModelError> {
    let path = model_file(models_dir, user)?;
    prepare_model_store(models_dir, uid, gid)?;
    let raw = serde_json::to_string(models)?;
    if raw.len() as u64 > MAX_MODEL_FILE_BYTES {
        return Err(ModelError::TooLarge);
    }
    atomic_write_owned(&path, raw.as_bytes(), 0o640, uid, gid)?;
    Ok(())
}

/// Samples per model at most: each sample is another chance for a stranger
/// to match (docs/THRESHOLDS.md).
pub const MAX_MODEL_SAMPLES: usize = 15;

/// Add samples to model `id`; returns its new sample count.
pub fn append_samples(
    models: &mut [FaceModel],
    id: &str,
    user: &str,
    data: Vec<Vec<f64>>,
) -> Result<usize, ModelError> {
    let model = models
        .iter_mut()
        .find(|m| m.id.to_string() == id)
        .ok_or_else(|| ModelError::UnknownId(id.into(), user.into()))?;
    if !model.is_current_format() {
        return Err(ModelError::LegacyModel(model.id));
    }
    if model.data.len() + data.len() > MAX_MODEL_SAMPLES {
        return Err(ModelError::Full(model.id, model.data.len()));
    }
    model.data.extend(data);
    Ok(model.data.len())
}

pub const EMBEDDING_LEN: usize = 128;
pub const MAX_IMPORT_SAMPLES: usize = 20;

#[derive(Debug, Deserialize)]
struct ImportedModel {
    format: String,
    embeddings: Vec<Vec<f32>>,
}

/// Check samples enrolled elsewhere (the settings app, via
/// `peekin import-model`).
pub fn parse_import(json: &str) -> Result<Vec<Vec<f64>>, String> {
    let m: ImportedModel =
        serde_json::from_str(json).map_err(|e| format!("invalid model data: {e}"))?;
    if m.format != EMBEDDING_FORMAT {
        return Err(format!("unsupported model format {:?}", m.format));
    }
    if m.embeddings.is_empty() || m.embeddings.len() > MAX_IMPORT_SAMPLES {
        return Err(format!(
            "expected 1 to {MAX_IMPORT_SAMPLES} samples, got {}",
            m.embeddings.len()
        ));
    }
    m.embeddings
        .into_iter()
        .map(|e| {
            if e.len() != EMBEDDING_LEN || !e.iter().all(|x| x.is_finite()) {
                return Err(format!(
                    "each sample must be {EMBEDDING_LEN} finite numbers"
                ));
            }
            // Stored samples recognition would skip could never match.
            if !valid_embedding(&e) {
                return Err(format!(
                    "sample is not a normalised embedding: its norm is {:.3}, recognition uses {} to {}",
                    embedding_norm(&e),
                    EMBEDDING_NORMS.start(),
                    EMBEDDING_NORMS.end()
                ));
            }
            Ok(e.into_iter().map(f64::from).collect())
        })
        .collect()
}

/// One row of `peekin list --plain`: `id,time,label` in local time.
pub fn format_model_row(m: &FaceModel, plain: bool) -> String {
    use chrono::{Local, TimeZone};
    let dt = Local.timestamp_opt(m.time, 0).single();
    let timestr = dt
        .map(|d| d.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| m.time.to_string());
    if plain {
        format!("{},{},{}", m.id, timestr, m.label)
    } else {
        let note = if m.is_current_format() {
            ""
        } else {
            "  (old dlib model, not used)"
        };
        format!("{:<4}{}  {}{note}", m.id, timestr, m.label)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("peekin-models-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    fn model(id: i64, label: &str, format: Option<&str>, v: f64) -> FaceModel {
        FaceModel {
            id,
            label: label.into(),
            time: 1_700_000_000 + id,
            format: format.map(str::to_owned),
            data: vec![vec![v; 128]],
        }
    }

    fn sample() -> Vec<FaceModel> {
        let unit = 1.0 / (EMBEDDING_LEN as f64).sqrt();
        vec![
            model(0, "Model #0", Some(EMBEDDING_FORMAT), unit),
            model(1, "work", Some(EMBEDDING_FORMAT), -unit),
        ]
    }

    #[test]
    fn service_access_reports_a_root_only_store() {
        let dir = tmpdir("service-access");
        let models = dir.join("models");
        fs::create_dir(&models).unwrap();
        fs::write(models.join("alice.dat"), "[]").unwrap();
        let gid = unsafe { libc::getegid() };
        let as_root = unsafe { libc::geteuid() } == 0;
        if as_root {
            let c = std::ffi::CString::new(models.as_os_str().as_bytes()).unwrap();
            let f =
                std::ffi::CString::new(models.join("alice.dat").as_os_str().as_bytes()).unwrap();
            // A group other than root's, standing in for peekin.
            unsafe {
                libc::chown(c.as_ptr(), 0, 4242);
                libc::chown(f.as_ptr(), 0, 4242);
            }
            fs::set_permissions(&models, fs::Permissions::from_mode(0o700)).unwrap();
            fs::set_permissions(models.join("alice.dat"), fs::Permissions::from_mode(0o640))
                .unwrap();
            let error = check_service_access(&models, "alice", 4242).unwrap_err();
            assert!(error.contains("mode 0700"), "{error}");
            fs::set_permissions(&models, fs::Permissions::from_mode(0o750)).unwrap();
            assert_eq!(check_service_access(&models, "alice", 4242), Ok(()));
            fs::set_permissions(models.join("alice.dat"), fs::Permissions::from_mode(0o600))
                .unwrap();
            assert!(check_service_access(&models, "alice", 4242).is_err());
        } else {
            // Not root-owned: always refused.
            assert!(check_service_access(&models, "alice", gid).is_err());
        }
        assert!(check_service_access(&models, "bob", gid).is_err());
        assert!(check_service_access(&dir.join("missing"), "alice", gid).is_err());
        assert!(check_service_access(&models, "../alice", gid).is_err());
        let _ = fs::remove_dir_all(dir);
    }

    fn me() -> (libc::uid_t, libc::gid_t) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    fn chmod(path: &Path, mode: u32) {
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    /// A store laid out as installed (0750, 0640) but owned by the current
    /// user: tests cannot create root-owned files.
    fn own_store(name: &str) -> (PathBuf, PathBuf) {
        let dir = tmpdir(name);
        let models = dir.join("models");
        save_user_models(&models, "alice", &sample()).unwrap();
        (dir, models)
    }

    /// Runs setfacl; `false`, with a note, where the tool is missing or the
    /// file system refuses ACLs.
    fn setfacl(args: &[&str], path: &Path) -> bool {
        let outcome = std::process::Command::new("setfacl")
            .args(args)
            .arg(path)
            .status();
        match outcome {
            Ok(status) if status.success() => true,
            other => {
                eprintln!(
                    "skipping the ACL case: setfacl {args:?} {}: {other:?}",
                    path.display()
                );
                false
            }
        }
    }

    #[test]
    fn store_writable_by_the_group_or_open_to_others_is_refused() {
        let (dir, models) = own_store("writable");
        let file = models.join("alice.dat");
        let (uid, gid) = me();
        assert_eq!(check_store(&models, "alice", uid, gid), Ok(()));
        assert!(check_store(&models, "alice", uid + 1, gid).is_err());
        assert!(check_store(&models, "alice", uid, gid + 1).is_err());
        for mode in [0o600, 0o660, 0o642, 0o666, 0o644, 0o641] {
            chmod(&file, mode);
            let error = check_store(&models, "alice", uid, gid).unwrap_err();
            let found = format!("mode {mode:04o})");
            assert!(
                error.contains("alice.dat")
                    && error.contains("mode 0640")
                    && error.contains(&found),
                "{error}"
            );
        }
        chmod(&file, 0o640);
        for mode in [0o700, 0o770, 0o752, 0o777, 0o755, 0o751] {
            chmod(&models, mode);
            let error = check_store(&models, "alice", uid, gid).unwrap_err();
            let found = format!("mode {mode:04o})");
            assert!(
                !error.contains("alice.dat")
                    && error.contains("mode 0750")
                    && error.contains(&found),
                "{error}"
            );
        }
        chmod(&models, 0o750);
        assert_eq!(check_store(&models, "alice", uid, gid), Ok(()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn store_with_an_acl_is_refused() {
        let (dir, models) = own_store("acl");
        let file = models.join("alice.dat");
        let (uid, gid) = me();
        // Read access for another account; the mode still shows 0640.
        if !setfacl(&["-m", "u:65534:r"], &file) {
            let _ = fs::remove_dir_all(dir);
            return;
        }
        assert_eq!(fs::metadata(&file).unwrap().mode() & 0o7777, 0o640);
        let error = check_store(&models, "alice", uid, gid).unwrap_err();
        assert!(
            error.contains("alice.dat") && error.contains("ACL"),
            "{error}"
        );
        let loaded = load_models(&models, "alice", Some((uid, gid)));
        assert!(
            matches!(&loaded, Err(ModelError::UnsafeStore(m)) if m.contains("ACL")),
            "{:?}",
            loaded.as_ref().map(Vec::len)
        );
        assert!(setfacl(&["-b"], &file));
        assert_eq!(check_store(&models, "alice", uid, gid), Ok(()));
        assert!(setfacl(&["-m", "u:65534:rx"], &models));
        assert_eq!(fs::metadata(&models).unwrap().mode() & 0o7777, 0o750);
        let error = check_store(&models, "alice", uid, gid).unwrap_err();
        assert!(
            !error.contains("alice.dat") && error.contains("ACL"),
            "{error}"
        );
        let loaded = load_models(&models, "alice", Some((uid, gid)));
        assert!(
            matches!(&loaded, Err(ModelError::UnsafeStore(m)) if m.contains("ACL")),
            "{:?}",
            loaded.as_ref().map(Vec::len)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn preparing_the_store_removes_acls() {
        let dir = tmpdir("strip-acl");
        let models = dir.join("models");
        fs::create_dir(&models).unwrap();
        // An access ACL and a default one, which new model files would inherit.
        if !setfacl(&["-m", "u:65534:rx,d:u:65534:rx"], &models) {
            let _ = fs::remove_dir_all(dir);
            return;
        }
        let (uid, gid) = me();
        save_user_models_owned(&models, "alice", &sample(), uid, gid).unwrap();
        assert_eq!(check_store(&models, "alice", uid, gid), Ok(()));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn worker_checks_the_opened_model_on_installed_systems_only() {
        let (dir, models) = own_store("worker");
        let file = models.join("alice.dat");
        let service = Some(me());
        assert_eq!(load_models(&models, "alice", service).unwrap(), sample());
        assert!(matches!(
            load_models(&models, "bob", service),
            Err(ModelError::NoModelForUser(_))
        ));
        for (path, bad, good) in [
            (&file, 0o660, 0o640),
            (&file, 0o644, 0o640),
            (&models, 0o777, 0o750),
            (&models, 0o755, 0o750),
        ] {
            chmod(path, bad);
            let loaded = load_models(&models, "alice", service);
            let found = format!("mode {bad:04o}");
            assert!(
                matches!(&loaded, Err(ModelError::UnsafeStore(m)) if m.contains(&found)),
                "{found}: {:?}",
                loaded.as_ref().map(Vec::len)
            );
            chmod(path, good);
        }
        chmod(&file, 0o660);
        // The worker's entry point applies the policy to the installed layout only.
        let mut paths = PeekinPaths::from_dirs(dir.join("etc"), dir.join("data"));
        paths.user_models_dir = models.clone();
        assert_eq!(load_service_models(&paths, "alice").unwrap(), sample());
        paths.sealed_models_dir = Some(dir.join("etc").join("models"));
        let loaded = load_service_models(&paths, "alice");
        assert!(
            matches!(loaded, Err(ModelError::UnsafeStore(_))),
            "{:?}",
            loaded.as_ref().map(Vec::len)
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn save_load_roundtrip_with_private_permissions() {
        let dir = tmpdir("roundtrip");
        let models_dir = dir.join("models");
        save_user_models(&models_dir, "alice", &sample()).unwrap();
        assert_eq!(load_user_models(&models_dir, "alice").unwrap(), sample());
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&models_dir), 0o750);
        assert_eq!(mode(&models_dir.join("alice.dat")), 0o640);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn reads_files_without_format_tag() {
        let dir = tmpdir("legacy");
        fs::write(
            dir.join("bob.dat"),
            r#"[{"time": 1700000000, "label": "Initial model", "id": 0, "data": [[0.5, 0.25]]}]"#,
        )
        .unwrap();
        let models = load_user_models(&dir, "bob").unwrap();
        assert_eq!(models[0].format, None);
        assert!(
            usable_embeddings(&models).is_empty(),
            "dlib vectors must not be matched"
        );
        assert!(format_model_row(&models[0], false).contains("old dlib model"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn usable_embeddings_keep_model_index() {
        let mut models = sample();
        models.insert(0, model(9, "legacy", None, 0.9));
        let usable = usable_embeddings(&models);
        assert_eq!(
            usable.iter().map(|(i, _)| *i).collect::<Vec<_>>(),
            vec![1, 2]
        );
        assert_eq!(usable[0].1.len(), 128);
    }

    #[test]
    fn traversal_usernames_rejected_everywhere() {
        let dir = tmpdir("traversal");
        let victim = dir.join("victim.dat");
        fs::write(&victim, "[]").unwrap();
        let models_dir = dir.join("models");
        fs::create_dir_all(&models_dir).unwrap();
        assert!(matches!(
            load_user_models(&models_dir, "../victim"),
            Err(ModelError::InvalidUser(_))
        ));
        assert!(matches!(
            save_user_models(&models_dir, "../victim", &[]),
            Err(ModelError::InvalidUser(_))
        ));
        assert!(victim.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_symlinked_model_and_lock_files() {
        use std::os::unix::fs::symlink;

        let dir = tmpdir("symlinks");
        let victim = dir.join("victim");
        fs::write(&victim, "[]").unwrap();
        symlink(&victim, dir.join("alice.dat")).unwrap();
        assert!(matches!(
            load_user_models(&dir, "alice"),
            Err(ModelError::UnsafeStore(_))
        ));
        assert!(matches!(
            save_user_models(&dir, "alice", &sample()),
            Err(ModelError::Io(_))
        ));
        assert_eq!(fs::read_to_string(&victim).unwrap(), "[]");

        symlink(&victim, dir.join(".bob.lock")).unwrap();
        assert!(matches!(
            lock_user_models(&dir, "bob"),
            Err(ModelError::Io(_))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn rejects_oversized_model_file_before_parsing() {
        let dir = tmpdir("oversized");
        let file = fs::File::create(dir.join("alice.dat")).unwrap();
        file.set_len(MAX_MODEL_FILE_BYTES + 1).unwrap();
        assert!(matches!(
            load_user_models(&dir, "alice"),
            Err(ModelError::TooLarge)
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn owned_atomic_replacement_keeps_owner_group_and_mode() {
        let dir = tmpdir("owned");
        let uid = unsafe { libc::geteuid() };
        let gid = unsafe { libc::getegid() };
        save_user_models_owned(&dir, "alice", &sample(), uid, gid).unwrap();
        save_user_models_owned(&dir, "alice", &sample(), uid, gid).unwrap();
        let metadata = fs::symlink_metadata(dir.join("alice.dat")).unwrap();
        assert_eq!(metadata.uid(), uid);
        assert_eq!(metadata.gid(), gid);
        assert_eq!(metadata.mode() & 0o777, 0o640);
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_dir_and_user_map_correctly() {
        let dir = std::env::temp_dir().join("peekin-models-definitely-missing");
        let _ = fs::remove_dir_all(&dir);
        assert!(matches!(
            load_user_models(&dir, "bob"),
            Err(ModelError::NotInitialised)
        ));
        let dir2 = tmpdir("nouser");
        assert!(matches!(
            load_user_models(&dir2, "bob"),
            Err(ModelError::NoModelForUser(_))
        ));
        let _ = fs::remove_dir_all(&dir2);
    }

    #[test]
    fn samples_are_appended_up_to_the_cap() {
        let unit = 1.0 / (EMBEDDING_LEN as f64).sqrt();
        let mut models = sample();
        let five = vec![vec![unit; EMBEDDING_LEN]; 5];
        let before = models[1].data.len();
        assert_eq!(
            append_samples(&mut models, "1", "alice", five.clone()).unwrap(),
            before + 5
        );
        assert_eq!(
            models[0].data.len(),
            sample()[0].data.len(),
            "other models untouched"
        );
        while models[1].data.len() + 5 <= MAX_MODEL_SAMPLES {
            append_samples(&mut models, "1", "alice", five.clone()).unwrap();
        }
        assert!(matches!(
            append_samples(&mut models, "1", "alice", five.clone()),
            Err(ModelError::Full(1, _))
        ));
        assert!(matches!(
            append_samples(&mut models, "9", "alice", five.clone()),
            Err(ModelError::UnknownId(_, _))
        ));
        let mut legacy = vec![model(3, "old", None, unit)];
        assert!(matches!(
            append_samples(&mut legacy, "3", "alice", five),
            Err(ModelError::LegacyModel(3))
        ));
    }

    #[test]
    fn label_sanitise() {
        assert_eq!(FaceModel::sanitise_label("a,b,c"), "abc");
        assert_eq!(FaceModel::sanitise_label(&"x".repeat(30)).len(), 24);
        assert_eq!(FaceModel::next_id(&sample()), 2);
        assert_eq!(FaceModel::next_id(&[]), 0);
        assert_eq!(FaceModel::sanitise_label(" a\n\u{1b},b "), "ab");
    }

    fn import_json(format: &str, samples: usize, len: usize, v: f32) -> String {
        let one = vec![v; len];
        serde_json::json!({ "format": format, "embeddings": vec![one; samples] }).to_string()
    }

    #[test]
    fn import_accepts_valid_samples() {
        let v = 1.0 / (EMBEDDING_LEN as f32).sqrt();
        let data = parse_import(&import_json(EMBEDDING_FORMAT, 5, EMBEDDING_LEN, v)).unwrap();
        assert_eq!(data.len(), 5);
        assert_eq!(data[0].len(), EMBEDDING_LEN);
    }

    #[test]
    fn import_rejects_bad_input() {
        let v = 1.0 / (EMBEDDING_LEN as f32).sqrt();
        assert!(parse_import("not json").is_err());
        assert!(parse_import(&import_json("dlib", 5, EMBEDDING_LEN, v)).is_err());
        assert!(parse_import(&import_json(EMBEDDING_FORMAT, 0, EMBEDDING_LEN, v)).is_err());
        assert!(parse_import(&import_json(
            EMBEDDING_FORMAT,
            MAX_IMPORT_SAMPLES + 1,
            EMBEDDING_LEN,
            v
        ))
        .is_err());
        assert!(parse_import(&import_json(EMBEDDING_FORMAT, 5, 64, v)).is_err());
        assert!(parse_import(&import_json(EMBEDDING_FORMAT, 5, EMBEDDING_LEN, 10.0)).is_err());
        assert!(parse_import(&import_json(EMBEDDING_FORMAT, 5, EMBEDDING_LEN, 0.0)).is_err());
    }

    #[test]
    fn import_accepts_exactly_the_norms_recognition_uses() {
        let value = |norm: f32| norm / (EMBEDDING_LEN as f32).sqrt();
        let with_norm = |norm| import_json(EMBEDDING_FORMAT, 3, EMBEDDING_LEN, value(norm));
        let error = parse_import(&with_norm(0.75)).map(|d| d.len()).unwrap_err();
        assert!(
            error.contains("0.750") && error.contains("0.9 to 1.1"),
            "{error}"
        );
        assert_eq!(parse_import(&with_norm(1.0)).unwrap().len(), 3);
        for norm in [0.5, 0.75, 0.85, 0.95, 1.0, 1.05, 1.2, 2.0] {
            let stored = FaceModel {
                data: vec![vec![f64::from(value(norm)); EMBEDDING_LEN]],
                ..model(0, "m", Some(EMBEDDING_FORMAT), 0.0)
            };
            assert_eq!(
                parse_import(&with_norm(norm)).is_ok(),
                !usable_embeddings(&[stored]).is_empty(),
                "norm {norm}"
            );
        }
    }

    #[test]
    fn plain_row_format() {
        let m = &sample()[0];
        let row = format_model_row(m, true);
        assert!(row.starts_with("0,"));
        assert!(row.ends_with(",Model #0"));
    }
}
