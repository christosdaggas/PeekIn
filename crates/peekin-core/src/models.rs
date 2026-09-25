//! Face model store: a JSON list `[{id, label, time, data}]` plus a `format`
//! tag. Old dlib entries (no tag) are listed and removable but never matched.

use crate::fsutil::{atomic_write_owned, create_dir_all_mode};
use crate::paths::validate_username;
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

fn valid_embedding(e: &[f32]) -> bool {
    if e.len() != EMBEDDING_LEN || !e.iter().all(|x| x.is_finite()) {
        return false;
    }
    let norm = e.iter().map(|x| x * x).sum::<f32>().sqrt();
    (0.9..=1.1).contains(&norm)
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
    if metadata.mode() & 0o7777 != 0o750 {
        fs::set_permissions(models_dir, fs::Permissions::from_mode(0o750))?;
    }
    Ok(())
}

/// Why the service group cannot read `<user>.dat`, if it cannot. PAM checks
/// this before a scan, so a root-only store is not mistaken for a dead camera.
pub fn check_service_access(
    models_dir: &Path,
    user: &str,
    service_gid: libc::gid_t,
) -> Result<(), String> {
    let path = model_file(models_dir, user).map_err(|e| e.to_string())?;
    let dir =
        fs::symlink_metadata(models_dir).map_err(|e| format!("{}: {e}", models_dir.display()))?;
    if !dir.file_type().is_dir() {
        return Err(format!("{} is not a directory", models_dir.display()));
    }
    if dir.uid() != 0 || dir.gid() != service_gid || dir.mode() & 0o050 != 0o050 {
        return Err(format!(
            "{} must be owned by root:peekin with mode 0750 (found uid {} gid {} mode {:04o})",
            models_dir.display(),
            dir.uid(),
            dir.gid(),
            dir.mode() & 0o7777
        ));
    }
    let file = fs::symlink_metadata(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    if !file.file_type().is_file() {
        return Err(format!("{} is not a regular file", path.display()));
    }
    if file.uid() != 0 || file.gid() != service_gid || file.mode() & 0o040 == 0 {
        return Err(format!(
            "{} must be owned by root:peekin with mode 0640 (found uid {} gid {} mode {:04o})",
            path.display(),
            file.uid(),
            file.gid(),
            file.mode() & 0o7777
        ));
    }
    Ok(())
}

/// Load `<models_dir>/<user>.dat`.
pub fn load_user_models(models_dir: &Path, user: &str) -> Result<Vec<FaceModel>, ModelError> {
    let path = model_file(models_dir, user)?;
    if !models_dir.exists() {
        return Err(ModelError::NotInitialised);
    }
    ensure_directory(models_dir)?;
    let metadata = ensure_regular_file(&path, user)?;
    if metadata.len() > MAX_MODEL_FILE_BYTES {
        return Err(ModelError::TooLarge);
    }
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(ModelError::UnsafeStore(path.display().to_string()));
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

/// Delete the user's `.dat` (error if absent).
pub fn clear_user_models(models_dir: &Path, user: &str) -> Result<(), ModelError> {
    let path = model_file(models_dir, user)?;
    if !models_dir.exists() {
        return Err(ModelError::NotInitialised);
    }
    ensure_directory(models_dir)?;
    ensure_regular_file(&path, user)?;
    fs::remove_file(path)?;
    Ok(())
}

/// Drop one id; delete the file when it was the last model.
pub fn remove_model(models_dir: &Path, user: &str, id: &str) -> Result<(), ModelError> {
    remove_model_owned(models_dir, user, id, unsafe { libc::geteuid() }, unsafe {
        libc::getegid()
    })
}

pub fn remove_model_owned(
    models_dir: &Path,
    user: &str,
    id: &str,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> Result<(), ModelError> {
    let models = load_user_models(models_dir, user)?;
    if !models.iter().any(|m| m.id.to_string() == id) {
        return Err(ModelError::UnknownId(id.into(), user.into()));
    }
    if models.len() == 1 {
        fs::remove_file(model_file(models_dir, user)?)?;
        return Ok(());
    }
    let kept: Vec<FaceModel> = models
        .into_iter()
        .filter(|m| m.id.to_string() != id)
        .collect();
    save_user_models_owned(models_dir, user, &kept, uid, gid)
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
            let norm = e.iter().map(|x| x * x).sum::<f32>().sqrt();
            if !(0.5..=2.0).contains(&norm) {
                return Err("sample is not a normalised embedding".to_string());
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
            clear_user_models(&models_dir, "../victim"),
            Err(ModelError::InvalidUser(_))
        ));
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
    fn remove_middle_and_last() {
        let dir = tmpdir("remove");
        save_user_models(&dir, "alice", &sample()).unwrap();
        remove_model(&dir, "alice", "0").unwrap();
        let back = load_user_models(&dir, "alice").unwrap();
        assert_eq!(back.len(), 1);
        assert_eq!(back[0].id, 1);
        remove_model(&dir, "alice", "1").unwrap();
        assert!(!dir.join("alice.dat").exists());
        let _ = fs::remove_dir_all(&dir);
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
    fn remove_unknown_id_errors() {
        let dir = tmpdir("unknown");
        save_user_models(&dir, "alice", &sample()).unwrap();
        assert!(matches!(
            remove_model(&dir, "alice", "99"),
            Err(ModelError::UnknownId(_, _))
        ));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_removes_all_models() {
        let dir = tmpdir("clear");
        assert!(matches!(
            clear_user_models(&dir, "alice"),
            Err(ModelError::NoModelForUser(_))
        ));
        save_user_models(&dir, "alice", &sample()).unwrap();
        clear_user_models(&dir, "alice").unwrap();
        assert!(!dir.join("alice.dat").exists());
        let _ = fs::remove_dir_all(&dir);
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
    fn plain_row_format() {
        let m = &sample()[0];
        let row = format_model_row(m, true);
        assert!(row.starts_with("0,"));
        assert!(row.ends_with(",Model #0"));
    }
}
