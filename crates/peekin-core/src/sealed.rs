//! Face models encrypted at rest with `systemd-creds` (TPM2 plus host key, or
//! the host key alone), not bound to PCRs. Everything reads the decrypted copies
//! in [`RUN_MODELS_DIR`] (tmpfs). This protects disks and backups, not against
//! root or someone holding the whole machine. Development trees stay plaintext.

use crate::fsutil;
use crate::models::{self, FaceModel};
use crate::paths::{validate_username, PeekinPaths};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const RUN_MODELS_DIR: &str = "/run/peekin/models";
pub const TOOL: &str = "systemd-creds";
const SUFFIX: &str = ".dat.cred";

fn credential_name(user: &str) -> String {
    format!("peekin-model-{user}")
}

pub fn sealed_path(sealed_dir: &Path, user: &str) -> PathBuf {
    sealed_dir.join(format!("{user}{SUFFIX}"))
}

fn plain_path(dir: &Path, user: &str) -> PathBuf {
    dir.join(format!("{user}.dat"))
}

pub fn key_description() -> &'static str {
    if Path::new("/dev/tpmrm0").exists() {
        "the TPM and the host key"
    } else {
        "the host key file only (no TPM found)"
    }
}

fn run(tool: &Path, args: &[&str], input: &[u8]) -> io::Result<Vec<u8>> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run {}: {e}", tool.display())))?;
    // A tool that fails early stops reading; its exit status says why.
    match child.stdin.take().expect("piped").write_all(input) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
        _ => {}
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{} {} failed: {}",
            tool.display(),
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Encrypt into `<sealed_dir>/<user>.dat.cred` (root-only, atomic).
fn seal_bytes(tool: &Path, sealed_dir: &Path, user: &str, plaintext: &[u8]) -> io::Result<()> {
    let target = sealed_path(sealed_dir, user);
    let tmp = sealed_dir.join(format!(".{user}{SUFFIX}.new"));
    let _ = fs::remove_file(&tmp);
    let name = format!("--name={}", credential_name(user));
    let tmp_arg = tmp.to_string_lossy().into_owned();
    let result = run(tool, &["encrypt", &name, "-", &tmp_arg], plaintext).and_then(|_| {
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, &target)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn unseal_bytes(tool: &Path, sealed_dir: &Path, user: &str) -> io::Result<Vec<u8>> {
    let name = format!("--name={}", credential_name(user));
    let source = sealed_path(sealed_dir, user).to_string_lossy().into_owned();
    run(tool, &["decrypt", &name, &source, "-"], &[])
}

fn remove_if_present(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// Seal `new`, or delete the sealed copy for `None`.
fn write_sealed(
    tool: &Path,
    sealed_dir: &Path,
    user: &str,
    new: Option<&[FaceModel]>,
) -> io::Result<()> {
    match new {
        Some(new) => {
            let bytes = serde_json::to_vec(new)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
            seal_bytes(tool, sealed_dir, user, &bytes)
        }
        None => remove_if_present(&sealed_path(sealed_dir, user)),
    }
}

/// Write the plaintext copy, or delete it for `None`.
fn write_plain(
    dir: &Path,
    user: &str,
    new: Option<&[FaceModel]>,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<()> {
    match new {
        Some(new) => {
            models::save_user_models_owned(dir, user, new, uid, gid).map_err(io::Error::other)
        }
        None => remove_if_present(&plain_path(dir, user)),
    }
}

fn not_applied(reason: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("the change was not applied: {reason}"))
}

/// Replace `user`'s face models with `new` (`None`: delete them) in both the
/// sealed copy and the decrypted copy in use, or in neither. The sealed copy
/// is written first, so a failing `systemd-creds` changes nothing; if the copy
/// in use cannot be written after that, the previous sealed file is put back.
/// Development trees only have the plaintext copy.
pub fn replace_models(
    paths: &PeekinPaths,
    user: &str,
    new: Option<&[FaceModel]>,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<()> {
    replace_models_with(
        Path::new(TOOL),
        paths.user_models_dir(),
        paths.sealed_models_dir(),
        user,
        new,
        uid,
        gid,
    )
}

fn replace_models_with(
    tool: &Path,
    run_dir: &Path,
    sealed_dir: Option<&Path>,
    user: &str,
    new: Option<&[FaceModel]>,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<()> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let Some(sealed_dir) = sealed_dir else {
        return write_plain(run_dir, user, new, uid, gid);
    };
    let cred = sealed_path(sealed_dir, user);
    let previous = match fs::read(&cred) {
        Ok(bytes) => Some(bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => None,
        Err(e) => return Err(not_applied(format!("{}: {e}", cred.display()))),
    };
    write_sealed(tool, sealed_dir, user, new)
        .map_err(|e| not_applied(format!("its encrypted copy could not be updated: {e}")))?;
    if let Err(error) = write_plain(run_dir, user, new, uid, gid) {
        let restored = match previous {
            Some(bytes) => fsutil::atomic_write(&cred, &bytes, Some(0o600)),
            None => remove_if_present(&cred),
        };
        return Err(match restored {
            Ok(()) => not_applied(error),
            Err(e) => io::Error::other(format!(
                "the face models in use could not be changed ({error}) and their previous \
                 encrypted copy could not be put back ({e}): the change takes effect at the \
                 next boot"
            )),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct Unsealed {
    pub user: String,
    /// The plaintext model found on disk has been sealed.
    pub migrated: bool,
    pub result: Result<(), String>,
}

fn users_with(dir: &Path, suffix: &str) -> io::Result<Vec<String>> {
    let mut users = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(user) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_suffix(suffix))
        {
            // A leading dot (temporary files) is no valid username.
            if validate_username(user).is_ok() {
                users.push(user.to_string());
            }
        }
    }
    users.sort();
    Ok(users)
}

/// Decrypt every sealed model into `run_dir` (mode 0640). Plaintext models
/// still on disk are sealed first, then deleted. An account that fails keeps
/// no decrypted copy, so its face login is off rather than running on a stale
/// one.
pub fn unseal_all(
    tool: &Path,
    sealed_dir: &Path,
    run_dir: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<Vec<Unsealed>> {
    models::prepare_model_store(run_dir, uid, gid).map_err(io::Error::other)?;
    let mut out = Vec::new();
    for user in users_with(sealed_dir, ".dat")? {
        let plain = plain_path(sealed_dir, &user);
        let result = fs::read(&plain)
            .and_then(|bytes| seal_bytes(tool, sealed_dir, &user, &bytes))
            .and_then(|()| fs::remove_file(&plain));
        if let Err(e) = result {
            out.push(Unsealed {
                user,
                migrated: false,
                result: Err(format!("cannot seal the plaintext model on disk: {e}")),
            });
            continue;
        }
        out.push(Unsealed {
            user,
            migrated: true,
            result: Ok(()),
        });
    }
    for user in users_with(sealed_dir, SUFFIX)? {
        let result = unseal_bytes(tool, sealed_dir, &user)
            .and_then(|bytes| {
                serde_json::from_slice::<Vec<FaceModel>>(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            })
            .and_then(|items| {
                models::save_user_models_owned(run_dir, &user, &items, uid, gid)
                    .map_err(io::Error::other)
            })
            .map_err(|e| e.to_string());
        match out.iter_mut().find(|u| u.user == user) {
            Some(existing) => existing.result = existing.result.clone().and(result),
            None => out.push(Unsealed {
                user,
                migrated: false,
                result,
            }),
        }
    }
    for entry in &mut out {
        if let Err(message) = &mut entry.result {
            if let Err(e) = remove_if_present(&plain_path(run_dir, &entry.user)) {
                message.push_str(&format!(
                    "; its old decrypted copy could not be removed: {e}"
                ));
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake systemd-creds. Written once: writing an executable while another test
    /// forks makes running it fail with ETXTBSY. A `FAIL-ENCRYPT` file in the
    /// sealed directory makes `encrypt` fail.
    fn fake_tool() -> PathBuf {
        static TOOL: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        TOOL.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("peekin-sealed-tool-{}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            let tool = dir.join("fake-creds");
            fs::write(
                &tool,
                "#!/bin/sh\n\
                 case \"$1\" in\n\
                 encrypt) [ -e \"${4%/*}/FAIL-ENCRYPT\" ] && { echo 'encryption refused' >&2; exit 1; }\n\
                 { echo \"SEALED $2\"; cat; } > \"$4\" ;;\n\
                 decrypt) read -r tag name < \"$3\"; [ \"$tag $name\" = \"SEALED $2\" ] || exit 1; tail -n +2 \"$3\" ;;\n\
                 esac\n",
            )
            .unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
            tool
        })
        .clone()
    }

    fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("peekin-sealed-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (sealed, run) = (root.join("etc"), root.join("run"));
        fs::create_dir_all(&sealed).unwrap();
        (root, sealed, run, fake_tool())
    }

    fn me() -> (libc::uid_t, libc::gid_t) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    const MODELS: &str = r#"[{"id":0,"label":"a","time":1,"data":[[1.0]]}]"#;

    /// `model(0)` alone serialises to [`MODELS`].
    fn model(id: i64) -> FaceModel {
        FaceModel {
            id,
            label: "a".into(),
            time: 1,
            format: None,
            data: vec![vec![1.0]],
        }
    }

    fn read(path: PathBuf) -> String {
        fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    }

    #[test]
    fn plaintext_on_disk_is_sealed_moved_to_memory_and_deleted() {
        let (root, sealed, run, tool) = setup("migrate");
        fs::write(sealed.join("alice.dat"), MODELS).unwrap();
        let (uid, gid) = me();
        let report = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert_eq!(report.len(), 1);
        assert!(report[0].migrated && report[0].result.is_ok(), "{report:?}");
        assert!(!sealed.join("alice.dat").exists(), "plaintext left on disk");
        assert!(sealed.join("alice.dat.cred").exists());
        let back = models::load_user_models(&run, "alice").unwrap();
        assert_eq!(back[0].label, "a");
        assert_eq!(
            fs::metadata(run.join("alice.dat"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        // A second boot just decrypts again.
        fs::remove_dir_all(&run).unwrap();
        let again = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert!(!again[0].migrated && again[0].result.is_ok(), "{again:?}");
        assert!(run.join("alice.dat").exists());
        // A credential that cannot be decrypted is reported, not skipped.
        fs::write(sealed.join("bob.dat.cred"), "garbage\n").unwrap();
        let broken = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert!(
            broken.iter().any(|u| u.user == "bob" && u.result.is_err()),
            "{broken:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_failing_tool_leaves_no_partial_file() {
        let (root, sealed, run, _) = setup("failing");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("alice.dat"), MODELS).unwrap();
        let (uid, gid) = me();
        let err = replace_models_with(
            Path::new("/bin/false"),
            &run,
            Some(&sealed),
            "alice",
            Some(&[model(0), model(1)]),
            uid,
            gid,
        )
        .unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
        assert_eq!(fs::read_dir(&sealed).unwrap().count(), 0);
        assert_eq!(read(run.join("alice.dat")), MODELS);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_change_is_written_to_both_copies() {
        let (root, sealed, run, tool) = setup("replace");
        let (uid, gid) = me();
        let two = [model(0), model(1)];
        replace_models_with(&tool, &run, Some(&sealed), "alice", Some(&two), uid, gid).unwrap();
        assert_eq!(models::load_user_models(&run, "alice").unwrap(), two);
        let cred = sealed.join("alice.dat.cred");
        let text = fs::read_to_string(&cred).unwrap();
        assert!(
            text.starts_with("SEALED --name=peekin-model-alice\n"),
            "{text}"
        );
        assert_eq!(
            fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            unseal_bytes(&tool, &sealed, "alice").unwrap(),
            read(run.join("alice.dat")).into_bytes()
        );
        // The name binds the credential to its user.
        fs::copy(&cred, sealed.join("bob.dat.cred")).unwrap();
        assert!(unseal_bytes(&tool, &sealed, "bob").is_err());
        // No models left: neither copy is left either.
        replace_models_with(&tool, &run, Some(&sealed), "alice", None, uid, gid).unwrap();
        assert!(!run.join("alice.dat").exists());
        assert!(!cred.exists(), "no models left, no sealed copy");
        assert!(replace_models_with(&tool, &run, Some(&sealed), "../x", None, uid, gid).is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn development_trees_only_keep_the_plaintext_copy() {
        let (root, _, run, _) = setup("dev");
        let (uid, gid) = me();
        let absent = Path::new("/nonexistent/systemd-creds");
        replace_models_with(absent, &run, None, "alice", Some(&[model(0)]), uid, gid).unwrap();
        assert_eq!(read(run.join("alice.dat")), MODELS);
        replace_models_with(absent, &run, None, "alice", None, uid, gid).unwrap();
        assert!(!run.join("alice.dat").exists());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_removal_that_cannot_be_sealed_changes_neither_copy() {
        let (root, sealed, run, tool) = setup("remove-unsealed");
        let (uid, gid) = me();
        let two = [model(0), model(1)];
        replace_models_with(&tool, &run, Some(&sealed), "alice", Some(&two), uid, gid).unwrap();
        let in_use = read(run.join("alice.dat"));
        let on_disk = read(sealed.join("alice.dat.cred"));
        fs::write(sealed.join("FAIL-ENCRYPT"), "").unwrap();
        let err = replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "alice",
            Some(&two[1..]),
            uid,
            gid,
        )
        .unwrap_err();
        assert_eq!(read(run.join("alice.dat")), in_use, "removal active: {err}");
        assert_eq!(read(sealed.join("alice.dat.cred")), on_disk);
        assert!(err.to_string().contains("not applied"), "{err}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_addition_that_cannot_be_sealed_changes_neither_copy() {
        let (root, sealed, run, tool) = setup("add-unsealed");
        let (uid, gid) = me();
        replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "alice",
            Some(&[model(0)]),
            uid,
            gid,
        )
        .unwrap();
        let in_use = read(run.join("alice.dat"));
        let on_disk = read(sealed.join("alice.dat.cred"));
        fs::write(sealed.join("FAIL-ENCRYPT"), "").unwrap();
        // bob has no model yet.
        let err = replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "bob",
            Some(&[model(0)]),
            uid,
            gid,
        )
        .unwrap_err();
        assert!(!run.join("bob.dat").exists(), "addition active: {err}");
        assert!(!sealed.join("bob.dat.cred").exists());
        assert!(err.to_string().contains("not applied"), "{err}");
        // alice has one.
        let err = replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "alice",
            Some(&[model(0), model(1)]),
            uid,
            gid,
        )
        .unwrap_err();
        assert_eq!(
            read(run.join("alice.dat")),
            in_use,
            "addition active: {err}"
        );
        assert_eq!(read(sealed.join("alice.dat.cred")), on_disk);
        assert!(err.to_string().contains("not applied"), "{err}");
        let mut left: Vec<_> = fs::read_dir(&sealed)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        left.sort();
        assert_eq!(left, ["FAIL-ENCRYPT", "alice.dat.cred"]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_copy_in_use_that_cannot_be_written_puts_the_sealed_copy_back() {
        let (root, sealed, run, tool) = setup("unwritable");
        let (uid, gid) = me();
        replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "alice",
            Some(&[model(0)]),
            uid,
            gid,
        )
        .unwrap();
        let cred = sealed.join("alice.dat.cred");
        let on_disk = read(cred.clone());
        // A directory in its place: the copy in use can be neither replaced nor removed.
        fs::remove_file(run.join("alice.dat")).unwrap();
        fs::create_dir(run.join("alice.dat")).unwrap();
        for change in [Some(&[model(0), model(1)][..]), None] {
            let err = replace_models_with(&tool, &run, Some(&sealed), "alice", change, uid, gid)
                .unwrap_err();
            assert!(err.to_string().contains("not applied"), "{err}");
            assert_eq!(read(cred.clone()), on_disk, "{change:?}");
            assert_eq!(
                fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        // A user without a sealed copy is left without one.
        fs::create_dir(run.join("bob.dat")).unwrap();
        let err = replace_models_with(
            &tool,
            &run,
            Some(&sealed),
            "bob",
            Some(&[model(0)]),
            uid,
            gid,
        )
        .unwrap_err();
        assert!(err.to_string().contains("not applied"), "{err}");
        assert!(!sealed.join("bob.dat.cred").exists());
        // If even that fails (here: the temporary file of fsutil::atomic_write
        // is taken), the error says the sealed change takes effect at boot.
        fs::create_dir(sealed.join(format!(".alice.dat.cred.tmp{}", std::process::id()))).unwrap();
        let err =
            replace_models_with(&tool, &run, Some(&sealed), "alice", None, uid, gid).unwrap_err();
        assert!(err.to_string().contains("next boot"), "{err}");
        assert!(!cred.exists(), "{err}");
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn usernames_with_dots_are_sealed_and_restored() {
        let (root, sealed, run, tool) = setup("dots");
        let (uid, gid) = me();
        let users = ["john.doe", "user@ad.example.com"];
        for user in users {
            fs::write(sealed.join(format!("{user}.dat")), MODELS).unwrap();
        }
        let report = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert_eq!(report.len(), users.len(), "{report:?}");
        for user in users {
            assert!(
                report
                    .iter()
                    .any(|u| u.user == user && u.migrated && u.result.is_ok()),
                "{report:?}"
            );
            assert!(
                !sealed.join(format!("{user}.dat")).exists(),
                "plaintext left on disk"
            );
            assert!(sealed.join(format!("{user}.dat.cred")).exists());
        }
        // The next boot decrypts them again; "<user>.dat.cred" is never taken for
        // a plaintext model and a temporary file is no account.
        fs::remove_dir_all(&run).unwrap();
        fs::write(sealed.join(".john.doe.dat.cred.new"), "partial").unwrap();
        let again = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert_eq!(again.len(), users.len(), "{again:?}");
        for user in users {
            assert!(
                again
                    .iter()
                    .any(|u| u.user == user && !u.migrated && u.result.is_ok()),
                "{again:?}"
            );
            assert_eq!(models::load_user_models(&run, user).unwrap()[0].label, "a");
        }
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn an_account_that_cannot_be_restored_keeps_no_stale_copy_in_memory() {
        let (root, sealed, run, tool) = setup("stale");
        let (uid, gid) = me();
        // Copies in memory from before, as when unseal-models runs again by hand.
        fs::create_dir_all(&run).unwrap();
        for user in ["bob", "carol", "dave"] {
            fs::write(run.join(format!("{user}.dat")), MODELS).unwrap();
        }
        // bob's copy cannot be decrypted, carol's is no model list once
        // decrypted, dave's plaintext model on disk cannot be sealed.
        fs::write(sealed.join("bob.dat.cred"), "garbage\n").unwrap();
        fs::write(
            sealed.join("carol.dat.cred"),
            "SEALED --name=peekin-model-carol\nnot a model\n",
        )
        .unwrap();
        fs::write(sealed.join("dave.dat"), MODELS).unwrap();
        fs::write(sealed.join("FAIL-ENCRYPT"), "").unwrap();
        let report = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        for user in ["bob", "carol", "dave"] {
            assert!(
                report.iter().any(|u| u.user == user && u.result.is_err()),
                "{report:?}"
            );
            assert!(
                !run.join(format!("{user}.dat")).exists(),
                "stale copy of {user} left in memory"
            );
        }
        assert!(
            sealed.join("dave.dat").exists(),
            "unsealed plaintext deleted"
        );
        let _ = fs::remove_dir_all(root);
    }
}
