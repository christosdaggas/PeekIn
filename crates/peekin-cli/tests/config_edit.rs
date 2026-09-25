//! `peekin config` edits a copy as the invoking user and applies it as root
//! only when it is valid. Run as root (CI containers), the editor must run as
//! another account; run as a user, that user is the invoker.

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

const ORIGINAL: &str = "# keep me\n[video]\ntimeout = 3\n";
const SECRET: &str = "root-only secret";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The account `SUDO_USER` names: `nobody` under root, else the current user.
fn invoker() -> (String, u32) {
    let name = if is_root() {
        "nobody".to_string()
    } else {
        let out = Command::new("id").arg("-un").output().unwrap();
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    };
    let out = Command::new("id").args(["-u", &name]).output().unwrap();
    let uid = String::from_utf8(out.stdout)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    (name, uid)
}

/// Fake editors and the directory they report to. Written once: writing an
/// executable while another test forks makes running it fail with ETXTBSY.
/// The editor gets a cleared environment, so the paths are baked in.
fn tools() -> &'static PathBuf {
    static DIR: OnceLock<PathBuf> = OnceLock::new();
    DIR.get_or_init(|| {
        let dir = std::env::temp_dir().join(format!("peekin-config-edit-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("out")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        fs::set_permissions(dir.join("out"), fs::Permissions::from_mode(0o777)).unwrap();
        fs::write(dir.join("secret"), SECRET).unwrap();
        fs::set_permissions(dir.join("secret"), fs::Permissions::from_mode(0o600)).unwrap();
        let out = dir.join("out");
        let secret = dir.join("secret");
        for (name, body) in [
            (
                "raise",
                "sed -i 's/^timeout = 3$/timeout = 5/' \"$1\"".to_string(),
            ),
            (
                "invalid",
                "sed -i 's/^timeout = 3$/timeout = 999/' \"$1\"".to_string(),
            ),
            (
                "symlink",
                format!("rm -f \"$1\"; ln -s {} \"$1\"", secret.display()),
            ),
            ("fail", "exit 3".to_string()),
            ("untouched", "true".to_string()),
            ("unused", "true".to_string()),
        ] {
            let script = dir.join(name);
            fs::write(
                &script,
                format!(
                    "#!/bin/sh\nid -u > {out}/{name}.uid\nenv > {out}/{name}.env\n\
                     echo \"$1\" > {out}/{name}.path\n{body}\n",
                    out = out.display()
                ),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        }
        dir
    })
}

fn config_dir(test: &str) -> PathBuf {
    let dir = tools().join(format!("etc-{test}"));
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("config.ini"), ORIGINAL).unwrap();
    fs::set_permissions(dir.join("config.ini"), fs::Permissions::from_mode(0o644)).unwrap();
    dir
}

fn peekin_config(dir: &Path, editor: &str, sudo_user: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_peekin"));
    command
        .args(["config", "--config-dir"])
        .arg(dir)
        .arg("--data-dir")
        .arg(dir)
        .env("EDITOR", tools().join(editor))
        .env("PEEKIN_TEST_LEAK", "must-not-reach-the-editor")
        .env_remove("SUDO_USER")
        .stdin(Stdio::null());
    if !is_root() {
        command.env("EUID_CHECK_SKIP", "1");
    }
    if let Some(user) = sudo_user {
        command.env("SUDO_USER", user);
    }
    let out = command.output().unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

fn reported(editor: &str, what: &str) -> Option<String> {
    fs::read_to_string(tools().join("out").join(format!("{editor}.{what}"))).ok()
}

/// The staged copy the editor was given no longer exists, nor its directory.
fn assert_cleaned_up(editor: &str) {
    let path = PathBuf::from(reported(editor, "path").unwrap().trim());
    let staged = path.parent().unwrap();
    assert!(
        staged.starts_with(std::env::temp_dir()) && path.ends_with("config.ini"),
        "{}",
        path.display()
    );
    assert!(!staged.exists(), "left behind: {}", staged.display());
}

#[test]
fn a_valid_edit_is_made_as_the_invoking_user_and_applied() {
    let (user, uid) = invoker();
    let dir = config_dir("valid");
    let (ok, text) = peekin_config(&dir, "raise", Some(&user));
    assert!(ok, "{text}");
    assert_eq!(
        reported("raise", "uid").unwrap().trim(),
        uid.to_string(),
        "the editor must run as the invoking user"
    );
    let env = reported("raise", "env").unwrap();
    assert!(!env.contains("PEEKIN_TEST_LEAK"), "{env}");
    assert!(env.contains(&format!("USER={user}\n")), "{env}");
    let config = dir.join("config.ini");
    assert_eq!(
        fs::read_to_string(&config).unwrap(),
        ORIGINAL.replace("timeout = 3", "timeout = 5")
    );
    let meta = fs::metadata(&config).unwrap();
    assert_eq!(meta.mode() & 0o777, 0o644, "the mode is kept");
    assert_eq!(meta.uid(), unsafe { libc::geteuid() }, "the owner is kept");
    assert!(text.contains("saved"), "{text}");
    assert_cleaned_up("raise");
}

#[test]
fn an_invalid_edit_changes_nothing() {
    let (user, _) = invoker();
    let dir = config_dir("invalid");
    let (ok, text) = peekin_config(&dir, "invalid", Some(&user));
    assert!(!ok, "{text}");
    assert!(text.contains("timeout"), "{text}");
    assert!(text.contains("not changed"), "{text}");
    assert_eq!(
        fs::read_to_string(dir.join("config.ini")).unwrap(),
        ORIGINAL
    );
    assert_cleaned_up("invalid");
}

#[test]
fn a_copy_replaced_by_a_link_is_never_read_or_applied() {
    let (user, _) = invoker();
    let dir = config_dir("symlink");
    let (ok, text) = peekin_config(&dir, "symlink", Some(&user));
    assert!(!ok, "{text}");
    assert!(!text.contains(SECRET), "{text}");
    let config = dir.join("config.ini");
    assert!(fs::symlink_metadata(&config).unwrap().is_file());
    assert_eq!(fs::read_to_string(config).unwrap(), ORIGINAL);
    assert_cleaned_up("symlink");
}

#[test]
fn a_failing_or_idle_editor_changes_nothing() {
    let (user, _) = invoker();
    let dir = config_dir("fail");
    let (ok, text) = peekin_config(&dir, "fail", Some(&user));
    assert!(!ok, "{text}");
    assert!(text.contains("not changed"), "{text}");
    assert_eq!(
        fs::read_to_string(dir.join("config.ini")).unwrap(),
        ORIGINAL
    );
    let dir = config_dir("untouched");
    let (ok, text) = peekin_config(&dir, "untouched", Some(&user));
    assert!(ok, "{text}");
    assert!(text.contains("No changes"), "{text}");
    assert_eq!(
        fs::read_to_string(dir.join("config.ini")).unwrap(),
        ORIGINAL
    );
}

#[test]
fn without_a_sudo_user_or_as_root_no_editor_runs() {
    let dir = config_dir("refused");
    for sudo_user in [None, Some("root")] {
        let (ok, text) = peekin_config(&dir, "unused", sudo_user);
        assert!(!ok, "{sudo_user:?}: {text}");
        assert!(text.contains("SUDO_USER"), "{sudo_user:?}: {text}");
    }
    assert!(reported("unused", "uid").is_none(), "an editor ran");
    assert_eq!(
        fs::read_to_string(dir.join("config.ini")).unwrap(),
        ORIGINAL
    );
}
