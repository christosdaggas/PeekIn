//! `peekin pam-setup` and `system-setup` against a fake authselect; never
//! touches the live profile.

use peekin_core::authselect::{auth_rules, insert_rule, validate_stack, RULE};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::OnceLock;

const FAKE: &str = r#"#!/bin/sh
set -eu
root=$AUTHSELECT_TEST_ROOT
pam=$root/etc/pam.d
current=$root/etc/authselect/current
profile=$root/etc/authselect/custom/peekin
origin() { if [ "$1" = custom/peekin ]; then echo "$profile"; else echo "$root/etc/authselect/default/$1"; fi; }
command=$1; shift
case $command in
check) ;;
current) cat "$current" ;;
create-profile)
    mkdir -p "$(dirname "$profile")"; mkdir "$profile"
    for a; do case $a in --base-on=*) base=${a#--base-on=} ;; esac; done
    for n in system-auth password-auth; do cp -p "$root/etc/authselect/default/$base/$n" "$profile/$n"; done ;;
test)
    o=$(origin "$1"); n=password-auth
    for a; do if [ "$a" = --system-auth ]; then n=system-auth; fi; done
    cat "$o/$n" ;;
select)
    o=$(origin "$1"); sel=
    for a; do case $a in -b|--backup=*) ;; *) sel="${sel:+$sel }$a" ;; esac; done
    printf '%s\n' "$sel" > "$current"
    for n in system-auth password-auth; do cp -p "$o/$n" "$pam/$n"; done ;;
*) echo "unsupported fake command: $command" >&2; exit 1 ;;
esac
"#;

/// Written once: writing an executable while another test forks makes
/// running it fail with ETXTBSY.
fn fake_authselect() -> &'static Path {
    static FAKE_PATH: OnceLock<PathBuf> = OnceLock::new();
    FAKE_PATH.get_or_init(|| {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join("fake-authselect");
        let staged = path.with_extension(format!("{}", std::process::id()));
        fs::write(&staged, FAKE).unwrap();
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o755)).unwrap();
        fs::rename(&staged, &path).unwrap();
        path
    })
}

const SSSD_SYSTEM: &str = "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\n\
auth required pam_faillock.so preauth silent\n\
auth sufficient pam_fprintd.so\n\
auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
auth [default=2 ignore=ignore success=ok] pam_localuser.so\n\
auth [success=done authinfo_unavail=ignore user_unknown=ignore ignore=ignore default=die] pam_sss.so try_cert_auth\n\
auth sufficient pam_unix.so nullok\n\
auth sufficient pam_systemd_home.so\n\
auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
auth sufficient pam_sss_gss.so\n\
auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
auth sufficient pam_sss.so forward_pass\n\
auth required pam_faillock.so authfail\n\
auth optional pam_gnome_keyring.so only_if=login auto_start\n\
auth required pam_deny.so\naccount required pam_unix.so\n";

const SSSD_PASSWORD: &str =
    "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\n\
auth required pam_faillock.so preauth silent\n\
auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
auth [default=1 ignore=ignore success=ok] pam_localuser.so\n\
auth sufficient pam_unix.so nullok\n\
auth sufficient pam_systemd_home.so\n\
auth [default=1 ignore=ignore success=ok] pam_usertype.so isregular\n\
auth sufficient pam_sss.so forward_pass\n\
auth required pam_faillock.so authfail\n\
auth optional pam_gnome_keyring.so auto_start\n\
auth required pam_deny.so\naccount required pam_unix.so\n";

struct Fixture {
    root: PathBuf,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

impl Fixture {
    fn new() -> Self {
        static N: AtomicUsize = AtomicUsize::new(0);
        let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "pam-setup-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&root);
        let f = Fixture { root };
        let base = f.path("etc/authselect/default/local");
        fs::create_dir_all(f.path("etc/pam.d")).unwrap();
        fs::create_dir_all(&base).unwrap();
        f.write("etc/authselect/current", "local with-fingerprint\n");
        f.write(
            "etc/pam.d/sudo",
            "#%PAM-1.0\nauth include system-auth\naccount include system-auth\n",
        );
        f.write(
            "etc/pam.d/gdm-password",
            "auth [success=done ignore=ignore default=bad] pam_selinux_permit.so\n\
             auth substack password-auth\nauth optional pam_gnome_keyring.so\nauth include postlogin\n",
        );
        f.write("etc/pam.d/login", "auth include system-auth\n");
        for name in ["system-auth", "password-auth"] {
            let mut text = String::from(
                "auth required pam_env.so\nauth required pam_faildelay.so delay=2000000\n",
            );
            if name == "system-auth" {
                text += "auth sufficient pam_fprintd.so\n";
            }
            text += "auth sufficient pam_unix.so nullok\nauth required pam_deny.so\naccount required pam_unix.so\n";
            fs::write(base.join(name), &text).unwrap();
            f.write(&format!("etc/pam.d/{name}"), &text);
        }
        f
    }

    fn path(&self, rel: &str) -> PathBuf {
        self.root.join(rel)
    }

    fn write(&self, rel: &str, text: &str) {
        fs::write(self.path(rel), text).unwrap();
    }

    fn read(&self, rel: &str) -> String {
        fs::read_to_string(self.path(rel)).unwrap()
    }

    fn current(&self) -> String {
        self.read("etc/authselect/current")
    }

    fn state_exists(&self) -> bool {
        self.path("var/lib/peekin/authselect-previous.json")
            .exists()
    }

    fn profile_exists(&self) -> bool {
        self.path("etc/authselect/custom/peekin").exists()
    }

    fn use_sssd(&self, features: &[&str]) {
        let sssd = self.path("etc/authselect/default/sssd");
        fs::create_dir_all(&sssd).unwrap();
        for (name, text) in [
            ("system-auth", SSSD_SYSTEM),
            ("password-auth", SSSD_PASSWORD),
        ] {
            fs::write(sssd.join(name), text).unwrap();
            self.write(&format!("etc/pam.d/{name}"), text);
        }
        let selection: Vec<&str> = std::iter::once("sssd")
            .chain(features.iter().copied())
            .collect();
        self.write(
            "etc/authselect/current",
            &format!("{}\n", selection.join(" ")),
        );
    }

    fn invoke(&self, mode: &str, through_shell: bool) -> Output {
        let peekin = env!("CARGO_BIN_EXE_peekin");
        let mut command = if through_shell {
            let mut c = Command::new("sh");
            c.arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../../packaging/system-setup"
            ))
            .arg(mode);
            c
        } else {
            let mut c = Command::new(peekin);
            c.args(["pam-setup", mode]);
            c
        };
        command
            .env("AUTHSELECT_TEST_ROOT", &self.root)
            .env("AUTHSELECT_TEST_BINARY", fake_authselect())
            .env("PAM_DIR", self.path("etc/pam.d"))
            .env("PAM_SETUP", peekin)
            .env("CONFIG_FILE", self.path("absent-config"))
            .env("SELINUX", "0")
            .env("SERVICE_USER", "peekin-test-nonexistent")
            // Never take over a real linux-hello installation or run an installed PeekIn.
            .env("OLD_ETC", self.path("no-old-etc"))
            .env("OLD_ACTIVITY", self.path("no-old-activity"))
            .env("OLD_SNAPSHOTS", self.path("no-old-log"))
            .env("PEEKIN_CLI", self.path("no-peekin"))
            .output()
            .unwrap()
    }

    fn succeeds(&self, mode: &str, through_shell: bool) {
        let out = self.invoke(mode, through_shell);
        assert!(
            out.status.success(),
            "{mode}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }

    fn fails(&self, mode: &str) {
        assert!(
            !self.invoke(mode, false).status.success(),
            "{mode} succeeded"
        );
    }
}

fn position(
    rules: &[peekin_core::authselect::Rule],
    f: impl Fn(&peekin_core::authselect::Rule) -> bool,
) -> usize {
    rules.iter().position(f).unwrap()
}

#[test]
fn install_upgrade_remove_keep_service_pam_files() {
    let f = Fixture::new();
    let services = ["sudo", "gdm-password", "login"];
    let before: Vec<String> = services
        .iter()
        .map(|s| f.read(&format!("etc/pam.d/{s}")))
        .collect();
    let now = |f: &Fixture| -> Vec<String> {
        services
            .iter()
            .map(|s| f.read(&format!("etc/pam.d/{s}")))
            .collect()
    };
    for _ in 0..2 {
        f.succeeds("install", true);
        assert_eq!(f.current().split_whitespace().next(), Some("custom/peekin"));
        for name in ["system-auth", "password-auth"] {
            let rendered = f.read(&format!("etc/pam.d/{name}"));
            validate_stack(&rendered, true).unwrap();
            assert_eq!(rendered.matches("pam_peekin.so").count(), 1);
        }
        assert_eq!(now(&f), before);
    }
    f.succeeds("remove", true);
    assert_eq!(f.current(), "local with-fingerprint\n");
    assert_eq!(now(&f), before);
    assert!(!f.state_exists());
    assert!(!f.profile_exists());
    f.succeeds("install", true);
}

#[test]
fn unsafe_stack_and_custom_service_are_rejected_without_selection() {
    let f = Fixture::new();
    f.write(
        "etc/pam.d/password-auth",
        "auth required pam_env.so\nauth sufficient pam_unix.so\nauth required pam_custom_gate.so\nauth required pam_deny.so\n",
    );
    f.fails("install");
    assert!(!f.state_exists());
    assert_eq!(f.current(), "local with-fingerprint\n");
    f.write(
        "etc/pam.d/gdm-password",
        "auth requisite pam_deny.so\nauth substack password-auth\n",
    );
    f.fails("install");
}

#[test]
fn sssd_install_is_idempotent_and_keeps_the_password_fallback() {
    let f = Fixture::new();
    let features = [
        "with-faillock",
        "with-smartcard",
        "with-fingerprint",
        "with-systemd-homed",
        "with-gssapi",
        "with-pam-gnome-keyring",
    ];
    f.use_sssd(&features);
    for _ in 0..2 {
        f.succeeds("install", false);
        for name in ["system-auth", "password-auth"] {
            let rendered = f.read(&format!("etc/pam.d/{name}"));
            validate_stack(&rendered, true).unwrap();
            let rules = auth_rules(&rendered).unwrap();
            let face = position(&rules, |r| r.module == "pam_peekin.so");
            let unix = position(&rules, |r| r.module == "pam_unix.so");
            let sss = position(&rules, |r| {
                r.module == "pam_sss.so" && r.args.iter().any(|a| a == "forward_pass")
            });
            assert!(face < unix && unix < sss);
        }
    }
    f.succeeds("remove", false);
    assert_eq!(f.current(), format!("sssd {}\n", features.join(" ")));
    assert!(!f.profile_exists());
}

#[test]
fn required_guard_and_altered_sssd_tail_are_rejected() {
    let installed = insert_rule(SSSD_SYSTEM).unwrap();
    assert!(installed.find("pam_faillock.so preauth") < installed.find("pam_peekin.so"));
    validate_stack(&installed, true).unwrap();
    assert!(validate_stack(
        &installed.replace("pam_sss.so forward_pass", "pam_sss.so"),
        true
    )
    .is_err());
    assert!(validate_stack(
        &installed.replace(
            "auth required pam_deny.so",
            "auth required pam_custom_gate.so\nauth required pam_deny.so"
        ),
        true
    )
    .is_err());
}

#[test]
fn smartcard_required_fails_closed() {
    let f = Fixture::new();
    f.use_sssd(&["with-smartcard-required"]);
    let password = f.read("etc/pam.d/password-auth").replace(
        "auth required pam_faillock.so preauth silent\n",
        "auth required pam_deny.so # Smartcard authentication is required\n",
    );
    f.write("etc/pam.d/password-auth", &password);
    f.write("etc/authselect/default/sssd/password-auth", &password);
    f.fails("install");
    assert_eq!(f.current(), "sssd with-smartcard-required\n");
    assert!(!f.state_exists());
}

#[test]
fn corrupt_rollback_state_never_switches_profiles() {
    let f = Fixture::new();
    f.succeeds("install", false);
    f.write(
        "var/lib/peekin/authselect-previous.json",
        r#"{"previous": [null], "templates": {}}"#,
    );
    f.fails("remove");
    assert_eq!(f.current().split_whitespace().next(), Some("custom/peekin"));
}

/// Needs Fedora's authselect and its SSSD templates; skipped elsewhere.
#[test]
fn real_fedora_sssd_renders_supported_feature_combinations() {
    let templates = Path::new("/usr/share/authselect/default/sssd");
    let have_authselect = Command::new("authselect").arg("--help").output().is_ok();
    if !have_authselect || !templates.join("system-auth").is_file() {
        eprintln!("skipped: Fedora authselect SSSD templates unavailable");
        return;
    }
    for name in ["system-auth", "password-auth"] {
        let template = fs::read_to_string(templates.join(name)).unwrap();
        let updated = insert_rule(&template).unwrap();
        assert_eq!(updated.matches("pam_peekin.so").count(), 1);
        assert_eq!(updated.replacen(RULE, "", 1), template);
        assert!(updated.find("pam_peekin.so") < updated.find("pam_usertype.so isregular"));
    }
    let render = |features: &[&str], flag: &str| -> String {
        let out = Command::new("authselect")
            .arg("test")
            .arg("sssd")
            .args(features)
            .arg(flag)
            .output()
            .unwrap();
        assert!(out.status.success());
        String::from_utf8(out.stdout).unwrap()
    };
    let combinations: &[&[&str]] = &[
        &[],
        &["with-faillock"],
        &["with-smartcard", "with-fingerprint"],
        &["with-pam-u2f", "with-faillock"],
        &["with-pam-u2f-2fa", "with-faillock"],
        &[
            "with-systemd-homed",
            "with-gssapi",
            "with-pam-gnome-keyring",
        ],
        &[
            "with-smartcard",
            "with-fingerprint",
            "with-pam-u2f",
            "with-systemd-homed",
            "with-gssapi",
            "with-faillock",
            "with-pam-gnome-keyring",
        ],
    ];
    for features in combinations {
        for flag in ["--system-auth", "--password-auth"] {
            let rendered = render(features, flag);
            validate_stack(&rendered, false).unwrap();
            let installed = insert_rule(&rendered).unwrap();
            validate_stack(&installed, true).unwrap();
            let after: Vec<_> = auth_rules(&installed)
                .unwrap()
                .into_iter()
                .filter(|r| r.module != "pam_peekin.so")
                .collect();
            assert_eq!(after, auth_rules(&rendered).unwrap());
        }
    }
    for flag in ["--system-auth", "--password-auth"] {
        assert!(validate_stack(&render(&["with-smartcard-required"], flag), false).is_err());
    }
}
