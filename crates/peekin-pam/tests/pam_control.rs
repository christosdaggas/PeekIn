//! The generated auth control flow through real libpam, with pam_permit and
//! pam_deny standing in for face and password. No camera, password or live
//! PAM configuration is used.

use std::ffi::{c_char, c_int, c_void, CString};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

type ConvFn = extern "C" fn(c_int, *mut *const c_void, *mut *mut c_void, *mut c_void) -> c_int;

#[repr(C)]
struct PamConv {
    conv: ConvFn,
    appdata_ptr: *mut c_void,
}

#[link(name = "pam")]
extern "C" {
    fn pam_start_confdir(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        confdir: *const c_char,
        pamh: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
}

/// Any conversation is unexpected here: PAM_CONV_ERR.
extern "C" fn no_conversation(
    _: c_int,
    _: *mut *const c_void,
    _: *mut *mut c_void,
    _: *mut c_void,
) -> c_int {
    19
}

fn current_user() -> String {
    // SAFETY: getpwuid returns NULL or a valid entry, copied before any other call.
    unsafe {
        let pw = libc::getpwuid(libc::getuid());
        assert!(!pw.is_null());
        std::ffi::CStr::from_ptr((*pw).pw_name)
            .to_string_lossy()
            .into_owned()
    }
}

fn authenticates(dir: &Path, service: &str, user: &str) -> bool {
    let conversation = PamConv {
        conv: no_conversation,
        appdata_ptr: std::ptr::null_mut(),
    };
    let service = CString::new(service).unwrap();
    let user = CString::new(user).unwrap();
    let dir = CString::new(dir.to_str().unwrap()).unwrap();
    let mut handle = std::ptr::null_mut();
    // SAFETY: all strings are NUL-terminated and outlive the transaction.
    unsafe {
        let rc = pam_start_confdir(
            service.as_ptr(),
            user.as_ptr(),
            &conversation,
            dir.as_ptr(),
            &mut handle,
        );
        assert_eq!(rc, 0, "pam_start_confdir failed");
        let result = pam_authenticate(handle, 0);
        pam_end(handle, result);
        result == 0
    }
}

struct TempDir(PathBuf);

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

/// (guard passes, face passes, password passes)
const CASES: [(bool, bool, bool); 4] = [
    (true, true, false),
    (false, true, false),
    (true, false, true),
    (true, false, false),
];

#[test]
fn face_or_password_never_overrides_a_failed_guard() {
    let dir = TempDir(
        Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!("pam-control-{}", std::process::id())),
    );
    let _ = fs::remove_dir_all(&dir.0);
    fs::create_dir_all(&dir.0).unwrap();
    let d = &dir.0;
    let user = current_user();
    let module = |passes: bool| {
        if passes {
            "pam_permit.so"
        } else {
            "pam_deny.so"
        }
    };
    let guard = |passes: bool| {
        if passes {
            user.clone()
        } else {
            "peekin-nonexistent-test-user".to_string()
        }
    };

    // Direct stacks, edited by system-setup.
    for control in ["required", "requisite"] {
        for (guard_passes, face_passes, password_passes) in CASES {
            fs::write(
                d.join("sudo"),
                format!(
                    "auth {control} pam_succeed_if.so user = {}\nauth sufficient pam_unix.so\nauth required pam_deny.so\n",
                    guard(guard_passes)
                ),
            )
            .unwrap();
            fs::write(
                d.join("gdm-password"),
                "auth required pam_selinux_permit.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n",
            )
            .unwrap();
            let out = Command::new("sh")
                .arg(concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/../../packaging/system-setup"
                ))
                .arg("install")
                .env("PAM_DIR", d)
                .env("CONFIG_FILE", d.join("absent.ini"))
                .env("SELINUX", "0")
                // Never take over a real linux-hello installation or run an installed PeekIn.
                .env("OLD_ETC", d.join("no-old-etc"))
                .env("OLD_ACTIVITY", d.join("no-old-activity"))
                .env("OLD_SNAPSHOTS", d.join("no-old-log"))
                .env("PEEKIN_CLI", d.join("no-peekin"))
                .env("PAM_SETUP", d.join("no-pam-setup"))
                // The counter directory the install (re)creates: never /var/lib.
                .env("STATE_DIR", d.join("failures"))
                .env("SERVICE_USER", "peekin-test-nonexistent")
                .output()
                .unwrap();
            assert!(
                out.status.success(),
                "{}",
                String::from_utf8_lossy(&out.stderr)
            );
            let body = fs::read_to_string(d.join("sudo"))
                .unwrap()
                .replace("pam_peekin.so", module(face_passes))
                .replace("pam_unix.so", module(password_passes));
            fs::write(d.join("sudo"), body).unwrap();
            assert_eq!(
                authenticates(d, "sudo", &user),
                guard_passes && (face_passes || password_passes),
                "{control} {guard_passes} {face_passes} {password_passes}"
            );
        }
    }

    // Fedora services include/substack the authselect-generated stack.
    for (service, stack, nesting) in [
        ("sudo", "system-auth", "include"),
        ("gdm-password", "password-auth", "substack"),
    ] {
        fs::write(d.join(service), format!("auth {nesting} {stack}\n")).unwrap();
        for (guard_passes, face_passes, password_passes) in CASES {
            fs::write(
                d.join(stack),
                format!(
                    "auth required pam_succeed_if.so user = {}\n\
                     auth [success=done default=ignore] {}\n\
                     auth sufficient {}\n\
                     auth required pam_deny.so\n",
                    guard(guard_passes),
                    module(face_passes),
                    module(password_passes)
                ),
            )
            .unwrap();
            assert_eq!(
                authenticates(d, service, &user),
                guard_passes && (face_passes || password_passes),
                "{service} {guard_passes} {face_passes} {password_passes}"
            );
        }
    }
}
