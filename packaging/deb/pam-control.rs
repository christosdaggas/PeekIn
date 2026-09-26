//! Real Debian libpam control flow, using private service files and stub modules.
//! Run from the repository root: rustc --test packaging/deb/pam-control.rs -l pam -o /tmp/opencode/peekin-pam-control && /tmp/opencode/peekin-pam-control
use std::ffi::{c_char, c_int, c_void, CString};
use std::fs;
use std::path::Path;
use std::process::Command;

#[repr(C)]
struct PamConv {
    conv: extern "C" fn(c_int, *mut *const c_void, *mut *mut c_void, *mut c_void) -> c_int,
    data: *mut c_void,
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

extern "C" fn no_conversation(_: c_int, _: *mut *const c_void, _: *mut *mut c_void, _: *mut c_void) -> c_int {
    19 // PAM_CONV_ERR; these stubs must never ask for a password.
}

fn authenticates(dir: &Path, service: &str, user: &str) -> bool {
    let conv = PamConv { conv: no_conversation, data: std::ptr::null_mut() };
    let service = CString::new(service).unwrap();
    let user = CString::new(user).unwrap();
    let dir = CString::new(dir.to_str().unwrap()).unwrap();
    let mut handle = std::ptr::null_mut();
    unsafe {
        assert_eq!(pam_start_confdir(service.as_ptr(), user.as_ptr(), &conv, dir.as_ptr(), &mut handle), 0);
        let result = pam_authenticate(handle, 0);
        pam_end(handle, result);
        result == 0
    }
}

#[test]
fn face_success_and_password_fallback_follow_debian_auth_stack() {
    let dir = std::env::temp_dir().join(format!("peekin-debian-pam-{}", std::process::id()));
    fs::create_dir(&dir).unwrap();
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup { fn drop(&mut self) { let _ = fs::remove_dir_all(&self.0); } }
    let _cleanup = Cleanup(dir.clone());
    fs::write(dir.join("sudo"), "@include common-auth\n").unwrap();
    fs::write(dir.join("gdm-password"),
        "auth requisite pam_nologin.so\nauth required pam_succeed_if.so user != root quiet_success\n@include common-auth\nauth optional pam_gnome_keyring.so\n").unwrap();
    let user = std::env::var("USER").unwrap();
    // pam_start_confdir does not redirect included files into its private
    // config dir on Debian. Inline the equivalent auth rules for the dispatch
    // test while testing the literal @include position in test-pam-setup.sh.
    fs::write(dir.join("sudo"), "auth sufficient pam_permit.so\nauth requisite pam_deny.so\n").unwrap();
    assert!(authenticates(&dir, "sudo", &user), "baseline password stub must pass");
    fs::write(dir.join("sudo"), "@include common-auth\n").unwrap();
    let out = Command::new("sh").arg("packaging/deb/pam-setup").arg("install")
        .env("PAM_DIR", &dir).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    for service in ["sudo", "gdm-password"] {
        let installed = fs::read_to_string(dir.join(service)).unwrap();
        for (face, password, expected) in [
            ("pam_permit.so", "pam_deny.so", true),
            ("pam_deny.so", "pam_permit.so", true),
            ("pam_deny.so", "pam_deny.so", false),
        ] {
            // Debian pam-auth-update's jump/deny/permit sequence.
            let common = format!(
                "auth [success=1 default=ignore] {password}\nauth requisite pam_deny.so\nauth required pam_permit.so\n"
            );
            fs::write(dir.join(service), installed.replace("pam_peekin.so", face)
                .replace("@include common-auth\n", &common)).unwrap();
            assert_eq!(authenticates(&dir, service, &user), expected, "{service} {face} {password}");
        }
        fs::write(dir.join(service), installed).unwrap();
    }
    // A required pre-auth gate must not be bypassed by a face match.
    let gdm = fs::read_to_string(dir.join("gdm-password")).unwrap();
    fs::write(dir.join("gdm-password"), gdm.replace("user != root", "user = peekin-nonexistent-user")
        .replace("pam_peekin.so", "pam_permit.so")
        .replace("@include common-auth\n", "auth required pam_deny.so\n")).unwrap();
    assert!(!authenticates(&dir, "gdm-password", &user));
}
