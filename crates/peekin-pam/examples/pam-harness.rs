//! Drives pam_peekin.so through real libpam: `pam-harness <pam-config-dir> <service> <user>`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::time::Instant;

#[repr(C)]
struct PamMessage {
    msg_style: c_int,
    msg: *const c_char,
}

#[repr(C)]
struct PamResponse {
    resp: *mut c_char,
    resp_retcode: c_int,
}

type ConvFn =
    extern "C" fn(c_int, *mut *const PamMessage, *mut *mut PamResponse, *mut c_void) -> c_int;

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
    fn pam_setcred(pamh: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(pamh: *mut c_void, status: c_int) -> c_int;
    fn pam_strerror(pamh: *mut c_void, errnum: c_int) -> *const c_char;
}

extern "C" fn conv(
    n: c_int,
    msgs: *mut *const PamMessage,
    resp: *mut *mut PamResponse,
    _: *mut c_void,
) -> c_int {
    // SAFETY: libpam passes `n` valid messages; responses are freed by libpam.
    unsafe {
        let replies =
            libc::calloc(n.max(1) as usize, std::mem::size_of::<PamResponse>()) as *mut PamResponse;
        for i in 0..n as usize {
            let m = &**msgs.add(i);
            let text = CStr::from_ptr(m.msg).to_string_lossy();
            let kind = match m.msg_style {
                3 => "error",
                4 => "info",
                _ => "prompt (answered empty)",
            };
            println!("  [conversation {kind}] {text}");
            if m.msg_style == 1 || m.msg_style == 2 {
                (*replies.add(i)).resp = libc::strdup(c"".as_ptr());
            }
        }
        *resp = replies;
    }
    0
}

fn main() {
    let args: Vec<CString> = std::env::args()
        .skip(1)
        .map(|a| CString::new(a).unwrap())
        .collect();
    let [confdir, service, user] = args.as_slice() else {
        eprintln!("usage: pam-harness <pam-config-dir> <service> <user>");
        std::process::exit(2);
    };
    let conversation = PamConv {
        conv,
        appdata_ptr: std::ptr::null_mut(),
    };
    let mut pamh = std::ptr::null_mut();
    // SAFETY: all strings are NUL-terminated and outlive the PAM transaction.
    unsafe {
        let rc = pam_start_confdir(
            service.as_ptr(),
            user.as_ptr(),
            &conversation,
            confdir.as_ptr(),
            &mut pamh,
        );
        if rc != 0 {
            eprintln!("pam_start_confdir failed: {rc}");
            std::process::exit(2);
        }
        let started = Instant::now();
        let rc = pam_authenticate(pamh, 0);
        let took = started.elapsed();
        let text = CStr::from_ptr(pam_strerror(pamh, rc)).to_string_lossy();
        println!(
            "pam_authenticate = {rc} ({text}) after {} ms",
            took.as_millis()
        );
        if rc == 0 {
            const PAM_ESTABLISH_CRED: c_int = 0x0002;
            pam_setcred(pamh, PAM_ESTABLISH_CRED);
        }
        pam_end(pamh, rc);
        std::process::exit(if rc == 0 { 0 } else { 1 });
    }
}
