//! A panic inside the module must never reach the PAM host: no unwinding and
//! nothing on the host's stderr (sudo's terminal, GDM's journal), only a
//! message for the module's own log. A binary of its own, because the test
//! redirects this process's stderr.

use std::io::Read;
use std::os::fd::AsRawFd;

#[test]
fn a_panic_is_caught_silently_and_reported() {
    let captured = std::env::temp_dir().join(format!("peekin-panic-{}", std::process::id()));
    let file = std::fs::File::create(&captured).unwrap();
    // SAFETY: plain descriptor juggling on descriptors this test owns.
    let saved = unsafe { libc::dup(2) };
    assert!(saved >= 0);
    assert_eq!(unsafe { libc::dup2(file.as_raw_fd(), 2) }, 2);
    let failed = pam_peekin::run_guarded(|| -> i32 { panic!("camera exploded") });
    let fine = pam_peekin::run_guarded(|| 7);
    unsafe {
        libc::dup2(saved, 2);
        libc::close(saved);
    }
    let mut printed = String::new();
    std::fs::File::open(&captured)
        .unwrap()
        .read_to_string(&mut printed)
        .unwrap();
    let _ = std::fs::remove_file(&captured);
    assert_eq!(printed, "", "the panic reached the host's stderr");
    let message = failed.unwrap_err();
    assert!(message.contains("camera exploded"), "{message}");
    assert!(
        message.contains("panic_quiet.rs"),
        "location for the log: {message}"
    );
    assert_eq!(fine, Ok(7));
}
