//! `peekin cameras --attest/--revoke` refuse what cannot be attested.

use std::process::Command;

fn peekin(args: &[&str]) -> (bool, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_peekin"))
        .args(args)
        .output()
        .unwrap();
    let text =
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr);
    (out.status.success(), text)
}

#[test]
fn saving_needs_evidence() {
    let (ok, text) = peekin(&["cameras", "--attest", "/dev/null", "--save"]);
    assert!(!ok);
    assert!(text.contains("--evidence"), "{text}");
}

#[test]
fn only_cameras_can_be_attested() {
    for args in [
        &["cameras", "--attest", "/dev/null"][..],
        &["cameras", "--attest", "/nonexistent/video9"][..],
    ] {
        let (ok, text) = peekin(args);
        assert!(!ok);
        assert!(
            text.contains("is not a camera that can be opened"),
            "{text}"
        );
    }
}
