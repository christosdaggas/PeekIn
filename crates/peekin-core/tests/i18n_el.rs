//! The Greek catalogue compiles and is used at runtime. A separate test
//! binary, because the locale is process-wide.

use peekin_core::compare::{ChallengeMode, ChallengeStage};
use peekin_core::i18n::{bind, tr, tr_args, trn};
use std::path::Path;
use std::process::Command;

#[test]
fn greek_messages_are_used_in_a_greek_session() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let dir = std::env::temp_dir().join(format!("peekin-i18n-{}", std::process::id()));
    let messages = dir.join("el/LC_MESSAGES");
    std::fs::create_dir_all(&messages).unwrap();
    let status = Command::new("msgfmt")
        .arg("--check")
        .arg("-o")
        .arg(messages.join("peekin.mo"))
        .arg(root.join("po/el.po"))
        .status()
        .expect("msgfmt (gettext) is needed to build the translations");
    assert!(status.success(), "po/el.po does not compile");

    // A Greek session, as GTK or GDM would set it up (glibc ignores
    // LANGUAGE in the C locales). Needs the Greek glibc locale
    // (glibc-langpack-el on Fedora).
    std::env::remove_var("LANGUAGE");
    // SAFETY: single-threaded at this point of the test binary.
    let set = unsafe { libc::setlocale(libc::LC_ALL, c"el_GR.UTF-8".as_ptr()) };
    assert!(
        !set.is_null(),
        "el_GR.UTF-8 locale missing: install glibc-langpack-el"
    );
    bind(&dir);

    assert_eq!(tr("Cancel"), "Ακύρωση");
    assert_eq!(
        tr_args("Face recognised: {username}", &[("username", &"alice")]),
        "Αναγνωρίστηκε το πρόσωπο: alice"
    );
    assert_eq!(
        trn("{n} recent failed attempt", "{n} recent failed attempts", 1),
        "1 πρόσφατη αποτυχημένη προσπάθεια"
    );
    assert_eq!(
        trn("{n} recent failed attempt", "{n} recent failed attempts", 3),
        "3 πρόσφατες αποτυχημένες προσπάθειες"
    );
    assert_eq!(
        ChallengeMode::Passive.prompt(),
        "Έλεγχος προσώπου: κοιτάξτε την κάμερα."
    );
    let mode = ChallengeMode::for_config(true).unwrap();
    let movement = mode.prompt();
    assert!(movement.starts_with("Έλεγχος προσώπου"), "{movement}");
    // The prompt before the scan names no turn; each one comes on its own.
    assert!(
        !movement.contains("ΑΡΙΣΤΕΡΑ") && !movement.contains("ΔΕΞΙΑ"),
        "{movement}"
    );
    let ChallengeMode::Movement(order) = mode else {
        panic!("movement expected")
    };
    let turn = ChallengeStage::Turn(0).instruction(order);
    assert!(
        turn == "Γυρίστε το κεφάλι ΑΡΙΣΤΕΡΑ" || turn == "Γυρίστε το κεφάλι ΔΕΞΙΑ",
        "{turn}"
    );
    assert_eq!(
        tr("A message nobody translated"),
        "A message nobody translated"
    );
    let _ = std::fs::remove_dir_all(dir);
}
