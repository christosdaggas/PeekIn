# Contributing to PeekIn

Thank you for helping. PeekIn sits in the login path of people's
computers, so every change is judged first by one question: can it lock anyone
out, or let the wrong person in? The password must always keep working, and
anything unexpected must fall back to it.

## Reporting problems

- **Security issues** (a way to get past face authentication, a privilege
  problem, a crash in the PAM module): do not open a public issue. See
  [SECURITY.md](SECURITY.md).
- **Bugs**: open an issue with the bug template. Include the output of
  `sudo peekin doctor`, your camera model, the Fedora version and, for
  login problems, `journalctl -b | grep -E 'pam_peekin|peekin'`.
- **Ideas**: open an issue with the feature template and describe the problem
  first, the solution second.

## Building and testing

Fedora is the supported platform (see the README for the packages).

```sh
sudo dnf builddep packaging/peekin.spec
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked         # includes the PAM/authselect and libpam tests
sh packaging/test-system-setup.sh
cargo test -p peekin-settings --locked gtk_smoke -- --ignored --test-threads=1   # GTK smoke test
packaging/build-rpm.sh                  # the RPMs
```

The PAM module's end-to-end test creates accounts and must run as root in a
throwaway container or VM, never on your own machine:

```sh
cargo build -p peekin-pam --lib --examples --locked
sudo PEEKIN_E2E=1 sh packaging/test-pam-module.sh
```

CI (`.github/workflows/ci.yml`) runs all of this on Fedora 44, plus the RPM
install, the SELinux policy checks, the translation and man page checks. A
pull request should pass it.

To try the app without installing anything, use development mode with private
directories (see `peekin-settings(1)`).

## Guidelines

- **Fail closed.** Invalid or unreadable security settings disable face
  authentication; they never fall back to a weaker default. Add the key to the
  security list in `crates/peekin-core/src/config.rs` when that applies.
- **Least privilege.** The recognition worker runs as the `peekin`
  account; only the PAM module and the polkit helper run as root. New root
  code needs a clear reason.
- **Tests with the change.** Every behaviour change comes with a test that
  fails without it. Changes to the PAM path extend
  `packaging/test-pam-module.sh`.
- **Say what is measured.** Security claims in docs name their evidence;
  unmeasured values are called estimates (see docs/THRESHOLDS.md).
- **Settings** are documented in `data/config.ini` and in
  `data/man/peekin-config.5`; a unit test checks the man page lists every
  key.
- **User-visible text** goes through `tr()`, `tr_args()` or `trn()`
  (`peekin_core::i18n`). Logs stay in English.
- Keep changes focused; unrelated clean-ups belong in their own pull request.

## Translations

Translations use gettext; the template is `po/peekin.pot`.

- Update after changing text: `sh po/update.sh`, then translate the new
  entries (CI fails while any message is untranslated).
- New language: `msginit -i po/peekin.pot -l <lang> -o po/<lang>.po`, or
  copy `po/el.po` as a starting point. Keep every `{placeholder}` unchanged;
  `msgfmt --check` verifies them.
- Also translate the `<description>` and `<message>` elements in
  `data/com.chrisdaggas.peekin.policy` and the desktop entry.

## Licence

By contributing you agree that your contribution is licensed under the MIT
licence of this project (see LICENSE).
