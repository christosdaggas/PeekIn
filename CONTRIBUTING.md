# Contributing

Keep changes focused. Face login must always fall back to the password when
something fails.

## Report a problem

- **Bugs:** use the bug report form. Include your PeekIn version, distribution,
  desktop, camera and `sudo peekin doctor` output.
- **Ideas:** explain the problem and the improvement you want.
- **Security issues:** report privately; see [SECURITY.md](SECURITY.md).

For login problems, include relevant output from
`journalctl -b | grep -E 'pam_peekin|peekin'`. Remove private information.

## Build and test

See the [README](README.md#build-from-source) for Fedora and Debian build commands.
Before submitting a change, run:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
sh packaging/test-system-setup.sh
cargo test -p peekin-settings --locked gtk_smoke -- --ignored --test-threads=1
```

For Debian packaging changes, also run:

```sh
sh packaging/deb/test-pam-setup.sh
sh packaging/deb/test-models-service.sh
```

Run the PAM end-to-end test **only in a disposable VM or container**: it creates
accounts and requires root.

```sh
cargo build -p peekin-pam --lib --examples --locked
sudo PEEKIN_E2E=1 sh packaging/test-pam-module.sh
```

## Change checklist

- Add tests for changed behavior, including password fallback for PAM changes.
- Invalid security settings must disable face login, not weaken it.
- Keep privileged work limited to the PAM module and polkit helper.
- Update `data/config.ini` and `data/man/peekin-config.5` for setting changes.
- Support security claims with evidence; see [threshold measurements](docs/THRESHOLDS.md).
- Make sure CI passes before merging.

## Translations

Use `tr()`, `tr_args()` or `trn()` for user-facing text; keep logs in English.
Run `sh po/update.sh` after text changes and translate new entries.
To add a language:

```sh
msginit -i po/peekin.pot -l <lang> -o po/<lang>.po
```

Keep `{placeholders}` unchanged and check with `msgfmt --check`.
Also translate the polkit policy and desktop entry in `data/`.

Contributions use the project's [MIT license](LICENSE).
