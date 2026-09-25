<p align="center">
  <img src="app.png" alt="PeekIn UI" width="100%">
</p>

<h1 align="center">PeekIn</h1>

<p align="center">
  <b>Look. Recognize. Unlock.</b><br>
  Face authentication for Linux.
</p>

---

Typing your password dozens of times a day gets old. With **PeekIn** you just
look at your camera, and your Linux machine knows it's you: `sudo` in the
terminal, the GNOME lock screen and the login screen all open with a glance.

Your password always keeps working. If the camera can't see you, if it's too
dark or if anything goes wrong, PeekIn steps aside and asks for the password
as usual.

## Why PeekIn

- **Unlock with a glance.** Look at the camera for `sudo`, the lock screen or
  the login screen. No extra hardware needed: a regular webcam works, and
  infrared cameras are supported too.
- **Hard to fool with a photo.** After it recognises you, PeekIn asks for a
  short random sequence of head turns (for example LEFT, RIGHT, LEFT). A
  printed photo or a picture on a phone can't follow instructions.
- **Your face stays on your computer.** Nothing goes to the cloud. Face data
  is encrypted with your computer's TPM chip (or a host key where there is
  none), so a copied disk or a backup is useless to anyone else.
- **You decide where it works.** Turn face login on or off separately for
  `sudo`, the login screen, the lock screen, administrator dialogs and the text
  console. It never works over SSH.
- **Locks when you walk away.** The optional Away lock locks your screen when
  you leave your desk, and PeekIn tells you when someone tried to unlock it
  while you were gone.
- **Stops guessing.** After a few rejected faces in a row, face login pauses
  until you use your password.
- **Brightens up in the dark.** In a dim room PeekIn briefly turns up the
  laptop screen so the camera can see your face.
- **Pick your cameras.** Laptop with several cameras? Choose one for face
  login and another for the Away lock.
- **A friendly app.** Add your face with a live preview, test recognition,
  see a history of every attempt and change every setting without editing a
  file. It speaks English and Greek.
- **Built for Fedora.** One RPM sets up PAM, SELinux and the system services
  for you, and `dnf remove` undoes those changes.

## How it works

1. **Add your face.** Open the PeekIn app and look at the camera for a few
   seconds. You can add more than one face model, for example with and without
   glasses.
2. **Look at the camera.** When you run `sudo` or unlock your screen, PeekIn
   checks the camera for a moment.
3. **Turn your head when asked.** Follow the on-screen head turns, and you're
   in. You can switch this check off if you prefer speed over protection.

Under the hood PeekIn is written in Rust and uses OpenCV's YuNet face detector
and SFace face recognizer, running entirely on your own computer.

## Get started

On Fedora, build and install the RPM:

```sh
sudo dnf install rpm-build rpmdevtools curl 'dnf-command(builddep)'
sudo dnf builddep packaging/peekin.spec
packaging/build-rpm.sh
sudo dnf install dist/rpm/peekin-[0-9]*.rpm
sudo peekin doctor
```

Then open **PeekIn** from your applications and add your face. That's it.

`sudo peekin doctor` checks the whole installation and tells you how to fix
anything that is missing.

## Be aware

PeekIn is a convenience, not a replacement for your password. The head-turn
check makes photos and recorded videos much harder to use, but no ordinary
webcam can prove that a live person is in front of it: a skilled attacker with
a 3D mask or a live video feed could still get through. Keep a strong
password. Technical details are in [Security](#security) below.

> While functional, it may contain bugs or security issues. Use at your own risk.
>
> No Warranty: This software is provided "AS IS" without warranty of any kind, express or implied. See the LICENSE file for full details.

## Author

Made by Christos A. Daggas · <info@chrisdaggas.com> · <https://chrisdaggas.com>

Inspired by Howdy and Windows Hello.

---

## Technical documentation

Everything below is for administrators and developers.

### Components

- `pam_peekin.so` (`peekin-pam`): PAM module. Runs
  `peekin-compare` with a hard deadline and bounded reap, so camera
  failures fall through to the
  password when configured as `sufficient`.
- `peekin-compare` (`peekin-vision`): camera capture and face
  recognition.
- `peekin` (`peekin-cli`): root-oriented `add`, `test`, `list`, `clear`,
  `remove`, `disable`, `set`, `config`, `cameras`, `doctor`, `version`.
- `peekin-settings`: GTK4 + libadwaita settings app with settings,
  face models (list/remove, and add with a live camera preview) and a
  visual recognition test. It runs as the logged-in user. A separate
  `peekin-helper` exposes only typed metadata/settings/enroll/remove/test
  operations. Polkit uses separate actions; settings, enrollment and removal
  always require fresh administrator authorization. The helper derives the
  target account from `PKEXEC_UID` and accepts no user or path override.

Not implemented: photos of successful logins (`save_successful`, ignored),
rubberstamps (a config that enables them disables face login rather than
skipping them), password-prompt workarounds (only `workaround = off`: the scan
runs before the password prompt).

### Layout

- `crates/peekin-core/`: config, paths, model store, the scan loop
  (`compare.rs`) and enrollment (`enroll.rs`) behind the `FaceSource` trait.
  No native dependencies; the PAM module links it.
- `crates/peekin-vision/`: OpenCV implementation of `FaceSource`, plus
  `peekin-compare`.
- `crates/peekin-pam/`: `pam_peekin.so` and `examples/pam-harness.rs`.
- `crates/peekin-cli/`: the `peekin` command, `peekin-helper` and
  `examples/benchmark.rs`.
- `crates/peekin-settings/`: the settings app.
- `data/`: default `config.ini`, `fetch-models.sh`, polkit policy, desktop
  entry, icon.
- `data/systemd/`: the boot and session services and their presets.
- `packaging/`: RPM spec, build script, `system-setup`, SELinux module.
- `po/`: translations. `docs/`: thresholds and COPR notes.
- `dist/rpm/`: the RPMs `packaging/build-rpm.sh` builds (not in git).

### Build

Rust 1.92 or newer is required (the locked gtk4-rs crates declare it).

```sh
sudo dnf install cargo rust opencv-devel clang-devel pam-devel gtk4-devel libadwaita-devel
cargo build --release
cargo test --workspace
```

### Install as an RPM (Fedora)

```sh
sudo dnf install rpm-build rpmdevtools curl 'dnf-command(builddep)'
sudo dnf builddep packaging/peekin.spec   # every BuildRequires, incl. SELinux tools
packaging/build-rpm.sh     # -> dist/rpm/peekin-*.rpm
sudo dnf install dist/rpm/peekin-[0-9]*.rpm
sudo peekin doctor    # confirms the installation is complete
```

Manual pages: `peekin(1)`, `peekin-settings(1)`, `peekin-session(1)`,
`peekin-config(5)` (every setting) and `pam_peekin(8)`.

`build-rpm.sh` checks its prerequisites first and prints the command that
installs anything missing. The source RPM also builds in a clean chroot:
`SRPM_ONLY=1 packaging/build-rpm.sh && mock -r fedora-44-x86_64
target/rpmbuild/SRPMS/peekin-*.src.rpm`. Upgrading is a plain
`dnf install`/`dnf upgrade` of a newer RPM; face models and settings are kept.
The service account comes from a shipped `sysusers.d` file, so RPM creates it
before installing files and the model store is packaged with its final
ownership (`root:peekin`, 0750).

The build also produces `peekin-debuginfo` and `peekin-debugsource`.
Install them next to the package (`sudo dnf install
dist/rpm/peekin-debug*.rpm`) when reporting a crash,
so backtraces (`coredumpctl gdb`) show function names and source lines.

For installing and updating with `dnf` from a COPR repository, see
[docs/COPR.md](docs/COPR.md) (the repository must first be set up by the
maintainer).

`dnf` pulls in the OpenCV, GTK4 and libadwaita runtime libraries; the face
models are included. After installation the package (see
`packaging/system-setup`) attempts to:

- repair the face model store permissions and add the service account to
  the `video` group (this runs first and even when PAM integration is refused),
- load the SELinux module `peekin` (lets GDM map the camera buffers),
- add `auth [success=done default=ignore] pam_peekin.so` immediately before
  `pam_unix.so`. Direct standalone sudo/GDM stacks use a validated local edit.
  For Fedora's standard `include system-auth`/`substack password-auth` services,
  the installer copies the active authselect profile to
  `/etc/authselect/custom/peekin`, validates the rendered authentication
  control flow, and selects that profile with the same features. Validated
  Fedora `local` and `sssd` profiles are supported. Mandatory-smartcard and
  unknown jump/control layouts are refused rather than risking a PAM bypass.
  It records the
  previous selection privately so removal can restore it **only while the PeekIn profile is still active**. Unknown/custom PAM layouts are refused.
  The PAM module accepts faces only for the places switched on in
  `[services]` (by default `sudo`, the login screen and the lock screen), even
  though the shared authselect profile is loaded by other services. SSH and
  unlisted services can never use a face match.

Enroll with the PeekIn app or `sudo peekin add`; users without a
face model are not affected. `sudo dnf remove peekin` restores the prior
authselect selection (if unchanged), or removes the standalone PAM lines, and
removes the SELinux module. Generated authselect PAM files are never edited.

### Try it without installing

The CLI and settings app can run against private directories as a normal user:

```sh
data/fetch-models.sh /tmp/peekin/data/models
mkdir -p /tmp/peekin/etc /tmp/peekin/pam.d
cp data/config.ini /tmp/peekin/etc/      # device_path = none picks a camera
EUID_CHECK_SKIP=1 target/release/peekin --config-dir /tmp/peekin/etc \
    --data-dir /tmp/peekin/data -U "$USER" add
# settings app against the same directories, without pkexec
target/release/peekin-settings --dev --cli "$PWD/target/release/peekin" \
    --config-dir /tmp/peekin/etc --data-dir /tmp/peekin/data
```

Production PAM deliberately requires the dedicated service account and protected
template store. The previous normal-user PAM demo no longer establishes a valid
production identity. `cargo test -p peekin-pam --test pam_control` tests
authentication ordering and password fallback through real libpam using
private, camera-free fixtures. No live PAM file is changed by that test.

### PAM module

Options: `config_dir=` (default `/etc/peekin`), `data_dir=`
(`/usr/share/peekin`), `compare=`
(`/usr/libexec/peekin/peekin-compare`). The installer supports the
validated Fedora authselect layout and a narrow standalone stack, and rejects
unknown control flow without rewriting it. It never edits generated
`system-auth`/`password-auth` files directly. The previous authselect selection
is stored at `/var/lib/peekin/authselect-previous.json` with mode 0600.
Logs are written under the calling program (sudo, gdm-session-worker):
`journalctl -b | grep pam_peekin`.

### Configuration

`/etc/peekin/config.ini`, editable with the settings app or
`sudo peekin config`:

- `[core] movement_challenge` (default `true`): after recognising the face,
  ask for a random sequence of three head turns. `false` unlocks as soon as
  the face matches on three spaced frames ("look at the camera"), usually in
  well under a second, but a photo or a phone screen showing the user is then
  far more likely to work, especially with a colour webcam. The settings app
  has a "Head-movement check" switch; the Test tab and `peekin test`
  follow the saved value. A malformed value keeps face authentication off.
- Security level (settings app): Fast = no head turns (still required
  without an approved infrared camera), threshold 0.363; Balanced (the
  defaults) = head turns, 0.363; Secure = head turns, 0.45 and the personal
  threshold. Changing any of these settings by hand shows "Custom".
- `[core] require_movement_without_ir` (default `true`): with
  `movement_challenge = false`, the head turns are still required unless the
  camera in use is an administrator-approved infrared camera
  (`/etc/peekin/ir-profiles.json`). The PAM module picks the mode from the
  camera; the worker checks it again after opening the camera and refuses a
  weaker mode. Switch "Keep it on without an infrared camera" in the settings
  app; `false` restores plain look-at-the-camera matching on colour cameras.
- `[core] max_failed_attempts` (default 5, 0 = off): after this many rejected
  faces in a row (face not recognised, or head movement not followed) face
  login pauses for 15 minutes, or until the user logs in with the password,
  which resets the counter. "No face seen" and camera problems do not count.
  Counters: `/var/lib/peekin/failures/<user>` (root, 0600, SELinux type
  `peekin_var_lib_t`). `peekin doctor` and the settings app (System
  status → Failed face attempts) show the state; the app's Resume button lifts
  a pause after administrator authentication.
- `[services]`: where face login may be used. `sudo` (also `sudo -i`),
  `login_screen` (GDM after boot; the GNOME keyring then stays locked until
  the password is typed), `lock_screen` (GDM unlock of a running session,
  recognised from the user's logind session) are on by default; `polkit`
  (administrator dialogs, `pkexec`) and `console` (local text console login)
  are opt-in and experimental. They rely on the Fedora authselect profile,
  whose system-auth stack those services include. SSH is never allowed.
- `[video] timeout`: scan time, 1 to 10 seconds, default 3. With the
  head-movement check the head turns get up to 8 more seconds after the face
  is recognised. A scan that never sees a face ends with "No face seen".
  Linux Hello before 1.3 shipped 10 s. RPM keeps a `config.ini` you have edited,
  so an upgraded system can still scan for 10 s; `peekin doctor` and the
  settings app point this out when the value and its old comment are unchanged.
- `[video] device_path`: `none` (default) chooses the camera each time face
  authentication starts (administrator-attested infrared first, then the first
  colour camera, then an unverified grayscale/infrared node, whose emitter often
  stays off on Linux; select such a sensor explicitly if it works). A fixed
  `/dev/v4l/by-id/...` path survives moving a USB camera to another port;
  `/dev/v4l/by-path/...` is tied to the port.
- `[video] ir_only`: allow only an administrator-attested physical IR profile.
  Grayscale pixel formats are a heuristic and are not trusted by themselves.
  Unknown and virtual cameras therefore fall back to password.
- `[video] min_similarity`: cosine similarity in the shared UI/core range
  0.2 through 1.0 (default 0.363). Values such as 0.99 are preserved.
  [docs/THRESHOLDS.md](docs/THRESHOLDS.md) lists the measured share of
  strangers accepted and of genuine attempts rejected for each value (on
  LFW, 13,233 photos): at 0.363 about 1 stranger in 240 matches a 5-sample
  model, at 0.45 about 1 in 5,700.
- `[video] personal_threshold` (default `false`): raise `min_similarity` for
  each user from their own enrollment. It takes the least similar pair of
  samples within one face model, subtracts 0.30 and caps the result at 0.50;
  the threshold used is the higher of that and `min_similarity`, so it is
  never lowered. A user's own samples say nothing about how close other faces
  come, which is why it only tightens. Measured stranger and rejection rates
  for these values are in [docs/THRESHOLDS.md](docs/THRESHOLDS.md). `peekin doctor` and the settings
  app ("Personal threshold") show the value for your account.
- `[video] brighten_screen` (default `true`): when a colour camera's first
  frames are dark, the recognition worker asks the PAM module to set the
  built-in screen (`/sys/class/backlight`) to full brightness for the rest of
  the scan; the previous brightness is restored when the scan ends, unless it
  was changed meanwhile. External monitors are not touched. On the text
  console and in polkit dialogs SELinux does not allow writing the backlight,
  so the screen stays as it is there (logged). `sudo peekin test` does
  the same, to try it out. Switch "Light up the screen in the dark".
- Improve recognition: the + button of a face model in the app adds 5 more
  samples to it (e.g. in dim light), up to 15 per model. A login is compared
  with every sample, so each sample is also another chance for a stranger
  (docs/THRESHOLDS.md); for a different look, add a new model instead.
- History: every scan is recorded (time, where, result, the face model that
  matched) in `/var/lib/peekin-activity/<user>`, the newest 200 entries.
  The file is root-owned with a POSIX ACL that lets only that user read it, so
  the settings app ("Activity" on the Face models page) shows it without a
  password; nobody but root can change it. It has no effect on authentication.
- Session helper (`peekin-session`, a systemd user service enabled for
  every user): after an unlock it shows a notification when faces were
  rejected while you were away. Its optional walk-away lock (off by default)
  locks the screen when there has been no input for the away time (60 s) and
  no face is in front of the camera for 10 s; the camera is only used while
  there is no input, and a busy or dark camera or a playing video never leads
  to a lock. Set per user on the app's "Away lock" page, stored in
  `~/.config/peekin/session.ini`; see `peekin-session(1)`. It has its own
  camera choice (same as face login, any colour camera, any infrared camera,
  or a specific one), so face login can use the infrared sensor while the away
  lock uses the colour camera, or the other way round. Face login's camera is
  chosen on the Settings page. With a camera such as the Logitech Brio, colour
  and infrared are separate devices, and PeekIn opens only the one it uses,
  so other applications keep the other; whether a camera can stream both at
  the same time is up to its firmware.
- `[snapshots] save_failed` (default `false`) and `keep` (default 20): keep a
  JPEG of each attempt where a face was seen but not accepted (wrong face, or
  the head movement not followed) in `/var/log/peekin` (0700, owned by the
  `peekin` worker account, SELinux type `peekin_log_t`), deleting the
  oldest beyond `keep`. No photo is taken of attempts without a face, camera
  errors or successful logins. The settings app ("Photos of failed attempts"
  on the Face models page) shows and deletes the photos of attempts on your own
  account after administrator authentication; `peekin doctor` shows how
  many are stored.
- PAM independently caps the runtime
  and kills/reaps the recognition process after a fixed startup grace.
- Security-critical malformed values (`disabled`, SSH/lid guards, `ir_only`,
  threshold or timeout) disable face authentication and fall back to password;
  they are never silently replaced for an authentication decision.
- Settings Apply is one locked, conflict-detecting atomic transaction. It
  validates the whole candidate and preserves unrelated comments/layout.
- Face models written by older dlib-based tools are listed but never used
  for matching; re-enroll with `peekin add`.

#### Physical infrared attestations

There is no built-in list that trusts a device name. After establishing that a
capture node is genuinely IR, an administrator may create
`/etc/peekin/ir-profiles.json`, owned by root and not group/world-writable.
The parent directory must also be root-controlled. The file contains up to 32
entries of this form (replace every illustrative value with observed evidence):

```json
[
  {
    "identity": {
      "vid": "046d",
      "pid": "085e",
      "bcd_device": "0317",
      "serial": "the observed unit serial",
      "interface_number": 0,
      "interface_class": "0e",
      "capture_index": 2,
      "driver": "uvcvideo"
    },
    "evidence": "Manufacturer IR documentation and local emitter validation, date and hardware revision"
  }
]
```

The identity is taken from the device's physical USB interface `modalias`,
while `capture_index` comes from `/sys/class/video4linux/videoN/index`. The
driver must match `VIDIOC_QUERYCAP`. The Logitech Brio 4K on this machine
exposes its IR sensor at video index 2 (GREY-only); index 0 is colour and is
not trusted as IR. Profile matching is independent of USB port and hub.
All fields must match, capture formats must be grayscale-only, and
`/sys/devices/virtual` is rejected. This is an
administrator attestation, not cryptographic device identity or PAD certification.

#### Settings app

Settings, Face models, Test, Away lock and About are separate pages. Readiness keeps configuration,
camera, PAM and model status separate. Apply is enabled only for pending changes
while idle; failed saves preserve edits and Reload offers explicit discard.
Enrollment supports Retry capture and Retry save with the label retained.
Testing follows the saved head-movement setting (a per-attempt randomized
challenge, or a plain match when it is off), with Stop, a countdown and
expandable bounded diagnostics. The pages remain
accessible from the header, with compact tabs at narrow widths; testing and
enrollment content scroll. Settings and model actions display progress and a
Cancel control while cancellation is safe. Once a privileged write has been
handed to its helper, the app waits and reconciles the result instead of
claiming an uncertain write was cancelled; failed saves retain unsaved edits.

### Security

This is a convenience, not a replacement for a password. Authentication needs
three spaced, single-person frames matching the same model, followed (unless
`movement_challenge = false` and either an approved infrared camera is used or
`require_movement_without_ir = false`) by a freshly randomized on-screen instruction for
**three ordered left/right head turns** with a return to centre between each turn. The system requires
landmark changes on distinct frames of the same matching face. A missing PAM
conversation or missing landmarks falls back to password. This frustrates a
static photograph or fixed prerecorded clip; it is **not** independently
validated liveness/PAD and does not defeat interactive replay, a movable 3D
mask or a camera feed controlled by an attacker. Face files are root-owned mode 0640
under a root-owned mode 0750 directory; only the dedicated non-login
`peekin` service group receives read access. Authenticating users cannot
write their biometric trust material.

Face models are encrypted on disk: `/etc/peekin/models/<user>.dat.cred`,
sealed with `systemd-creds` (AES-256-GCM) using the TPM2 chip together with
the host key `/var/lib/systemd/credential.secret`, or the host key alone on a
machine without a TPM. They are not bound to PCRs, so firmware and kernel
updates keep them readable. `peekin-models.service` decrypts them at boot into
`/run/peekin/models` (memory; SELinux type `peekin_run_t`), which PAM, the
worker and the app read; every change is sealed again, and plaintext models
found on disk (e.g. after an upgrade) are sealed and removed from it
(`sudo peekin unseal-models` does this by hand). This keeps the face data
unreadable to someone who reads the disk in another computer or gets a
backup of `/etc`. It does not protect against root on this system, nor
against someone who has the whole machine and boots it from other media,
since the TPM is on the board and the host key on the disk; full-disk
encryption (LUKS, unlocked by the TPM with `systemd-cryptenroll`) protects
everything else as well. If the TPM is cleared, the models cannot be
decrypted any more: add your face again (the password keeps working).

Enrollment rejects small, strongly non-frontal, blurry, multi-person and
cross-identity sample sets. The size/pose/sharpness cutoffs are engineering
heuristics, not empirically calibrated quality or accessibility guarantees.

### Troubleshooting

`sudo peekin doctor` checks the configuration, the ONNX models, the
service account, access to your face model, the camera (including whether the
service account may open it), PAM integration and the SELinux module, and
prints the command that fixes each problem. `sudo
/usr/libexec/peekin/system-setup install` is idempotent and repairs
permissions, group membership, SELinux and PAM integration.

PAM checks the camera and face model access before it shows anything, so a
broken installation falls straight through to the password. When a scan
fails, the lock screen/sudo shows why (not recognised in time, camera could
not be opened, too dark, head movement did not follow the instructions).
Details: `journalctl -b | grep pam_peekin`; SELinux denials:
`sudo ausearch -m avc -ts boot`. Infrared sensors frequently need their
emitter switched on (e.g. `linux-enable-ir-emitter`); if tests report dark
frames, select the colour camera in the settings app.

### Evaluation and diagnostics

`peekin test --until-match` prints a versioned JSON `timing` record with
model-load, camera-open, first-frame/usable-frame, detection, recognition and
total timings. `accepted_ms` measures wall time from command start through
matching and movement-challenge acceptance; it is null for a non-match,
rather than the fixed test duration.
For repeated median/p95 measurements using the protected model store:

```sh
cargo build --release -p peekin-cli --example benchmark
sudo target/release/examples/benchmark 20 "$USER"
```

Run this on every supported camera, resolution, FPS, lighting condition and
target machine. Record cold and warm runs separately. No project hardware
benchmark has been performed for this release, so no latency improvement or
hardware compatibility claim is made.

Camera-free checks:

```sh
cargo test --workspace --offline --locked   # also PAM/authselect and libpam
sh packaging/test-system-setup.sh
# real pam_peekin.so through libpam with a stub worker; creates the
# peekin account, so only in a disposable container/VM, as root:
cargo build -p peekin-pam --lib --examples
PEEKIN_E2E=1 sh packaging/test-pam-module.sh
```

The ignored `gtk_smoke` test can be run on an isolated GTK display with
`cargo test -p peekin-settings gtk_smoke -- --ignored --test-threads=1`; it
starts and stops a loopback-only Broadway display (`gtk4-broadwayd`) unless
`GDK_BACKEND` is already set.
It exercises real GTK widgets, tab navigation, threshold preservation and
operation guards. Unit/IPC tests also cover hung processes, cancellation,
truncated/oversized packets, slow readers and settings-write conflicts.

Before treating a hardware profile as verified infrared, record USB/vendor and
product IDs, stable capture node, formats, negotiated resolution/FPS, emitter
behavior in darkness, and tests showing that colour/virtual/sibling nodes are
rejected by `ir_only`. Accuracy calibration requires consenting genuine-user
and impostor trials across lighting, pose, glasses and appearance changes;
report false accept/reject rates and the chosen threshold. PAD requires a
separate attack protocol using printed photos, phone/tablet replay, video,
masks and any device-specific bypasses. The randomized motion challenge is
only a mitigation, not PAD certification; measure how often legitimate users
can complete it within their configured timeout.

Keyboard navigation, small-window scrolling and widget labels are implemented,
but live screen-reader, high-contrast, magnification and alternate-input testing
has not been performed. Those checks, camera hardware validation, threshold
calibration on webcam and infrared images (the LFW measurement is in
docs/THRESHOLDS.md), PAD evaluation, GDM/sudo integration on installed Fedora,
and SELinux behavior remain hard release-validation blockers, not proven facts.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for building, testing and the ground
rules, and [SECURITY.md](SECURITY.md) for reporting vulnerabilities privately.

## Translations

The settings app, the messages on the login and lock screens (head-turn
instructions, failures, "Face recognised: …"), the polkit password dialogs
and the desktop entry are translated with gettext (text domain `peekin`).
Greek (`el`) is included. The PAM module follows the locale of the program
that runs it, e.g. GDM or sudo; the journal log stays in English.

After changing user-visible text, run `sh po/update.sh` and translate the new
entries in `po/el.po`; CI fails while any message is untranslated. A new
language is a new `po/<lang>.po` (`msginit -i po/peekin.pot -l <lang>`).
The command-line tool is not translated.

## License

MIT, see `LICENSE`. The SFace model is Apache-2.0.
