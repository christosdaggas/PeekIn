Name:           peekin
Version:        1.0.0
Release:        7%{?dist}
Summary:        Face authentication for Linux
Packager:       Christos A. Daggas <info@chrisdaggas.com>
Vendor:         Christos A. Daggas

# PeekIn and the YuNet face detection model: MIT.
# SFace face recognition model: Apache-2.0.
# Bundled Rust crates are MIT and/or Apache-2.0 licensed.
License:        MIT AND Apache-2.0
Source0:        %{name}-%{version}.tar.gz
Source1:        face_detection_yunet_2023mar.onnx
Source2:        face_recognition_sface_2021dec.onnx
# Also in the source tree (data/); a separate source so %%pre can embed it.
Source3:        peekin.sysusers

ExclusiveArch:  %{rust_arches}

# Minimum Rust required by the locked gtk4-rs crates (rust-version in Cargo.toml).
BuildRequires:  cargo >= 1.92
BuildRequires:  rust >= 1.92
BuildRequires:  clang-devel
BuildRequires:  opencv-devel
BuildRequires:  pam-devel
BuildRequires:  gtk4-devel
BuildRequires:  libadwaita-devel
# msgfmt for the translations; the Greek locale for their runtime test.
BuildRequires:  gettext
BuildRequires:  glibc-langpack-el
BuildRequires:  systemd-rpm-macros
# checkmodule (checkpolicy) and semodule_package (policycoreutils) by path, so
# the build does not depend on which package ships them in a given release.
BuildRequires:  /usr/bin/checkmodule
BuildRequires:  /usr/bin/semodule_package

Requires:       polkit
# PeekIn replaces the linux-hello package and takes over its settings and
# data (system-setup, %%posttrans).
Obsoletes:      linux-hello < 2.0.0
%{?sysusers_requires_compat}
Requires(pre):  shadow-utils
Requires(post): policycoreutils sed grep coreutils authselect shadow-utils
Requires(preun): policycoreutils sed grep coreutils authselect

%description
PeekIn: Look. Recognize. Unlock. Face authentication for Linux.

PeekIn unlocks sudo, the lock screen and the login screen by recognising
your face with the camera. It consists of a PAM module (pam_peekin.so),
the peekin command line tool and a GTK settings app, all written in Rust.
Face recognition uses OpenCV's YuNet and SFace models.

Face recognition is a convenience, not a replacement for a password. A fresh
head-turn challenge makes static photos and fixed recordings harder to use,
but it is not certified presentation-attack detection.

Installing attempts to enable face authentication for sudo and GNOME login
through a validated direct PAM stack or a copied Fedora authselect profile.
Unsupported profiles are left unchanged and passwords remain the fallback.
The package loads a small SELinux module so GDM can use the camera. Enroll
your face with the PeekIn app or "sudo peekin add".

%prep
%autosetup -n %{name}-%{version}
echo "8f2383e4dd3cfbb4553ea8718107fc0423210dc964f9f4280604804ed2552fa4  %{SOURCE1}" | sha256sum -c
echo "0ba9fbfa01b5270c96627c4ef784da859931e02f04419c829e83484087c34e79  %{SOURCE2}" | sha256sum -c

%build
cd rust
# Only the vendored crates (no user cache). %%{build_rustflags} keeps full
# debug info; find-debuginfo moves it into the -debuginfo/-debugsource
# packages and rewrites the build paths to /usr/src/debug.
export CARGO_HOME="$PWD/.cargo-home"
export RUSTFLAGS="%{build_rustflags}"
cargo build --release --offline --locked --workspace
checkmodule -M -m -o packaging/selinux/peekin.mod packaging/selinux/peekin.te
semodule_package -o packaging/selinux/peekin.pp -m packaging/selinux/peekin.mod -f packaging/selinux/peekin.fc
for po in po/*.po; do
    msgfmt --check -o "${po%%.po}.mo" "$po"
done

%check
cd rust
# The same environment as %%build, so the tests reuse its build.
export CARGO_HOME="$PWD/.cargo-home"
export RUSTFLAGS="%{build_rustflags}"
cargo test --release --offline --locked --workspace

%install
cd rust
install -Dm755 target/release/peekin %{buildroot}%{_bindir}/peekin
install -Dm755 target/release/peekin-settings %{buildroot}%{_bindir}/peekin-settings
install -Dm755 target/release/peekin-helper %{buildroot}%{_libexecdir}/peekin/peekin-helper
install -Dm755 target/release/peekin-compare %{buildroot}%{_libexecdir}/peekin/peekin-compare
install -Dm755 target/release/peekin-session %{buildroot}%{_libexecdir}/peekin/peekin-session
install -Dm644 data/systemd/peekin-session.service %{buildroot}%{_userunitdir}/peekin-session.service
install -Dm644 data/systemd/peekin-user.preset %{buildroot}%{_userpresetdir}/80-peekin.preset
install -Dm644 data/systemd/peekin-models.service %{buildroot}%{_unitdir}/peekin-models.service
install -Dm644 data/systemd/peekin-system.preset %{buildroot}%{_presetdir}/80-peekin.preset
install -Dm644 data/peekin.tmpfiles %{buildroot}%{_tmpfilesdir}/peekin.conf
install -Dm755 target/release/libpam_peekin.so %{buildroot}%{_libdir}/security/pam_peekin.so
install -Dm644 data/config.ini %{buildroot}%{_sysconfdir}/peekin/config.ini
# The account and group come from the shipped sysusers.d file: RPM derives
# user(peekin)/group(peekin) from it and creates them before files
# are installed, so the model store can be shipped with its final ownership.
install -Dm644 %{SOURCE3} %{buildroot}%{_sysusersdir}/peekin.conf
install -dm750 %{buildroot}%{_sysconfdir}/peekin/models
install -dm700 %{buildroot}%{_localstatedir}/lib/peekin/failures
install -dm700 %{buildroot}%{_localstatedir}/log/peekin
install -dm711 %{buildroot}%{_localstatedir}/lib/peekin-activity
install -Dm644 %{SOURCE1} %{buildroot}%{_datadir}/peekin/models/face_detection_yunet_2023mar.onnx
install -Dm644 %{SOURCE2} %{buildroot}%{_datadir}/peekin/models/face_recognition_sface_2021dec.onnx
install -Dm644 data/com.chrisdaggas.peekin.policy %{buildroot}%{_datadir}/polkit-1/actions/com.chrisdaggas.peekin.policy
install -Dm644 data/com.chrisdaggas.peekin.desktop %{buildroot}%{_datadir}/applications/com.chrisdaggas.peekin.desktop
for page in data/man/*.[158]; do
    install -Dm644 "$page" %{buildroot}%{_mandir}/man${page##*.}/$(basename "$page")
done
for mo in po/*.mo; do
    lang=$(basename "$mo" .mo)
    install -Dm644 "$mo" %{buildroot}%{_datadir}/locale/$lang/LC_MESSAGES/%{name}.mo
done
install -Dm755 packaging/system-setup %{buildroot}%{_libexecdir}/peekin/system-setup
install -Dm644 packaging/selinux/peekin.pp %{buildroot}%{_datadir}/selinux/packages/peekin.pp
install -Dm644 data/icons/hicolor/scalable/apps/com.chrisdaggas.peekin.svg %{buildroot}%{_datadir}/icons/hicolor/scalable/apps/com.chrisdaggas.peekin.svg

# Run in rust/ (where %%install works), so the list is rust/%%{name}.lang.
%find_lang %{name}

%pre
# Native sysusers.d handling (RPM >= 4.20) creates the account before this
# runs; the compat macro and the explicit fallback are idempotent no-ops then.
%{?sysusers_create_compat:%sysusers_create_compat %{SOURCE3}}
getent group peekin >/dev/null || groupadd -r peekin || :
if ! getent passwd peekin >/dev/null; then
    video=; getent group video >/dev/null && video="-G video"
    useradd -r -g peekin $video -s /usr/sbin/nologin -d /nonexistent \
        -c "PeekIn recognition service" peekin || :
fi

%post
# /run/peekin/models for the decrypted face models, and the boot service that
# fills it (the face models on disk are encrypted with the TPM).
%tmpfiles_create peekin.conf
%systemd_post peekin-models.service
# The per-user session helper, enabled for every user by the preset; it
# starts with the next graphical login.
%systemd_user_post peekin-session.service

%preun
if [ "$1" -eq 0 ]; then
    # Keep the module installed if the previous authselect profile cannot be
    # restored; otherwise PAM could still refer to a removed shared object.
    %{_libexecdir}/peekin/system-setup remove || {
        echo "peekin: not removed: the previous authselect selection could not be restored." >&2
        echo "peekin: check 'authselect current' and /var/lib/peekin/authselect-previous.json," >&2
        echo "peekin: select the profile you want, then retry the removal." >&2
        exit 1
    }
fi
%systemd_user_preun peekin-session.service
%systemd_preun peekin-models.service

%posttrans
# After the whole transaction, so that on the upgrade from linux-hello the old
# package's removal (which restores the previous authselect profile and
# removes its SELinux module) has already run. Idempotent; never fails the
# transaction: the password always keeps working, and "peekin doctor"
# explains anything left to fix. Re-run to repair:
# /usr/libexec/peekin/system-setup install
%{_libexecdir}/peekin/system-setup install || \
    echo "peekin: setup incomplete; run: sudo peekin doctor" >&2

%files -f rust/%{name}.lang
%license rust/LICENSE
%doc rust/README.md rust/docs/THRESHOLDS.md
%{_bindir}/peekin
%{_bindir}/peekin-settings
%dir %{_libexecdir}/peekin
%{_libexecdir}/peekin/peekin-compare
%{_libexecdir}/peekin/peekin-session
%{_userunitdir}/peekin-session.service
%{_userpresetdir}/80-peekin.preset
%{_unitdir}/peekin-models.service
%{_presetdir}/80-peekin.preset
%{_tmpfilesdir}/peekin.conf
%{_libexecdir}/peekin/peekin-helper
%{_libexecdir}/peekin/system-setup
%{_libdir}/security/pam_peekin.so
%{_datadir}/selinux/packages/peekin.pp
%{_datadir}/icons/hicolor/scalable/apps/com.chrisdaggas.peekin.svg
%{_sysusersdir}/peekin.conf
%dir %{_sysconfdir}/peekin
%config(noreplace) %{_sysconfdir}/peekin/config.ini
%dir %attr(0750,root,peekin) %{_sysconfdir}/peekin/models
%dir %attr(0700,root,root) %{_localstatedir}/lib/peekin
%dir %attr(0700,root,root) %{_localstatedir}/lib/peekin/failures
# Photos of failed attempts ([snapshots] save_failed), written by the worker.
%dir %attr(0700,peekin,peekin) %{_localstatedir}/log/peekin
# History of attempts: root-owned files each readable by its user (ACL).
%dir %attr(0711,root,root) %{_localstatedir}/lib/peekin-activity
%{_datadir}/peekin/
%{_datadir}/polkit-1/actions/com.chrisdaggas.peekin.policy
%{_datadir}/applications/com.chrisdaggas.peekin.desktop
%{_mandir}/man1/peekin.1*
%{_mandir}/man1/peekin-settings.1*
%{_mandir}/man1/peekin-session.1*
%{_mandir}/man5/peekin-config.5*
%{_mandir}/man8/pam_peekin.8*

%changelog
* Sun Oct 11 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-7
- With ir_only, automatic camera selection takes only an approved infrared
  camera instead of a colour camera the worker then refuses
- New face models never reuse an ID the attempt history still names
- A plaintext face model next to an encrypted one is reported and left alone
  instead of replacing the encrypted copy at boot
- Stopping peekin-models.service (also on removal) removes the decrypted
  face models from memory
- A face failure recorded after a concurrent password login is counted in
  the new counter instead of a deleted file
- GDM requests count as lock-screen unlocks only for a logind session on a
  seat; a user logged in over SSH gets the login-screen switch
- The settings app's deadline for privileged operations starts when polkit
  has approved them, not while the password dialog is open
- The lid guard also reads the lid switch of an input device (EVIOCGSW),
  for laptops without the ACPI lid state; SELinux policy updated
- The attempt history is rewritten atomically; cameras without a
  /dev/v4l/by-path link are found through /dev/videoN
- The settings app says when the polkit and console switches cannot work
  on this PAM layout; a config.ini without workaround means off
- Translations listed in the README

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-6
- Make the head-movement choices explicit: always, only without approved IR,
  or off; verify all system settings round-trip through the settings helper
- Open the settings window at 1100 px and widen preference cards

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-5
- Keep the test window responsive while camera events stream and return to the
  main window when the test closes or the app is reopened
- Let the test window shrink and scroll its content

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-4
- Move the recognition test to a resizable window and stabilize its live status
- Load existing face models when opening the tab; add a separate Activity tab
- Apply Away Lock changes with the Apply button and add activity log clearing
- Fix the recognized icon and add six translations

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-3
- Face model changes are applied to the encrypted and the active copy or to
  neither, so a failed encryption can no longer bring a removed face back
- Usernames containing dots are decrypted at boot like any other
- An account whose model cannot be decrypted loses its active copy
- The failed-attempt counter fails closed: an unreadable, unwritable or
  damaged counter turns face login off (password only) until repaired
- The model store is refused when it is group or world writable, carries an
  ACL or gives others any access; the worker checks the opened file
- Imported samples follow the same normalisation rule as recognition
- system-setup install recreates the counter directory; doctor and manual
  pages report the new failure modes; security limits documented

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-2
- Load the SELinux module before decrypting the face models and relabel
  /run/peekin, so the lock screen can read models decrypted at install time
- peekin doctor reports a face model store the login screen cannot read

* Fri Sep 25 2026 Christos A. Daggas <info@chrisdaggas.com> - 1.0.0-1
- First release of PeekIn.
