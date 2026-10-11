//! `peekin doctor`: read-only checks that explain why face authentication would not start.

use peekin_core::cameras::{self, CameraKind, ResolveError};
use peekin_core::models::{self, usable_embeddings, ModelError};
use peekin_core::paths::VISION_MODELS;
use peekin_core::{PeekinConfig, PeekinPaths};
use std::ffi::{CStr, CString};
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const SERVICE_USER: &str = "peekin";
const REPAIR: &str = "sudo /usr/libexec/peekin/system-setup install";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Ok,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub level: Level,
    pub topic: &'static str,
    pub message: String,
}

#[derive(Debug, Default)]
pub struct Report(pub Vec<Finding>);

impl Report {
    fn add(&mut self, level: Level, topic: &'static str, message: impl Into<String>) {
        self.0.push(Finding {
            level,
            topic,
            message: message.into(),
        });
    }

    pub fn worst(&self) -> Level {
        self.0.iter().map(|f| f.level).max().unwrap_or(Level::Ok)
    }

    pub fn print(&self) {
        for finding in &self.0 {
            let tag = match finding.level {
                Level::Ok => "  ok ",
                Level::Warn => " warn",
                Level::Fail => " FAIL",
            };
            println!("[{tag}] {:<14} {}", finding.topic, finding.message);
        }
        println!(
            "\n{}",
            match self.worst() {
                Level::Ok => "No problems found.",
                Level::Warn => "Face authentication can run; review the warnings above.",
                Level::Fail =>
                    "Face authentication cannot run until the FAIL items are fixed. \
                     Details of past attempts: journalctl -b | grep pam_peekin",
            }
        );
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceAccount {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub groups: Vec<libc::gid_t>,
    pub shell: String,
}

pub fn service_account() -> Option<ServiceAccount> {
    let name = CString::new(SERVICE_USER).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: all pointers reference live, correctly sized buffers.
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_shell.is_null() {
        return None;
    }
    let shell = unsafe { CStr::from_ptr(pwd.pw_shell) }
        .to_string_lossy()
        .into_owned();
    let mut count: libc::c_int = 64;
    let mut groups = vec![0 as libc::gid_t; count as usize];
    // SAFETY: `groups` holds `count` entries; getgrouplist updates `count`.
    if unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut count) } < 0
    {
        groups.resize(count.max(0) as usize, 0);
        unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut count) };
    }
    groups.truncate(count.max(0) as usize);
    Some(ServiceAccount {
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        groups,
        shell,
    })
}

fn group_name(gid: libc::gid_t) -> String {
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    // SAFETY: as in `service_account`.
    let rc = unsafe { libc::getgrgid_r(gid, &mut grp, buf.as_mut_ptr(), buf.len(), &mut result) };
    if rc != 0 || result.is_null() {
        return gid.to_string();
    }
    unsafe { CStr::from_ptr(grp.gr_name) }
        .to_string_lossy()
        .into_owned()
}

/// Classic permission bits only: ACLs such as logind's `uaccess` never cover the service account.
pub fn can_read_write(metadata: &std::fs::Metadata, account: &ServiceAccount) -> bool {
    let mode = metadata.mode();
    let bits = if metadata.uid() == account.uid {
        mode >> 6
    } else if account.groups.contains(&metadata.gid()) || metadata.gid() == account.gid {
        mode >> 3
    } else {
        mode
    };
    bits & 0o6 == 0o6
}

fn check_config(report: &mut Report, paths: &PeekinPaths) -> Option<PeekinConfig> {
    let config = match PeekinConfig::load(&paths.config_file_path()) {
        Ok(config) => config,
        Err(error) => {
            report.add(Level::Fail, "config", error.to_string());
            return None;
        }
    };
    let security = config.security_errors();
    for problem in config.invalid_values() {
        let level = if security.contains(&problem) {
            Level::Fail
        } else {
            Level::Warn
        };
        report.add(level, "config", problem);
    }
    if config.disabled() {
        report.add(
            Level::Fail,
            "config",
            "face authentication is disabled ([core] disabled = true)",
        );
    } else if security.is_empty() {
        report.add(
            Level::Ok,
            "config",
            format!(
                "enabled; head-movement check {}, timeout {} s, threshold {}",
                if config.movement_challenge() {
                    "on"
                } else if config.require_movement_without_ir() {
                    "on unless an approved infrared camera is used"
                } else {
                    "off"
                },
                config.video_timeout_secs(),
                config.min_similarity()
            ),
        );
    }
    if config.legacy_default_timeout() {
        report.add(
            Level::Warn,
            "config",
            "scan time is 10 s, the default of Linux Hello before 1.3 (upgrades keep an edited \
             config.ini); the default is now 3 s: change it in the settings app or with: \
             sudo peekin set timeout 3",
        );
    }
    Some(config)
}

fn check_recognition_models(report: &mut Report, paths: &PeekinPaths) {
    let missing: Vec<_> = VISION_MODELS
        .iter()
        .map(|name| paths.vision_model_dir.join(name))
        .filter(|path| !path.is_file())
        .collect();
    if missing.is_empty() {
        report.add(Level::Ok, "onnx models", "YuNet and SFace present");
    } else {
        for path in missing {
            report.add(
                Level::Fail,
                "onnx models",
                format!("{} is missing; reinstall the package", path.display()),
            );
        }
    }
}

fn check_account(report: &mut Report) -> Option<ServiceAccount> {
    let Some(account) = service_account() else {
        report.add(
            Level::Fail,
            "service user",
            format!("account {SERVICE_USER} does not exist; repair with: {REPAIR}"),
        );
        return None;
    };
    if !(account.shell.ends_with("/nologin") || account.shell.ends_with("/false")) {
        report.add(
            Level::Fail,
            "service user",
            format!(
                "{SERVICE_USER} has login shell {}; PAM refuses it",
                account.shell
            ),
        );
    } else if let Err(error) =
        peekin_core::process::validate_service_identity(account.uid, account.gid, &account.groups)
    {
        report.add(Level::Fail, "service user", error.to_string());
    } else {
        let names: Vec<_> = account.groups.iter().map(|g| group_name(*g)).collect();
        report.add(
            Level::Ok,
            "service user",
            format!(
                "{SERVICE_USER} (uid {}), groups {}",
                account.uid,
                names.join(",")
            ),
        );
    }
    Some(account)
}

fn check_face_models(
    report: &mut Report,
    paths: &PeekinPaths,
    user: &str,
    account: Option<&ServiceAccount>,
) {
    match models::load_user_models(paths.user_models_dir(), user) {
        Ok(items) => {
            let usable = usable_embeddings(&items).len();
            if usable == 0 {
                report.add(
                    Level::Fail,
                    "face models",
                    format!("{user} has only legacy models; re-enroll with: sudo peekin add"),
                );
            } else {
                report.add(
                    Level::Ok,
                    "face models",
                    format!(
                        "{user}: {} model(s), {usable} usable sample(s)",
                        items.len()
                    ),
                );
            }
        }
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => {
            report.add(
                Level::Fail,
                "face models",
                format!(
                    "no face model for {user}; enroll in the PeekIn app or with: sudo peekin add"
                ),
            );
            return;
        }
        Err(error) => {
            report.add(Level::Fail, "face models", error.to_string());
            return;
        }
    }
    if let Some(account) = account {
        match models::check_service_access(paths.user_models_dir(), user, account.gid) {
            Ok(()) => report.add(
                Level::Ok,
                "model access",
                format!("{SERVICE_USER} can read the face model of {user}"),
            ),
            Err(reason) => report.add(
                Level::Fail,
                "model access",
                format!("{reason}; repair with: {REPAIR}"),
            ),
        }
    }
}

fn check_camera(report: &mut Report, config: &PeekinConfig, account: Option<&ServiceAccount>) {
    let configured = config.device_path();
    let device = match cameras::resolve_for(&configured, config.ir_only()) {
        Ok(device) => device,
        Err(
            error @ (ResolveError::NoCamera | ResolveError::NoInfrared | ResolveError::Missing(_)),
        ) => {
            report.add(Level::Fail, "camera", error.to_string());
            return;
        }
    };
    let kind = cameras::kind_of(&device);
    let described = match kind {
        Some(CameraKind::VerifiedInfrared) => "administrator-approved infrared",
        Some(CameraKind::InfraredCandidate) => "possible infrared (not approved)",
        Some(CameraKind::Colour) => "colour",
        None => {
            report.add(
                Level::Fail,
                "camera",
                format!(
                    "{} is not a video capture device (metadata node?)",
                    device.display()
                ),
            );
            return;
        }
    };
    report.add(
        Level::Ok,
        "camera",
        format!(
            "{}{} ({described})",
            device.display(),
            if config.device_is_automatic() {
                " selected automatically"
            } else {
                ""
            }
        ),
    );
    if kind == Some(CameraKind::InfraredCandidate) {
        report.add(
            Level::Warn,
            "camera",
            "unverified infrared sensor: its emitter often needs switching on (e.g. \
             linux-enable-ir-emitter); if `peekin test` reports dark frames, use the colour camera",
        );
    }
    if config.ir_only() && kind != Some(CameraKind::VerifiedInfrared) {
        report.add(
            Level::Fail,
            "camera",
            format!(
                "ir_only = true but this node has no administrator attestation in \
                 /etc/peekin/ir-profiles.json; review it with: sudo peekin cameras --attest {}",
                device.display()
            ),
        );
    }
    if !config.movement_required(kind) && kind != Some(CameraKind::VerifiedInfrared) {
        report.add(
            Level::Warn,
            "security",
            "head-movement check is off without an approved infrared camera: a photo or phone \
             screen showing you may unlock (require_movement_without_ir = true prevents this)",
        );
    }
    if let Some(account) = account {
        match std::fs::metadata(&device) {
            Ok(metadata) if can_read_write(&metadata, account) => report.add(
                Level::Ok,
                "camera access",
                format!("{SERVICE_USER} may open {}", device.display()),
            ),
            Ok(metadata) => report.add(
                Level::Fail,
                "camera access",
                format!(
                    "{SERVICE_USER} cannot open {} (group {}, mode {:04o}); add it to that group: \
                     sudo usermod -aG {} {SERVICE_USER}",
                    device.display(),
                    group_name(metadata.gid()),
                    metadata.mode() & 0o7777,
                    group_name(metadata.gid())
                ),
            ),
            Err(error) => report.add(Level::Fail, "camera access", error.to_string()),
        }
    }
}

fn check_pam(report: &mut Report, pam_dir: &Path) {
    use peekin_core::authselect::file_uses_module;
    let direct = ["sudo", "gdm-password"].map(|s| file_uses_module(&pam_dir.join(s)));
    let shared = ["system-auth", "password-auth"].map(|s| file_uses_module(&pam_dir.join(s)));
    match (direct, shared) {
        ([true, true], _) => report.add(Level::Ok, "pam", "enabled directly for sudo and GDM"),
        (_, [true, true]) => report.add(
            Level::Ok,
            "pam",
            "enabled through the custom/peekin authselect profile",
        ),
        _ => report.add(
            Level::Fail,
            "pam",
            format!(
                "pam_peekin.so is not in the sudo/GDM authentication stack; enable with: {REPAIR}"
            ),
        ),
    }
}

fn check_services(report: &mut Report, config: &PeekinConfig, pam_dir: &Path) {
    use peekin_core::config::FaceService;
    let enabled: Vec<_> = FaceService::ALL
        .into_iter()
        .filter(|s| config.service_enabled(*s))
        .collect();
    if enabled.is_empty() {
        report.add(
            Level::Fail,
            "services",
            "face login is switched off everywhere ([services])",
        );
        return;
    }
    let names: Vec<_> = enabled.iter().map(|s| s.key()).collect();
    report.add(
        Level::Ok,
        "services",
        format!("enabled for {}", names.join(", ")),
    );
    for (service, pam_name) in [
        (FaceService::Polkit, "polkit-1"),
        (FaceService::Console, "login"),
    ] {
        if config.service_enabled(service)
            && !peekin_core::authselect::service_uses_module(pam_dir, pam_name)
        {
            report.add(
                Level::Warn,
                "services",
                format!(
                    "{} is enabled, but /etc/pam.d/{pam_name} does not use pam_peekin.so \
                     (it works with the Fedora authselect profile)",
                    service.key()
                ),
            );
        }
    }
}

fn selinux_enforcing() -> bool {
    std::fs::read_to_string("/sys/fs/selinux/enforce").is_ok_and(|value| value.trim() == "1")
}

fn check_selinux(report: &mut Report) {
    if !selinux_enforcing() {
        return;
    }
    let loaded = std::process::Command::new("semodule")
        .arg("-l")
        .output()
        .ok()
        .filter(|out| out.status.success())
        .map(|out| {
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .any(|l| l.split_whitespace().next() == Some("peekin"))
        });
    match loaded {
        Some(true) => report.add(Level::Ok, "selinux", "peekin policy module loaded"),
        Some(false) => report.add(
            Level::Fail,
            "selinux",
            format!("peekin module not loaded: the login screen cannot stream from the camera; repair with: {REPAIR}"),
        ),
        None => report.add(
            Level::Warn,
            "selinux",
            "could not list SELinux modules (run as root); denials: sudo ausearch -m avc -ts boot",
        ),
    }
}

fn check_lockout(report: &mut Report, config: &PeekinConfig, state_dir: &Path, user: &str) {
    match peekin_core::lockout::load(state_dir, user) {
        Ok(record) => {
            let now = peekin_core::lockout::now();
            match record.pause(now, config.max_failed_attempts()) {
                Some(pause) => report.add(
                    Level::Fail,
                    "attempts",
                    format!(
                        "face login paused after {} for another {} min; \
                         logging in with the password lifts it",
                        match pause.cause {
                            peekin_core::lockout::PauseCause::FailedFaces(n) =>
                                format!("{n} failed attempts"),
                            peekin_core::lockout::PauseCause::NoFace(n) =>
                                format!("{n} scans without a face after a head-turn challenge"),
                        },
                        pause.until.saturating_sub(now).div_ceil(60).max(1)
                    ),
                ),
                None => report.add(
                    Level::Ok,
                    "attempts",
                    format!(
                        "{} recent failed attempt(s); limit {}",
                        record.current(now).failures,
                        match config.max_failed_attempts() {
                            0 => "off".to_string(),
                            n => n.to_string(),
                        }
                    ),
                ),
            }
        }
        // Without root (development mode) the doctor cannot see what PAM sees.
        Err(error)
            if error.kind() == std::io::ErrorKind::PermissionDenied
                && unsafe { libc::geteuid() } != 0 =>
        {
            report.add(
                Level::Warn,
                "attempts",
                format!("cannot read the failed-attempt counter (run as root): {error}"),
            )
        }
        // PAM keeps face login off while the counter is damaged or unreadable,
        // unless the limit is off: then it does not use the counter.
        Err(error) if config.max_failed_attempts() > 0 => report.add(
            Level::Fail,
            "attempts",
            format!(
                "face login is off for {user} (password only) until a password login clears \
                 the failed-attempt counter or its labels are repaired: {error}; \
                 repair with: {REPAIR}"
            ),
        ),
        Err(error) => report.add(
            Level::Warn,
            "attempts",
            format!(
                "the failed-attempt counter cannot be used ({error}); it is ignored while \
                 the attempt limit is off"
            ),
        ),
    }
}

const LOCKOUT_SELINUX_TYPE: &str = "peekin_var_lib_t";

fn selinux_type(path: &Path) -> Option<String> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = [0u8; 256];
    // SAFETY: both strings are NUL-terminated and buf outlives the call.
    let len = unsafe {
        libc::lgetxattr(
            path.as_ptr(),
            c"security.selinux".as_ptr(),
            buf.as_mut_ptr().cast(),
            buf.len(),
        )
    };
    let context = buf.get(..usize::try_from(len).ok()?)?;
    let context = std::str::from_utf8(context).ok()?.trim_end_matches('\0');
    context.split(':').nth(2).map(str::to_string)
}

const MODEL_STORE_SELINUX_TYPE: &str = "peekin_run_t";

/// With the wrong type the login and lock screen (xdm_t) cannot even stat the
/// face model, and PAM falls through to the password ("no face model for user").
fn check_model_store_label(report: &mut Report, path: &Path, actual: Option<&str>) {
    let Some(other) = actual.filter(|t| *t != MODEL_STORE_SELINUX_TYPE) else {
        return;
    };
    report.add(
        Level::Fail,
        "selinux",
        format!(
            "{} has SELinux type {other}, not {MODEL_STORE_SELINUX_TYPE}: the login and lock \
             screen cannot read the face models and fall back to the password; repair with: \
             {REPAIR}",
            path.display()
        ),
    );
}

/// Installed systems read the decrypted face models from memory; a store filled
/// before the policy module was loaded carries the generic /run type.
fn check_model_store_labels(report: &mut Report, paths: &PeekinPaths, user: &str) {
    if paths.sealed_models_dir().is_none() {
        return; // a development tree keeps plaintext models under its config dir
    }
    let mut targets = vec![paths.user_models_dir().to_path_buf()];
    if let Ok(file) = paths.user_model_path(user) {
        if file.exists() {
            targets.push(file);
        }
    }
    for path in targets {
        let actual = selinux_type(&path);
        check_model_store_label(report, &path, actual.as_deref());
    }
}

/// With the wrong type the login screen, console and polkit cannot read or write
/// the failure counter, and PAM, failing closed, leaves them the password only.
fn check_lockout_label(report: &mut Report, config: &PeekinConfig, actual: Option<&str>) {
    let Some(other) = actual.filter(|t| *t != LOCKOUT_SELINUX_TYPE) else {
        return;
    };
    if config.max_failed_attempts() > 0 {
        report.add(
            Level::Fail,
            "attempts",
            format!(
                "{} has SELinux type {other}, not {LOCKOUT_SELINUX_TYPE}: face login can be off \
                 (password only) on the login screen, the console and in polkit dialogs, whose \
                 domains cannot read or write the failed-attempt counter; repair with: {REPAIR}",
                peekin_core::lockout::STATE_DIR
            ),
        );
    }
}

fn check_threshold(report: &mut Report, config: &PeekinConfig, paths: &PeekinPaths, user: &str) {
    let Ok(items) = models::load_user_models(paths.user_models_dir(), user) else {
        return; // check_face_models already explains why
    };
    let known = usable_embeddings(&items);
    let global = config.min_similarity();
    let message = match peekin_core::matcher::personal_threshold(&known) {
        None => format!(
            "no face model with two samples yet; the threshold is {global} \
             (personal_threshold {})",
            if config.personal_threshold() {
                "on"
            } else {
                "off"
            }
        ),
        Some(_) if config.personal_threshold() => format!(
            "personal threshold on: {:.3} for {user} (global {global})",
            config.effective_min_similarity(&known)
        ),
        Some(personal) => format!(
            "personal threshold off; from {user}'s samples it would be {:.3} (global {global})",
            f64::from(personal).max(global)
        ),
    };
    report.add(Level::Ok, "threshold", message);
}

/// `tpm_present`: /dev/tpmrm0 exists.
fn check_sealed(
    report: &mut Report,
    config: &PeekinConfig,
    paths: &PeekinPaths,
    user: &str,
    tpm_present: bool,
) {
    let Some(sealed_dir) = paths.sealed_models_dir() else {
        return;
    };
    let policy = match peekin_core::sealed::SealPolicy::from_config(config) {
        Ok(policy) => policy,
        Err(error) => {
            report.add(
                Level::Fail,
                "encryption",
                format!(
                    "{error}: face models cannot be added, changed or removed until it is fixed"
                ),
            );
            return;
        }
    };
    if !config.tpm2_pcrs().unwrap_or_default().is_empty() && !tpm_present {
        report.add(
            Level::Fail,
            "encryption",
            "[core] tpm2_pcrs binds the face models to TPM PCRs, but there is no TPM \
             (/dev/tpmrm0): face models cannot be encrypted; remove the setting"
                .to_string(),
        );
    }
    let on_disk = sealed_dir.join(format!("{user}.dat"));
    let sealed = peekin_core::sealed::sealed_path(sealed_dir, user).exists();
    let in_memory = paths.user_models_dir().join(format!("{user}.dat")).exists();
    if on_disk.exists() {
        report.add(
            Level::Warn,
            "encryption",
            format!(
                "{} is an unencrypted face model on the disk; encrypt it with: sudo peekin unseal-models",
                on_disk.display()
            ),
        );
    }
    match (sealed, in_memory) {
        (true, true) => report.add(
            Level::Ok,
            "encryption",
            format!(
                "face models of {user} are encrypted on disk with {}",
                policy.describe()
            ),
        ),
        (true, false) => report.add(
            Level::Fail,
            "encryption",
            format!(
                "the encrypted face models of {user} were not decrypted at boot \
                 (peekin-models.service, or the TPM was cleared); repair with: \
                 sudo peekin unseal-models, or add your face again"
            ),
        ),
        (false, true) => report.add(
            Level::Fail,
            "encryption",
            format!(
                "the face models of {user} have no encrypted copy and will be lost at the \
                 next boot; add your face again (and check that systemd-creds works)"
            ),
        ),
        (false, false) => {}
    }
}

const POWER_SUPPLY_DIR: &str = "/sys/class/power_supply";

/// `abort_if_lid_closed` reads the ACPI lid state or an input device's lid
/// switch. A laptop (it has a battery) that offers neither would scan with
/// the lid closed.
fn check_lid(
    report: &mut Report,
    config: &PeekinConfig,
    lid: &peekin_core::lid::Paths,
    supplies: &Path,
) {
    if !config.abort_if_lid_closed() {
        return;
    }
    let sources = peekin_core::lid::sources(lid);
    let battery = std::fs::read_dir(supplies).is_ok_and(|entries| {
        entries.flatten().any(|e| {
            std::fs::read_to_string(e.path().join("type")).is_ok_and(|t| t.trim() == "Battery")
        })
    });
    if !sources.is_empty() {
        report.add(
            Level::Ok,
            "lid",
            format!(
                "face login is skipped while the lid is closed (read from {})",
                sources.join(", ")
            ),
        );
    } else if battery {
        report.add(
            Level::Warn,
            "lid",
            format!(
                "abort_if_lid_closed is on, but this laptop reports no lid state in {} and no \
                 input device with a lid switch: face login cannot tell that the lid is closed \
                 and would scan anyway",
                lid.acpi.display()
            ),
        );
    }
}

fn check_snapshots(report: &mut Report, config: &PeekinConfig, dir: &Path) {
    if !config.save_failed_snapshots() {
        return;
    }
    let message = match peekin_core::snapshots::list_all(dir) {
        Ok(all) => format!(
            "saving photos of failed attempts in {}: {} stored, newest {} per account kept",
            dir.display(),
            all.len(),
            config.snapshot_keep()
        ),
        Err(error) => {
            report.add(
                Level::Warn,
                "snapshots",
                format!(
                    "save_failed is on but {} is unusable ({error}); repair with: {REPAIR}",
                    dir.display()
                ),
            );
            return;
        }
    };
    report.add(Level::Ok, "snapshots", message);
}

pub fn run(paths: &PeekinPaths, user: &str) -> Report {
    let mut report = Report::default();
    let config = check_config(&mut report, paths);
    check_recognition_models(&mut report, paths);
    let account = check_account(&mut report);
    check_face_models(&mut report, paths, user, account.as_ref());
    if let Some(config) = &config {
        check_services(&mut report, config, Path::new("/etc/pam.d"));
        check_threshold(&mut report, config, paths, user);
        check_sealed(
            &mut report,
            config,
            paths,
            user,
            Path::new("/dev/tpmrm0").exists(),
        );
        check_snapshots(
            &mut report,
            config,
            Path::new(peekin_core::snapshots::SNAPSHOT_DIR),
        );
        check_lid(
            &mut report,
            config,
            &peekin_core::lid::Paths::system(),
            Path::new(POWER_SUPPLY_DIR),
        );
        check_camera(&mut report, config, account.as_ref());
        check_lockout(
            &mut report,
            config,
            Path::new(peekin_core::lockout::STATE_DIR),
            user,
        );
        if selinux_enforcing() {
            let actual = selinux_type(Path::new(peekin_core::lockout::STATE_DIR));
            check_lockout_label(&mut report, config, actual.as_deref());
            check_model_store_labels(&mut report, paths, user);
        }
    }
    check_pam(&mut report, Path::new("/etc/pam.d"));
    check_selinux(&mut report);
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn account(uid: u32, gid: u32, groups: &[u32]) -> ServiceAccount {
        ServiceAccount {
            uid,
            gid,
            groups: groups.to_vec(),
            shell: "/usr/sbin/nologin".into(),
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("peekin-doctor-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn device_access_follows_owner_then_group_then_other_bits() {
        let dir = temp("access");
        let node = dir.join("video0");
        std::fs::write(&node, "").unwrap();
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o660)).unwrap();
        let metadata = std::fs::metadata(&node).unwrap();
        let (uid, gid) = (metadata.uid(), metadata.gid());
        assert!(can_read_write(&metadata, &account(uid, 999_999, &[])));
        assert!(can_read_write(
            &metadata,
            &account(999_998, 999_999, &[gid])
        ));
        assert!(!can_read_write(
            &metadata,
            &account(999_998, 999_999, &[999_999])
        ));
        std::fs::set_permissions(&node, std::fs::Permissions::from_mode(0o666)).unwrap();
        let metadata = std::fs::metadata(&node).unwrap();
        assert!(can_read_write(&metadata, &account(999_998, 999_999, &[])));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn legacy_scan_time_is_pointed_out() {
        let dir = temp("legacy-timeout");
        let old = "[video]\n# 10 s is the new-install default.\ntimeout = 10\n";
        for (raw, legacy) in [(old, true), ("[video]\ntimeout = 10\n", false)] {
            std::fs::write(dir.join("config.ini"), raw).unwrap();
            let paths = PeekinPaths::from_dirs(dir.clone(), dir.clone());
            let mut report = Report::default();
            check_config(&mut report, &paths).unwrap();
            let found = report.0.iter().any(|f| f.message.contains("set timeout 3"));
            assert_eq!(found, legacy, "{:?}", report.0);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sealing_problems_are_reported_with_their_repair() {
        let dir = temp("sealed");
        let (etc, run) = (dir.join("etc"), dir.join("run"));
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        let mut paths = PeekinPaths::from_dirs(dir.join("cfg"), dir.join("data"));
        paths.user_models_dir = run.clone();
        paths.sealed_models_dir = Some(etc.clone());
        let config = PeekinConfig::empty();
        let check = |paths: &PeekinPaths| {
            let mut report = Report::default();
            check_sealed(&mut report, &config, paths, "alice", false);
            report
        };
        assert!(check(&paths).0.is_empty(), "no models, nothing to say");
        std::fs::write(etc.join("alice.dat.cred"), "x").unwrap();
        let r = check(&paths);
        assert_eq!(r.worst(), Level::Fail);
        assert!(r.0[0].message.contains("unseal-models"), "{:?}", r.0);
        std::fs::write(run.join("alice.dat"), "[]").unwrap();
        assert_eq!(check(&paths).worst(), Level::Ok);
        std::fs::write(etc.join("alice.dat"), "[]").unwrap();
        assert_eq!(check(&paths).worst(), Level::Warn);
        let dev = PeekinPaths::from_dirs(dir.join("cfg"), dir.join("data"));
        assert!(check(&dev).0.is_empty(), "development trees are not sealed");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pcr_binding_is_shown_and_refused_without_a_tpm() {
        let dir = temp("sealed-pcrs");
        let (etc, run) = (dir.join("etc"), dir.join("run"));
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&run).unwrap();
        std::fs::write(etc.join("alice.dat.cred"), "x").unwrap();
        std::fs::write(run.join("alice.dat"), "[]").unwrap();
        let mut paths = PeekinPaths::from_dirs(dir.join("cfg"), dir.join("data"));
        paths.user_models_dir = run;
        paths.sealed_models_dir = Some(etc);
        let check = |body: &str, tpm: bool| {
            let config = PeekinConfig::parse(body, "<t>".into()).unwrap();
            let mut report = Report::default();
            check_sealed(&mut report, &config, &paths, "alice", tpm);
            report
        };
        let bound = check("[core]\ntpm2_pcrs = 7\n", true);
        assert_eq!(bound.worst(), Level::Ok, "{:?}", bound.0);
        assert!(bound.0[0].message.contains("PCR 7"), "{:?}", bound.0);
        let no_tpm = check("[core]\ntpm2_pcrs = 7\n", false);
        assert_eq!(no_tpm.worst(), Level::Fail);
        assert!(no_tpm.0[0].message.contains("no TPM"), "{:?}", no_tpm.0);
        let invalid = check("[core]\ntpm2_pcrs = 99\n", true);
        assert_eq!(invalid.worst(), Level::Fail);
        assert!(
            invalid.0[0].message.contains("tpm2_pcrs"),
            "{:?}",
            invalid.0
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_laptop_without_lid_state_is_warned_about() {
        let dir = temp("lid");
        let (lid, supplies) = (peekin_core::lid::Paths::under(&dir), dir.join("supplies"));
        std::fs::create_dir_all(&lid.acpi).unwrap();
        std::fs::create_dir_all(&lid.input_class).unwrap();
        std::fs::create_dir_all(supplies.join("AC")).unwrap();
        std::fs::write(supplies.join("AC/type"), "Mains\n").unwrap();
        let on = PeekinConfig::empty();
        let check = |config: &PeekinConfig| {
            let mut report = Report::default();
            check_lid(&mut report, config, &lid, &supplies);
            report
        };
        // A desktop: no lid, nothing to say.
        assert!(check(&on).0.is_empty());
        // A laptop without the ACPI lid state: the guard cannot work.
        std::fs::create_dir_all(supplies.join("BAT0")).unwrap();
        std::fs::write(supplies.join("BAT0/type"), "Battery\n").unwrap();
        let r = check(&on);
        assert_eq!(r.worst(), Level::Warn, "{:?}", r.0);
        assert!(r.0[0].message.contains("no lid state"), "{:?}", r.0);
        let off =
            PeekinConfig::parse("[core]\nabort_if_lid_closed = false\n", "<t>".into()).unwrap();
        assert!(
            check(&off).0.is_empty(),
            "nothing to check when switched off"
        );
        // An input device with a lid switch is a source too.
        let switch = lid.input_class.join("event4/device/capabilities");
        std::fs::create_dir_all(&switch).unwrap();
        std::fs::write(switch.join("sw"), "1\n").unwrap();
        let r = check(&on);
        assert_eq!(r.worst(), Level::Ok, "{:?}", r.0);
        assert!(r.0[0].message.contains("event4"), "{:?}", r.0);
        std::fs::remove_dir_all(lid.input_class.join("event4")).unwrap();
        // The ACPI state is there: fine.
        std::fs::create_dir_all(lid.acpi.join("LID0")).unwrap();
        std::fs::write(lid.acpi.join("LID0/state"), "state:      open\n").unwrap();
        assert_eq!(check(&on).worst(), Level::Ok);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn snapshots_are_reported_only_when_switched_on() {
        let dir = temp("snapshots");
        let off = PeekinConfig::parse("", "<t>".into()).unwrap();
        let mut report = Report::default();
        check_snapshots(&mut report, &off, &dir);
        assert!(report.0.is_empty());
        let on = PeekinConfig::parse("[snapshots]\nsave_failed = true\n", "<t>".into()).unwrap();
        peekin_core::snapshots::save(&dir, "alice", 1, b"x", 20).unwrap();
        let mut report = Report::default();
        check_snapshots(&mut report, &on, &dir);
        assert_eq!(report.worst(), Level::Ok);
        assert!(report.0[0].message.contains("1 stored"), "{:?}", report.0);
        let mut report = Report::default();
        check_snapshots(&mut report, &on, &dir.join("missing"));
        assert_eq!(report.worst(), Level::Warn);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lockout_is_reported_until_it_expires() {
        let dir = temp("lockout");
        let config =
            PeekinConfig::parse("[core]\nmax_failed_attempts = 2\n", "<t>".into()).unwrap();
        let mut report = Report::default();
        check_lockout(&mut report, &config, &dir, "alice");
        assert_eq!(report.worst(), Level::Ok);
        let now = peekin_core::lockout::now();
        for _ in 0..2 {
            peekin_core::lockout::record_failure(&dir, "alice", now).unwrap();
        }
        let mut report = Report::default();
        check_lockout(&mut report, &config, &dir, "alice");
        assert_eq!(report.worst(), Level::Fail);
        assert!(
            report.0[0].message.contains("paused after 2"),
            "{:?}",
            report.0
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_pause_after_scans_without_a_face_names_its_cause() {
        let dir = temp("lockout-no-face");
        let config =
            PeekinConfig::parse("[core]\nmax_failed_attempts = 2\n", "<t>".into()).unwrap();
        let now = peekin_core::lockout::now();
        for _ in 0..peekin_core::lockout::MAX_NO_FACE_SCANS {
            let mut report = Report::default();
            check_lockout(&mut report, &config, &dir, "alice");
            assert_eq!(report.worst(), Level::Ok, "{:?}", report.0);
            peekin_core::lockout::record_no_face(&dir, "alice", now).unwrap();
        }
        let mut report = Report::default();
        check_lockout(&mut report, &config, &dir, "alice");
        assert_eq!(report.worst(), Level::Fail);
        let message = &report.0[0].message;
        assert!(
            message.contains("paused after 10 scans without a face"),
            "{message}"
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unusable_counter_turns_face_login_off() {
        let dir = temp("lockout-unusable");
        let config =
            PeekinConfig::parse("[core]\nmax_failed_attempts = 2\n", "<t>".into()).unwrap();
        // Damaged content, and a directory where the counter belongs: PAM
        // leaves these accounts with the password only.
        std::fs::write(dir.join("alice"), "garbage\n").unwrap();
        std::fs::create_dir(dir.join("bob")).unwrap();
        for user in ["alice", "bob"] {
            let mut report = Report::default();
            check_lockout(&mut report, &config, &dir, user);
            assert_eq!(report.worst(), Level::Fail, "{:?}", report.0);
            let message = &report.0[0].message;
            assert!(
                message.starts_with(&format!("face login is off for {user} "))
                    && message.contains("until a password login clears")
                    && message.contains("labels are repaired")
                    && message.ends_with(&format!("repair with: {REPAIR}")),
                "{message}"
            );
        }
        let mut report = Report::default();
        check_lockout(&mut report, &config, &dir, "alice");
        assert!(report.0[0].message.contains("is damaged"), "{:?}", report.0);
        // With the limit off PAM does not use the counter.
        let off = PeekinConfig::parse("[core]\nmax_failed_attempts = 0\n", "<t>".into()).unwrap();
        let mut report = Report::default();
        check_lockout(&mut report, &off, &dir, "alice");
        assert_eq!(report.worst(), Level::Warn, "{:?}", report.0);
        assert!(
            !report.0[0].message.contains("face login is off"),
            "{:?}",
            report.0
        );
        // Without root the doctor cannot see what PAM sees (development mode).
        let closed = dir.join("closed");
        std::fs::create_dir(&closed).unwrap();
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o000)).unwrap();
        let mut report = Report::default();
        check_lockout(&mut report, &config, &closed, "carol");
        std::fs::set_permissions(&closed, std::fs::Permissions::from_mode(0o700)).unwrap();
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(report.worst(), Level::Warn, "{:?}", report.0);
            assert!(
                report.0[0].message.contains("run as root"),
                "{:?}",
                report.0
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn lockout_directory_needs_its_selinux_type() {
        let config = PeekinConfig::parse("", "<t>".into()).unwrap();
        let mut report = Report::default();
        check_lockout_label(&mut report, &config, Some("peekin_var_lib_t"));
        check_lockout_label(&mut report, &config, None);
        assert!(report.0.is_empty(), "{:?}", report.0);
        check_lockout_label(&mut report, &config, Some("xdm_var_lib_t"));
        assert_eq!(report.worst(), Level::Fail);
        // PAM fails closed: the confined places cannot use the counter, so
        // their face login is off.
        let message = &report.0[0].message;
        assert!(
            message.contains("xdm_var_lib_t")
                && message.contains("face login can be off")
                && message.contains("login screen, the console and in polkit")
                && !message.contains("may not be enforced")
                && message.ends_with(&format!("repair with: {REPAIR}")),
            "{message}"
        );
        let off = PeekinConfig::parse("[core]\nmax_failed_attempts = 0\n", "<t>".into()).unwrap();
        let mut report = Report::default();
        check_lockout_label(&mut report, &off, Some("var_lib_t"));
        assert!(report.0.is_empty(), "{:?}", report.0);
    }

    #[test]
    fn model_store_needs_its_selinux_type() {
        let mut report = Report::default();
        let file = Path::new("/run/peekin/models/alice.dat");
        check_model_store_label(&mut report, file, Some("peekin_run_t"));
        check_model_store_label(&mut report, file, None);
        assert!(report.0.is_empty(), "{:?}", report.0);
        // Created before the policy module was loaded: the login screen (xdm_t)
        // may not even stat it, so PAM reports "no face model for user".
        check_model_store_label(&mut report, file, Some("var_run_t"));
        assert_eq!(report.worst(), Level::Fail);
        let message = &report.0[0].message;
        assert!(
            message.contains("var_run_t")
                && message.contains("peekin_run_t")
                && message.contains("alice.dat")
                && message.contains(REPAIR),
            "{message}"
        );
    }

    #[test]
    fn model_store_labels_are_checked_on_installed_systems_only() {
        // Only meaningful on an SELinux host; elsewhere there is no label.
        if !Path::new("/sys/fs/selinux/enforce").exists() {
            return;
        }
        let dir = temp("store-label");
        let (run, etc) = (dir.join("run"), dir.join("etc"));
        std::fs::create_dir_all(&run).unwrap();
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::write(run.join("alice.dat"), "[]").unwrap();
        let mut paths = PeekinPaths::from_dirs(etc.clone(), dir.join("data"));
        paths.user_models_dir = run.clone();
        // A development tree keeps plaintext models; no label is required.
        let mut report = Report::default();
        check_model_store_labels(&mut report, &paths, "alice");
        assert!(report.0.is_empty(), "{:?}", report.0);
        // An installed system reads the store from memory, which must be
        // peekin_run_t; a temporary directory never is. The directory and the
        // user's model are both reported.
        paths.sealed_models_dir = Some(etc);
        check_model_store_labels(&mut report, &paths, "alice");
        let messages: Vec<_> = report.0.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(messages.len(), 2, "{messages:?}");
        assert!(
            report.0.iter().all(|f| f.level == Level::Fail),
            "{messages:?}"
        );
        assert!(
            messages[0].starts_with(&run.display().to_string()),
            "{messages:?}"
        );
        assert!(messages[1].contains("alice.dat"), "{messages:?}");
        // Nothing to say about a model that does not exist.
        let mut report = Report::default();
        check_model_store_labels(&mut report, &paths, "nobody");
        assert_eq!(report.0.len(), 1, "{:?}", report.0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn selinux_type_reads_the_context_label() {
        // Only meaningful on an SELinux host; elsewhere there is no label.
        if !Path::new("/sys/fs/selinux/enforce").exists() {
            return;
        }
        let dir = temp("label");
        let label = selinux_type(&dir).expect("labelled temp dir");
        assert!(label.ends_with("_t"), "{label}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn optional_services_warn_when_their_stack_lacks_the_module() {
        let dir = temp("services");
        let config = PeekinConfig::parse("[services]\nconsole = true\n", "<t>".into()).unwrap();
        std::fs::write(dir.join("login"), "auth substack system-auth\n").unwrap();
        std::fs::write(dir.join("system-auth"), "auth sufficient pam_unix.so\n").unwrap();
        let mut report = Report::default();
        check_services(&mut report, &config, &dir);
        assert_eq!(report.worst(), Level::Warn);
        std::fs::write(
            dir.join("system-auth"),
            "auth [success=done default=ignore] pam_peekin.so\nauth sufficient pam_unix.so\n",
        )
        .unwrap();
        let mut report = Report::default();
        check_services(&mut report, &config, &dir);
        assert_eq!(report.worst(), Level::Ok, "{:?}", report.0);
        let off = PeekinConfig::parse(
            "[services]\nsudo = false\nlogin_screen = false\nlock_screen = false\n",
            "<t>".into(),
        )
        .unwrap();
        let mut report = Report::default();
        check_services(&mut report, &off, &dir);
        assert_eq!(report.worst(), Level::Fail);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn report_level_is_the_worst_finding() {
        let mut report = Report::default();
        assert_eq!(report.worst(), Level::Ok);
        report.add(Level::Warn, "a", "w");
        report.add(Level::Ok, "b", "o");
        assert_eq!(report.worst(), Level::Warn);
        report.add(Level::Fail, "c", "f");
        assert_eq!(report.worst(), Level::Fail);
    }

    #[test]
    fn pam_detection_ignores_comments() {
        let dir = temp("pam");
        std::fs::write(
            dir.join("sudo"),
            "# auth sufficient pam_peekin.so\nauth include system-auth\n",
        )
        .unwrap();
        std::fs::write(dir.join("gdm-password"), "auth substack password-auth\n").unwrap();
        let mut report = Report::default();
        check_pam(&mut report, &dir);
        assert_eq!(report.worst(), Level::Fail);
        for name in ["system-auth", "password-auth"] {
            std::fs::write(
                dir.join(name),
                "auth [success=done default=ignore] pam_peekin.so\nauth sufficient pam_unix.so\n",
            )
            .unwrap();
        }
        let mut report = Report::default();
        check_pam(&mut report, &dir);
        assert_eq!(report.worst(), Level::Ok);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn config_findings_separate_security_errors_from_warnings() {
        let dir = temp("config");
        let paths = PeekinPaths::from_dirs(dir.clone(), dir.join("data"));
        std::fs::write(paths.config_file_path(), "[video]\nmax_height = -1\n").unwrap();
        let mut report = Report::default();
        assert!(check_config(&mut report, &paths).is_some());
        assert_eq!(report.worst(), Level::Warn);
        std::fs::write(
            paths.config_file_path(),
            "[core]\nmovement_challenge = maybe\n",
        )
        .unwrap();
        let mut report = Report::default();
        check_config(&mut report, &paths);
        assert_eq!(report.worst(), Level::Fail);
        std::fs::remove_file(paths.config_file_path()).unwrap();
        let mut report = Report::default();
        assert!(check_config(&mut report, &paths).is_none());
        assert_eq!(report.worst(), Level::Fail);
        let _ = std::fs::remove_dir_all(dir);
    }
}
