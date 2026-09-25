//! PAM entry points and the minimal libpam FFI. The face scan runs first; on failure PAM moves on to the password.

use crate::run::{run_compare, RunEnd, WorkerIdentity};
use crate::status::{status_decision, ChildEnd, PamCode};
use crate::{
    check_enabled, check_lockout, user_has_session, CompareError, Gate, Lockout, Session,
    LID_STATE_DIR, LOGIND_USERS_DIR,
};
use peekin_core::activity;
use peekin_core::backlight;
use peekin_core::cameras;
use peekin_core::compare::ChallengeMode;
use peekin_core::i18n::{tr, tr_args};
use peekin_core::lockout;
use peekin_core::models;
use peekin_core::paths::validate_username;
use peekin_core::{PeekinConfig, PeekinPaths};
use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::time::Duration;

#[repr(C)]
pub struct PamHandle {
    _private: [u8; 0],
}

// Values from Linux-PAM's <security/_pam_types.h>.
pub const PAM_SUCCESS: c_int = 0;
pub const PAM_SYSTEM_ERR: c_int = 4;
pub const PAM_USER_UNKNOWN: c_int = 10;
pub const PAM_IGNORE: c_int = 25;
const PAM_SERVICE: c_int = 1;
const PAM_RHOST: c_int = 4;
const PAM_SILENT: c_int = 0x8000;
const PAM_ERROR_MSG: c_int = 3;
const PAM_TEXT_INFO: c_int = 4;

const LOG_ERR: c_int = 3;
const LOG_WARNING: c_int = 4;
const LOG_NOTICE: c_int = 5;
const LOG_INFO: c_int = 6;

#[link(name = "pam")]
extern "C" {
    fn pam_get_user(pamh: *mut PamHandle, user: *mut *const c_char, prompt: *const c_char)
        -> c_int;
    fn pam_get_item(pamh: *const PamHandle, item_type: c_int, item: *mut *const c_void) -> c_int;
    fn pam_syslog(pamh: *const PamHandle, priority: c_int, fmt: *const c_char, ...);
    fn pam_prompt(
        pamh: *mut PamHandle,
        style: c_int,
        response: *mut *mut c_char,
        fmt: *const c_char,
        ...
    ) -> c_int;
}

/// Grace on top of `[video] timeout` for model loading and camera start-up.
const COMPARE_GRACE: Duration = Duration::from_secs(5);
const DEFAULT_COMPARE: &str = "/usr/libexec/peekin/peekin-compare";
const SERVICE_USER: &str = "peekin";

fn c_string(s: &str) -> CString {
    CString::new(s.replace('\0', "?")).expect("NULs replaced")
}

struct Pam {
    pamh: *mut PamHandle,
    silent: bool,
}

impl Pam {
    fn log(&self, priority: c_int, msg: &str) {
        let msg = c_string(msg);
        // SAFETY: valid handle from libpam; "%s" consumes exactly one C string.
        unsafe { pam_syslog(self.pamh, priority, c"%s".as_ptr(), msg.as_ptr()) }
    }

    fn tell(&self, is_error: bool, msg: &str) -> bool {
        if self.silent {
            return false;
        }
        let msg = c_string(msg);
        let style = if is_error {
            PAM_ERROR_MSG
        } else {
            PAM_TEXT_INFO
        };
        // SAFETY: as above; a NULL response pointer makes libpam discard the reply.
        let rc = unsafe {
            pam_prompt(
                self.pamh,
                style,
                std::ptr::null_mut(),
                c"%s".as_ptr(),
                msg.as_ptr(),
            )
        };
        if rc != PAM_SUCCESS {
            self.log(
                LOG_ERR,
                "Failed to send message through the PAM conversation",
            );
        }
        rc == PAM_SUCCESS
    }

    fn user(&self) -> Result<String, c_int> {
        let mut ptr: *const c_char = std::ptr::null();
        // SAFETY: libpam writes a pointer it owns into `ptr`.
        let rc = unsafe { pam_get_user(self.pamh, &mut ptr, std::ptr::null()) };
        if rc != PAM_SUCCESS || ptr.is_null() {
            return Err(if rc == PAM_SUCCESS {
                PAM_USER_UNKNOWN
            } else {
                rc
            });
        }
        // SAFETY: non-null, NUL-terminated, valid for the handle's lifetime.
        Ok(unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned())
    }

    fn item(&self, item_type: c_int) -> Option<String> {
        let mut ptr: *const c_void = std::ptr::null();
        // SAFETY: string items are NUL-terminated and owned by libpam.
        let rc = unsafe { pam_get_item(self.pamh, item_type, &mut ptr) };
        (rc == PAM_SUCCESS && !ptr.is_null()).then(|| {
            unsafe { CStr::from_ptr(ptr.cast()) }
                .to_string_lossy()
                .into_owned()
        })
    }
}

/// Module options from the PAM config line: `config_dir=`, `data_dir=`, `compare=`.
#[derive(Debug, PartialEq, Eq)]
pub struct ModuleArgs {
    pub config_dir: PathBuf,
    pub data_dir: PathBuf,
    pub compare: PathBuf,
    pub state_dir: PathBuf,
    pub backlight_dir: PathBuf,
    pub activity_dir: PathBuf,
    pub unknown: Vec<String>,
}

impl ModuleArgs {
    pub fn parse<'a>(args: impl IntoIterator<Item = &'a str>) -> Self {
        let mut out = Self {
            config_dir: "/etc/peekin".into(),
            data_dir: "/usr/share/peekin".into(),
            compare: DEFAULT_COMPARE.into(),
            state_dir: lockout::STATE_DIR.into(),
            backlight_dir: backlight::BACKLIGHT_DIR.into(),
            activity_dir: activity::ACTIVITY_DIR.into(),
            unknown: Vec::new(),
        };
        for arg in args {
            match arg.split_once('=') {
                Some(("config_dir", v)) => out.config_dir = v.into(),
                Some(("data_dir", v)) => out.data_dir = v.into(),
                Some(("compare", v)) => out.compare = v.into(),
                Some(("state_dir", v)) => out.state_dir = v.into(),
                Some(("backlight_dir", v)) => out.backlight_dir = v.into(),
                Some(("activity_dir", v)) => out.activity_dir = v.into(),
                _ => out.unknown.push(arg.to_string()),
            }
        }
        out
    }
}

fn authenticate(pam: &Pam, args: ModuleArgs) -> c_int {
    for arg in &args.unknown {
        pam.log(
            LOG_WARNING,
            &format!("Ignoring unknown module option {arg:?}"),
        );
    }
    let paths = PeekinPaths::from_dirs(args.config_dir.clone(), args.data_dir.clone());
    let config = match PeekinConfig::load(&paths.config_file_path()) {
        Ok(c) => c,
        Err(e) => {
            pam.log(LOG_ERR, &format!("config.ini could not be read: {e}"));
            return PAM_SYSTEM_ERR;
        }
    };
    for warning in config.invalid_values() {
        pam.log(LOG_WARNING, &format!("config: {warning}"));
    }
    if !config.security_errors().is_empty() {
        pam.log(
            LOG_ERR,
            "Security-critical configuration is invalid; refusing face authentication",
        );
        return PamCode::AuthinfoUnavail as c_int;
    }

    let user = match pam.user() {
        Ok(u) => u,
        Err(rc) => {
            pam.log(LOG_ERR, "PAM gave no user name");
            return rc;
        }
    };
    if let Err(e) = validate_username(&user) {
        pam.log(LOG_ERR, &format!("Face login skipped: {e}"));
        return PAM_USER_UNKNOWN;
    }
    let session = Session {
        service: pam.item(PAM_SERVICE),
        rhost: pam.item(PAM_RHOST),
        user_has_session: account_uid(&user)
            .is_some_and(|uid| user_has_session(Path::new(LOGIND_USERS_DIR), uid)),
    };
    match check_enabled(&config, &paths, &user, Path::new(LID_STATE_DIR), &session) {
        Gate::Proceed => {}
        Gate::Skip(reason) => {
            pam.log(LOG_INFO, &format!("Face login skipped: {reason}"));
            return PamCode::AuthinfoUnavail as c_int;
        }
    }
    let workaround = config.workaround();
    if workaround != "off" {
        pam.log(
            LOG_NOTICE,
            &format!("workaround = {workaround} is not supported yet; scanning before the password prompt"),
        );
    }
    let Some((uid, gid, groups)) = account_identity(SERVICE_USER) else {
        pam.log(
            LOG_ERR,
            "Cannot resolve dedicated peekin worker account; \
             repair with: sudo /usr/libexec/peekin/system-setup install",
        );
        return PamCode::AuthinfoUnavail as c_int;
    };
    // Cheap preflight, so no face prompt is shown for a scan that can never start.
    if let Err(reason) = preflight(&config, &paths, &user, gid) {
        pam.log(LOG_ERR, &format!("Face login skipped: {reason}"));
        return PamCode::AuthinfoUnavail as c_int;
    }
    // The counter is created before the scan. One that cannot be read or written,
    // or is damaged, stops face login until it is repaired (fail closed); the
    // password is never blocked, PAM moves on to it.
    match check_lockout(
        &args.state_dir,
        &user,
        lockout::now(),
        config.max_failed_attempts(),
    ) {
        Lockout::Proceed => {}
        Lockout::Paused { failures, minutes } => {
            pam.log(
                LOG_NOTICE,
                &format!(
                    "Face login skipped: {failures} failed face attempts; paused for {minutes} min or until a password login"
                ),
            );
            record_activity(pam, &args, &user, &session, activity::Outcome::Paused, None);
            pam.tell(
                false,
                &tr_args(
                    "Face login paused after too many failed attempts ({minutes} min); \
                     use your password",
                    &[("minutes", &minutes)],
                ),
            );
            return PamCode::AuthinfoUnavail as c_int;
        }
        Lockout::Unusable(reason) => {
            pam.log(LOG_ERR, &format!("Face login skipped: {reason}"));
            pam.tell(
                true,
                &tr("Face authentication is unavailable (see the system log); use your password"),
            );
            return PamCode::AuthinfoUnavail as c_int;
        }
    }
    // The worker resolves the camera again and refuses a weaker mode, so a swapped camera fails closed.
    let camera = cameras::resolved_kind(&config.device_path());
    let mode = match ChallengeMode::for_config(config.movement_required(camera)) {
        Ok(mode) => mode,
        Err(error) => {
            // Fail closed: no fixed or weaker challenge without a fresh CSPRNG sequence.
            pam.log(
                LOG_ERR,
                &format!("Cannot generate a fresh face challenge: {error}"),
            );
            return PamCode::AuthinfoUnavail as c_int;
        }
    };
    match mode {
        // One prompt names the whole sequence: PAM cannot deliver per-step prompts mid-scan.
        ChallengeMode::Movement(_) => {
            if !pam.tell(false, &mode.prompt()) {
                pam.log(
                    LOG_INFO,
                    "Face challenge could not be shown; using password instead",
                );
                return PamCode::AuthinfoUnavail as c_int;
            }
        }
        ChallengeMode::Passive => {
            if config.detection_notice() {
                pam.tell(false, &mode.prompt());
            }
        }
    }

    let deadline =
        Duration::from_secs(config.attempt_secs(mode.is_movement()) as u64) + COMPARE_GRACE;
    // Raise the screen brightness for a colour camera in a dark scene until the scan ends.
    let mut boost = None;
    let mut on_low_light = || {
        if !config.brighten_screen() {
            return;
        }
        match backlight::raise(&args.backlight_dir) {
            Ok(raised) => boost = raised,
            // E.g. SELinux keeps the console and polkit domains away from sysfs.
            Err(error) => pam.log(LOG_INFO, &format!("Cannot brighten the screen: {error}")),
        }
    };
    let run = run_compare(
        &args.compare,
        &args.config_dir,
        &args.data_dir,
        WorkerIdentity {
            uid,
            gid,
            groups: &groups,
            user: &user,
        },
        mode,
        deadline,
        &mut on_low_light,
    );
    if let Some(mut boost) = boost {
        if let Err(error) = boost.restore() {
            pam.log(
                LOG_ERR,
                &format!("Cannot restore the screen brightness: {error}"),
            );
        }
    }
    for line in run.stderr.lines().filter(|l| !l.trim().is_empty()) {
        pam.log(LOG_INFO, &format!("peekin-compare: {line}"));
    }

    match run.end {
        RunEnd::Exited(end) => {
            update_lockout(pam, &args.state_dir, &user, end);
            if let Some(outcome) = crate::activity_outcome(end) {
                let model = crate::matched_model(&run.stdout);
                record_activity(pam, &args, &user, &session, outcome, model);
            }
            let decision = status_decision(end, &user, config.no_confirmation());
            let priority = match (decision.pam_code, end) {
                (PamCode::Success, _) => LOG_INFO,
                (_, ChildEnd::Exited(10)) => LOG_NOTICE,
                _ => LOG_ERR,
            };
            pam.log(priority, &decision.syslog);
            if let Some(msg) = &decision.conv_message {
                pam.tell(msg.is_error, &msg.text);
            }
            decision.pam_code as c_int
        }
        RunEnd::TimedOut { reaped } => {
            let mut msg = format!(
                "Not authenticated: peekin-compare did not finish within {}s and was killed",
                deadline.as_secs()
            );
            if !reaped {
                msg.push_str(
                    "; it did not exit after SIGKILL (camera driver hung?) and was abandoned",
                );
            }
            pam.log(LOG_ERR, &msg);
            record_activity(
                pam,
                &args,
                &user,
                &session,
                activity::Outcome::Unavailable,
                None,
            );
            pam.tell(true, &tr("Face recognition timed out; use your password"));
            PamCode::AuthErr as c_int
        }
        RunEnd::SpawnFailed(e) => {
            pam.log(
                LOG_ERR,
                &format!("Can't spawn {}: {e}", args.compare.display()),
            );
            PAM_SYSTEM_ERR
        }
        RunEnd::WaitFailed(e) => {
            pam.log(LOG_ERR, &format!("Failed to wait for peekin-compare: {e}"));
            PAM_SYSTEM_ERR
        }
    }
}

fn record_activity(
    pam: &Pam,
    args: &ModuleArgs,
    user: &str,
    session: &Session,
    outcome: activity::Outcome,
    model: Option<i64>,
) {
    let Some(uid) = account_uid(user) else { return };
    let entry = activity::Entry {
        time: lockout::now(),
        service: crate::face_service(session).map_or_else(
            || session.service.clone().unwrap_or_default(),
            |service| service.key().to_string(),
        ),
        outcome,
        model,
    };
    if let Err(error) = activity::record(&args.activity_dir, user, uid, &entry) {
        pam.log(
            LOG_ERR,
            &format!("Cannot record the attempt in the history: {error}"),
        );
    }
}

fn update_lockout(pam: &Pam, state_dir: &Path, user: &str, end: ChildEnd) {
    let result = match end {
        ChildEnd::Exited(0) => lockout::reset(state_dir, user),
        ChildEnd::Exited(code)
            if CompareError::from_exit_code(code).is_some_and(|e| e.counts_as_failed_attempt()) =>
        {
            lockout::record_failure(state_dir, user, lockout::now()).map(|record| {
                pam.log(
                    LOG_NOTICE,
                    &format!("Failed face attempt {} in a row", record.failures),
                );
            })
        }
        _ => Ok(()),
    };
    if let Err(error) = result {
        pam.log(
            LOG_ERR,
            &format!("Cannot update failed-attempt state: {error}"),
        );
    }
}

/// Any successful auth of the whole stack (e.g. the password) clears the face failure counter.
fn setcred(pam: &Pam, args: &ModuleArgs) {
    let Ok(user) = pam.user() else { return };
    if validate_username(&user).is_err() {
        return;
    }
    if let Err(error) = lockout::reset(&args.state_dir, &user) {
        pam.log(
            LOG_ERR,
            &format!("Cannot reset failed-attempt state: {error}"),
        );
    }
}

/// Non-blocking checks: the camera exists and the worker account can read the face model.
fn preflight(
    config: &PeekinConfig,
    paths: &PeekinPaths,
    user: &str,
    service_gid: libc::gid_t,
) -> Result<(), String> {
    let device = config.device_path();
    if !cameras::plausibly_present(&device) {
        return Err(if config.device_is_automatic() {
            "no camera found".into()
        } else {
            format!("configured camera {device} does not exist")
        });
    }
    models::check_service_access(paths.user_models_dir(), user, service_gid).map_err(|reason| {
        format!(
            "face model store refused: {reason}; \
             repair with: sudo /usr/libexec/peekin/system-setup install"
        )
    })
}

fn account_uid(user: &str) -> Option<libc::uid_t> {
    let name = CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; 16 * 1024];
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
    (rc == 0 && !result.is_null()).then_some(pwd.pw_uid)
}

fn account_identity(user: &str) -> Option<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>)> {
    let name = CString::new(user).ok()?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    if pwd.pw_name.is_null() || pwd.pw_shell.is_null() {
        return None;
    }
    if unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes() != user.as_bytes() {
        return None;
    }
    let shell = unsafe { CStr::from_ptr(pwd.pw_shell) }.to_string_lossy();
    if !(shell.ends_with("/nologin") || shell.ends_with("/false")) {
        return None;
    }
    let mut count = 0;
    unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, std::ptr::null_mut(), &mut count) };
    if !(1..=256).contains(&count) {
        return None;
    }
    let mut groups = vec![pwd.pw_gid; count.max(1) as usize];
    if unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut count) } < 0
    {
        return None;
    }
    groups.truncate(count as usize);
    peekin_core::process::validate_service_identity(pwd.pw_uid, pwd.pw_gid, &groups).ok()?;
    Some((pwd.pw_uid, pwd.pw_gid, groups))
}

/// # Safety
/// `argv` must hold `argc` valid C strings (guaranteed by libpam).
unsafe fn collect_args<'a>(argc: c_int, argv: *const *const c_char) -> Vec<&'a str> {
    if argv.is_null() {
        return Vec::new();
    }
    (0..argc.max(0) as usize)
        .filter_map(|i| {
            let p = *argv.add(i);
            (!p.is_null()).then(|| CStr::from_ptr(p).to_str().unwrap_or(""))
        })
        .collect()
}

/// # Safety
/// Called by libpam with a valid handle and argument vector.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let pam = Pam {
        pamh,
        silent: flags & PAM_SILENT != 0,
    };
    let args = ModuleArgs::parse(collect_args(argc, argv));
    // A panic must never unwind into sudo, GDM or other PAM hosts.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| authenticate(&pam, args)))
        .unwrap_or(PAM_SYSTEM_ERR)
}

macro_rules! ignored_hook {
    ($name:ident) => {
        #[no_mangle]
        pub extern "C" fn $name(
            _: *mut PamHandle,
            _: c_int,
            _: c_int,
            _: *const *const c_char,
        ) -> c_int {
            PAM_IGNORE
        }
    };
}

/// Called by the application after the whole auth stack succeeded.
///
/// # Safety
/// Called by libpam with a valid handle and argument vector.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    let pam = Pam {
        pamh,
        silent: flags & PAM_SILENT != 0,
    };
    let args = ModuleArgs::parse(collect_args(argc, argv));
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| setcred(&pam, &args)));
    PAM_IGNORE
}

ignored_hook!(pam_sm_acct_mgmt);
ignored_hook!(pam_sm_open_session);
ignored_hook!(pam_sm_close_session);
ignored_hook!(pam_sm_chauthtok);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn module_args_defaults_and_overrides() {
        let a = ModuleArgs::parse([]);
        assert_eq!(a.config_dir, PathBuf::from("/etc/peekin"));
        assert_eq!(a.compare, PathBuf::from(DEFAULT_COMPARE));
        let a = ModuleArgs::parse(["config_dir=/tmp/c", "compare=/opt/bin/cmp", "debug"]);
        assert_eq!(a.config_dir, PathBuf::from("/tmp/c"));
        assert_eq!(a.data_dir, PathBuf::from("/usr/share/peekin"));
        assert_eq!(a.compare, PathBuf::from("/opt/bin/cmp"));
        assert_eq!(a.unknown, vec!["debug".to_string()]);
    }

    #[test]
    fn c_strings_never_panic_on_interior_nul() {
        assert_eq!(c_string("a\0b").as_bytes(), b"a?b");
    }
}
