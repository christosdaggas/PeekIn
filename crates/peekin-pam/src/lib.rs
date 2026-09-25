//! `pam_peekin.so`: decides whether face authentication runs for a PAM request.

pub mod pam;
pub mod run;
pub mod status;

pub use status::{AuthDecision, ChildEnd, PamCode};

use peekin_core::config::FaceService;
use peekin_core::lockout::{self, PauseCause};
use peekin_core::{PeekinConfig, PeekinPaths};
use std::path::Path;

pub const LID_STATE_DIR: &str = "/proc/acpi/button/lid";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gate {
    Proceed,
    /// Skip face authentication (PAM_AUTHINFO_UNAVAIL) with a log reason.
    Skip(&'static str),
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Session {
    pub service: Option<String>,
    pub rhost: Option<String>,
    /// A logind session exists, so a GDM request is a lock-screen unlock.
    pub user_has_session: bool,
}

/// `PAM_RHOST` values naming this machine: the loopback addresses (also as an
/// IPv4-mapped IPv6 address) and the usual names for them. Exact matches
/// only (names ignoring case); anything else counts as remote.
const LOCAL_HOSTS: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "127.0.0.1",
    "::1",
    "::ffff:127.0.0.1",
];

impl Session {
    fn is_remote(&self) -> bool {
        let local = |h: &str| h.is_empty() || LOCAL_HOSTS.iter().any(|l| h.eq_ignore_ascii_case(l));
        self.service.as_deref() == Some("sshd") || self.rhost.as_deref().is_some_and(|h| !local(h))
    }
}

/// Which `[services]` switch governs this PAM request, if any.
pub fn face_service(session: &Session) -> Option<FaceService> {
    match session.service.as_deref()? {
        "sudo" | "sudo-i" => Some(FaceService::Sudo),
        "gdm-password" if session.user_has_session => Some(FaceService::LockScreen),
        "gdm-password" => Some(FaceService::LoginScreen),
        "polkit-1" => Some(FaceService::Polkit),
        "login" => Some(FaceService::Console),
        _ => None,
    }
}

pub const LOGIND_USERS_DIR: &str = "/run/systemd/users";

pub fn user_has_session(users_dir: &Path, uid: libc::uid_t) -> bool {
    std::fs::read_to_string(users_dir.join(uid.to_string())).is_ok_and(|body| {
        body.lines().any(|line| {
            line.strip_prefix("SESSIONS=")
                .is_some_and(|ids| !ids.trim().is_empty())
        })
    })
}

fn env_set(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

fn ssh_env() -> bool {
    ["SSH_CONNECTION", "SSH_CLIENT", "SSH_TTY", "SSHD_OPTS"]
        .into_iter()
        .any(env_set)
}

fn lid_closed(base: &Path) -> bool {
    let Ok(entries) = std::fs::read_dir(base) else {
        return false;
    };
    entries.flatten().any(|entry| {
        std::fs::read_to_string(entry.path().join("state"))
            .is_ok_and(|body| body.contains("closed"))
    })
}

/// Order: disabled, ssh, lid, model file. `username` must already be validated.
pub fn check_enabled(
    config: &PeekinConfig,
    paths: &PeekinPaths,
    username: &str,
    lid_base: &Path,
    session: &Session,
) -> Gate {
    // Only these services, each behind its own [services] switch, may turn a match into success.
    match face_service(session) {
        None => return Gate::Skip("PAM service is not enabled for face authentication"),
        Some(service) if !config.service_enabled(service) => {
            return Gate::Skip("face authentication is turned off for this service in [services]")
        }
        Some(_) => {}
    }
    if config.disabled() {
        return Gate::Skip("PeekIn is disabled");
    }
    if config.abort_if_ssh() && (session.is_remote() || ssh_env()) {
        return Gate::Skip("SSH session detected");
    }
    if config.abort_if_lid_closed() && lid_closed(lid_base) {
        return Gate::Skip("closed lid detected");
    }
    match paths.user_model_path(username) {
        Ok(p) if p.is_file() => Gate::Proceed,
        Ok(_) => Gate::Skip("no face model for user"),
        Err(_) => Gate::Skip("invalid username"),
    }
}

/// What the failed-attempt counter allows, checked before the face prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lockout {
    Proceed,
    /// Paused after too many rejected faces, or too many scans without a face
    /// after a head-turn challenge, for `minutes` more (at least 1).
    Paused {
        cause: PauseCause,
        minutes: u64,
    },
    /// The counter cannot be read or written, or is damaged; the reason is for the log.
    Unusable(String),
}

/// A counter that cannot be read or written, or is damaged, stops face login
/// until it is repaired (fail closed): without a trustworthy count that can
/// grow, the limit cannot be enforced. The counter is created before the scan,
/// so a failure is known to be recordable. The password is unaffected; PAM
/// moves on to it. `username` must already be validated.
pub fn check_lockout(state_dir: &Path, username: &str, now: u64, max_failures: u32) -> Lockout {
    // 0 turns the limit off; the counter then plays no part.
    if max_failures == 0 {
        return Lockout::Proceed;
    }
    match lockout::load_or_create(state_dir, username) {
        Ok(record) => match record.pause(now, max_failures) {
            Some(pause) => Lockout::Paused {
                cause: pause.cause,
                minutes: pause.until.saturating_sub(now).div_ceil(60).max(1),
            },
            None => Lockout::Proceed,
        },
        Err(error) => Lockout::Unusable(format!(
            "cannot read or write the failed-attempt counter: {error}; \
             repair with: sudo /usr/libexec/peekin/system-setup install; \
             a password login clears a damaged counter"
        )),
    }
}

std::thread_local! {
    static LAST_PANIC: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Runs `f` so that a panic neither unwinds into the PAM host (sudo, GDM)
/// nor prints to its stderr: the message and location are returned for the
/// module's log instead. The hook belongs to this module's own Rust runtime,
/// never the host's, and is installed once.
pub fn run_guarded<T>(f: impl FnOnce() -> T) -> Result<T, String> {
    static QUIET: std::sync::Once = std::sync::Once::new();
    QUIET.call_once(|| {
        std::panic::set_hook(Box::new(|info| {
            LAST_PANIC.with(|last| *last.borrow_mut() = Some(info.to_string()));
        }));
    });
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(f)).map_err(|_| {
        LAST_PANIC
            .with(|last| last.borrow_mut().take())
            .unwrap_or_else(|| "unknown panic".into())
    })
}

/// Turns the worker's `challenge-stage N` reports into the instruction for
/// each step, strictly in order: the next turn is shown only after the worker
/// saw the previous step performed. Directions come from PAM's own copy of
/// the sequence, never from the worker.
#[derive(Debug)]
pub struct StagePrompts {
    order: Option<peekin_core::compare::ChallengeOrder>,
    /// Number of the last stage shown; the neutral stage (1) is the prompt
    /// before the scan.
    last: u8,
}

impl StagePrompts {
    pub fn new(mode: peekin_core::compare::ChallengeMode) -> Self {
        use peekin_core::compare::ChallengeMode;
        Self {
            order: match mode {
                ChallengeMode::Movement(order) => Some(order),
                ChallengeMode::Passive => None,
            },
            last: 1,
        }
    }

    /// The instruction for stage `number`, or why the report breaks the
    /// protocol (the scan must then stop).
    pub fn next(&mut self, number: u8) -> Result<String, String> {
        use peekin_core::compare::ChallengeStage;
        let Some(order) = self.order else {
            return Err(format!(
                "the worker reported head-turn stage {number} without the challenge"
            ));
        };
        let stage = ChallengeStage::announced(number)
            .filter(|_| Some(number) == self.last.checked_add(1))
            .ok_or_else(|| {
                format!(
                    "the worker reported head-turn stage {number} after stage {}",
                    self.last
                )
            })?;
        self.last = number;
        Ok(stage.instruction(order))
    }
}

/// What a finished scan does to the failed-attempt counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CounterUpdate {
    /// Face login succeeded: both streaks end.
    Reset,
    /// A face was examined and rejected.
    Failure,
    /// No face at all although a head-turn challenge was asked for: someone
    /// may be hiding a recording whose turns do not match, to try again for
    /// free. Counted against its own, slower limit.
    NoFace,
    /// Camera problems, darkness, or no face without a challenge.
    Unchanged,
}

pub fn counter_update(end: status::ChildEnd, movement: bool) -> CounterUpdate {
    match end {
        status::ChildEnd::Exited(0) => CounterUpdate::Reset,
        status::ChildEnd::Exited(code) => match CompareError::from_exit_code(code) {
            Some(error) if error.counts_as_failed_attempt() => CounterUpdate::Failure,
            Some(CompareError::NoFaceSeen) if movement => CounterUpdate::NoFace,
            _ => CounterUpdate::Unchanged,
        },
        status::ChildEnd::Signaled { .. } => CounterUpdate::Unchanged,
    }
}

/// Exit codes of `peekin-compare`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompareError {
    NoFaceModel = 10,
    TimeoutReached = 11,
    Abort = 12,
    TooDark = 13,
    InvalidDevice = 14,
    Rubberstamp = 15,
    ChallengeFailed = 16,
    NoFaceSeen = 17,
}

impl CompareError {
    /// A face was examined and rejected; camera problems, darkness and no face do not count.
    pub fn counts_as_failed_attempt(&self) -> bool {
        matches!(self, Self::TimeoutReached | Self::ChallengeFailed)
    }

    pub fn from_exit_code(code: u8) -> Option<Self> {
        match code {
            10 => Some(Self::NoFaceModel),
            11 => Some(Self::TimeoutReached),
            12 => Some(Self::Abort),
            13 => Some(Self::TooDark),
            14 => Some(Self::InvalidDevice),
            15 => Some(Self::Rubberstamp),
            16 => Some(Self::ChallengeFailed),
            17 => Some(Self::NoFaceSeen),
            _ => None,
        }
    }

    pub fn log_message(&self) -> &'static str {
        match self {
            Self::NoFaceModel => "Not authenticated: no face model enrolled",
            Self::TimeoutReached => "Not authenticated: no matching face before the time limit",
            Self::Abort => "Not authenticated: the recognition worker stopped",
            Self::TooDark => "Not authenticated: the camera image was too dark",
            Self::InvalidDevice => "Not authenticated: the camera could not be opened",
            Self::Rubberstamp => "Not authenticated: rubber stamps are not supported",
            Self::ChallengeFailed => "Not authenticated: the head movement did not match",
            Self::NoFaceSeen => "Not authenticated: nobody in front of the camera",
        }
    }
}

/// `None` when there is nothing to record (no face model enrolled).
pub fn activity_outcome(end: status::ChildEnd) -> Option<peekin_core::activity::Outcome> {
    use peekin_core::activity::Outcome;
    Some(match end {
        status::ChildEnd::Exited(0) => Outcome::Success,
        status::ChildEnd::Exited(code) => match CompareError::from_exit_code(code) {
            Some(CompareError::NoFaceModel) => return None,
            Some(CompareError::TimeoutReached) => Outcome::Rejected,
            Some(CompareError::ChallengeFailed) => Outcome::ChallengeFailed,
            Some(CompareError::NoFaceSeen) => Outcome::NoFace,
            _ => Outcome::Unavailable,
        },
        status::ChildEnd::Signaled { .. } => Outcome::Unavailable,
    })
}

pub fn matched_model(stdout: &str) -> Option<i64> {
    stdout
        .lines()
        .find_map(|l| l.strip_prefix(peekin_core::lowlight::MATCHED_MODEL_PREFIX))
        .and_then(|id| id.trim().parse().ok())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn scan_results_map_to_history_entries() {
        use peekin_core::activity::Outcome;
        use status::ChildEnd;
        assert_eq!(
            activity_outcome(ChildEnd::Exited(0)),
            Some(Outcome::Success)
        );
        assert_eq!(
            activity_outcome(ChildEnd::Exited(11)),
            Some(Outcome::Rejected)
        );
        assert_eq!(
            activity_outcome(ChildEnd::Exited(16)),
            Some(Outcome::ChallengeFailed)
        );
        assert_eq!(
            activity_outcome(ChildEnd::Exited(17)),
            Some(Outcome::NoFace)
        );
        assert_eq!(
            activity_outcome(ChildEnd::Exited(14)),
            Some(Outcome::Unavailable)
        );
        assert_eq!(activity_outcome(ChildEnd::Exited(10)), None);
        assert_eq!(
            activity_outcome(ChildEnd::Signaled {
                signal: 9,
                name: "SIGKILL"
            }),
            Some(Outcome::Unavailable)
        );
        assert_eq!(matched_model("low-light\nmatched-model 7\n"), Some(7));
        assert_eq!(matched_model("matched-model x\n"), None);
        assert_eq!(matched_model(""), None);
    }

    fn setup(name: &str) -> (std::path::PathBuf, PeekinPaths) {
        let dir = std::env::temp_dir().join(format!("peekin-gate-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("etc/models")).unwrap();
        let paths = PeekinPaths::from_dirs(dir.join("etc"), dir.join("data"));
        (dir, paths)
    }

    fn cfg(body: &str) -> PeekinConfig {
        PeekinConfig::parse(body, "<test>".into()).unwrap()
    }

    fn local() -> Session {
        Session {
            service: Some("sudo".into()),
            rhost: None,
            user_has_session: false,
        }
    }

    #[test]
    fn shared_authselect_profile_never_authenticates_other_services() {
        let (dir, paths) = setup("service-allowlist");
        std::fs::write(paths.user_model_path("alice").unwrap(), "[]").unwrap();
        for service in [
            None,
            Some("login"),
            Some("sshd"),
            Some("su"),
            Some("polkit-1"),
        ] {
            assert!(matches!(
                check_enabled(
                    &PeekinConfig::empty(),
                    &paths,
                    "alice",
                    Path::new("/nonexistent"),
                    &Session {
                        service: service.map(str::to_owned),
                        rhost: None,
                        user_has_session: false,
                    }
                ),
                Gate::Skip(_)
            ));
        }
        assert_eq!(
            check_enabled(
                &PeekinConfig::empty(),
                &paths,
                "alice",
                Path::new("/nonexistent"),
                &local()
            ),
            Gate::Proceed
        );
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn each_place_follows_its_own_switch() {
        let (dir, paths) = setup("services");
        std::fs::write(paths.user_model_path("alice").unwrap(), "[]").unwrap();
        let gate = |config: &PeekinConfig, service: &str, has_session: bool| {
            check_enabled(
                config,
                &paths,
                "alice",
                Path::new("/nonexistent"),
                &Session {
                    service: Some(service.into()),
                    rhost: None,
                    user_has_session: has_session,
                },
            )
        };
        let defaults = PeekinConfig::empty();
        assert_eq!(gate(&defaults, "sudo-i", false), Gate::Proceed);
        assert_eq!(gate(&defaults, "gdm-password", false), Gate::Proceed);
        assert!(matches!(gate(&defaults, "polkit-1", false), Gate::Skip(_)));
        assert!(matches!(gate(&defaults, "login", false), Gate::Skip(_)));
        let custom = cfg("[services]\nlogin_screen = false\nconsole = true\npolkit = true\n");
        assert!(matches!(
            gate(&custom, "gdm-password", false),
            Gate::Skip(_)
        ));
        assert_eq!(
            gate(&custom, "gdm-password", true),
            Gate::Proceed,
            "lock screen"
        );
        assert_eq!(gate(&custom, "login", false), Gate::Proceed);
        assert_eq!(gate(&custom, "polkit-1", false), Gate::Proceed);
        assert!(matches!(gate(&custom, "sshd", false), Gate::Skip(_)));
        assert!(matches!(gate(&custom, "su", false), Gate::Skip(_)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn logind_sessions_distinguish_unlock_from_login() {
        let (dir, _) = setup("logind");
        let users = dir.join("users");
        fs::create_dir_all(&users).unwrap();
        fs::write(
            users.join("1000"),
            "NAME=alice\nSTATE=active\nSESSIONS=2 5\n",
        )
        .unwrap();
        fs::write(users.join("1001"), "NAME=bob\nSTATE=lingering\nSESSIONS=\n").unwrap();
        assert!(user_has_session(&users, 1000));
        assert!(!user_has_session(&users, 1001));
        assert!(!user_has_session(&users, 1002));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn disabled_short_circuits() {
        let (dir, p) = setup("disabled");
        let gate = check_enabled(
            &cfg("[core]\ndisabled = true\n"),
            &p,
            "alice",
            Path::new("/nonexistent"),
            &local(),
        );
        assert_eq!(gate, Gate::Skip("PeekIn is disabled"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_model_skips_and_present_model_proceeds() {
        let (dir, p) = setup("model");
        let none = Path::new("/nonexistent");
        assert_eq!(
            check_enabled(&PeekinConfig::empty(), &p, "alice", none, &local()),
            Gate::Skip("no face model for user")
        );
        fs::write(p.user_model_path("alice").unwrap(), "[]").unwrap();
        assert_eq!(
            check_enabled(&PeekinConfig::empty(), &p, "alice", none, &local()),
            Gate::Proceed
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn lid_closed_skips() {
        let (dir, p) = setup("lid");
        fs::write(p.user_model_path("alice").unwrap(), "[]").unwrap();
        let lid = dir.join("lid");
        fs::create_dir_all(lid.join("LID0")).unwrap();
        fs::write(lid.join("LID0/state"), "state:      closed\n").unwrap();
        assert_eq!(
            check_enabled(&PeekinConfig::empty(), &p, "alice", &lid, &local()),
            Gate::Skip("closed lid detected")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remote_sessions_detected_from_pam_items() {
        let (dir, p) = setup("remote");
        fs::write(p.user_model_path("alice").unwrap(), "[]").unwrap();
        let none = Path::new("/nonexistent");
        let cases = [
            (
                Session {
                    service: Some("sshd".into()),
                    rhost: None,
                    user_has_session: false,
                },
                true,
            ),
            (
                Session {
                    service: Some("sudo".into()),
                    rhost: Some("203.0.113.9".into()),
                    user_has_session: false,
                },
                true,
            ),
            (
                Session {
                    service: Some("gdm-password".into()),
                    rhost: Some("localhost".into()),
                    user_has_session: false,
                },
                false,
            ),
            (
                Session {
                    service: Some("sudo".into()),
                    rhost: Some(String::new()),
                    user_has_session: false,
                },
                false,
            ),
        ];
        for (session, remote) in cases {
            let gate = check_enabled(&PeekinConfig::empty(), &p, "alice", none, &session);
            let expected = if session.service.as_deref() == Some("sshd") {
                Gate::Skip("PAM service is not enabled for face authentication")
            } else if remote {
                Gate::Skip("SSH session detected")
            } else {
                Gate::Proceed
            };
            assert_eq!(gate, expected, "{session:?}");
        }
        let remote = Session {
            service: Some("sshd".into()),
            rhost: None,
            user_has_session: false,
        };
        let off = cfg("[core]\nabort_if_ssh = false\n");
        assert_eq!(
            check_enabled(&off, &p, "alice", none, &remote),
            Gate::Skip("PAM service is not enabled for face authentication")
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn loopback_names_and_addresses_are_local() {
        let remote = |rhost: &str| {
            Session {
                service: Some("sudo".into()),
                rhost: Some(rhost.into()),
                user_has_session: false,
            }
            .is_remote()
        };
        for local in [
            "",
            "localhost",
            "127.0.0.1",
            "::1",
            "::ffff:127.0.0.1",
            "localhost.localdomain",
            "ip6-localhost",
            "LocalHost",
            "::FFFF:127.0.0.1",
        ] {
            assert!(!remote(local), "{local:?}");
        }
        for far in [
            "203.0.113.9",
            "::ffff:203.0.113.9",
            "localhost.example.com",
            "ip6-localhost.example.com",
            "my-localhost",
            "::ffff:127.0.0.1.example.com",
        ] {
            assert!(remote(far), "{far:?}");
        }
    }

    #[test]
    fn unreadable_or_damaged_counters_stop_face_login() {
        let (dir, _) = setup("lockout");
        let state = dir.join("failures");
        let now = 1_000_000;
        assert_eq!(check_lockout(&state, "alice", now, 5), Lockout::Proceed);
        for _ in 0..5 {
            lockout::record_failure(&state, "alice", now - 60).unwrap();
        }
        assert_eq!(check_lockout(&state, "alice", now, 6), Lockout::Proceed);
        assert_eq!(
            check_lockout(&state, "alice", now, 5),
            Lockout::Paused {
                cause: PauseCause::FailedFaces(5),
                minutes: 14
            }
        );
        // Scans without a face after a head-turn challenge pause on their own.
        let (dir2, _) = setup("lockout-no-face");
        let state2 = dir2.join("failures");
        for i in 0..lockout::MAX_NO_FACE_SCANS {
            assert_eq!(
                check_lockout(&state2, "carol", now, 5),
                Lockout::Proceed,
                "{i}"
            );
            lockout::record_no_face(&state2, "carol", now - 120).unwrap();
        }
        assert_eq!(
            check_lockout(&state2, "carol", now, 5),
            Lockout::Paused {
                cause: PauseCause::NoFace(lockout::MAX_NO_FACE_SCANS),
                minutes: 13
            }
        );
        assert_eq!(check_lockout(&state2, "carol", now, 0), Lockout::Proceed);
        let _ = fs::remove_dir_all(&dir2);
        // Damaged content, or a directory where the counter belongs.
        fs::write(state.join("alice"), "garbage\n").unwrap();
        fs::create_dir(state.join("bob")).unwrap();
        for user in ["alice", "bob"] {
            match check_lockout(&state, user, now, 5) {
                Lockout::Unusable(reason) => assert!(
                    reason.starts_with("cannot read or write the failed-attempt counter: ")
                        && reason.ends_with(
                            "; repair with: sudo /usr/libexec/peekin/system-setup install; \
                             a password login clears a damaged counter"
                        ),
                    "{reason}"
                ),
                other => panic!("{user}: {other:?}"),
            }
        }
        // With the limit off the counter plays no part.
        assert_eq!(check_lockout(&state, "alice", now, 0), Lockout::Proceed);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn counters_that_cannot_be_written_stop_face_login() {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        let (dir, _) = setup("unwritable");
        let now = 1_000_000;
        // Places where a failure could never be recorded.
        let open = dir.join("open");
        fs::create_dir(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let dangling = dir.join("dangling");
        std::os::unix::fs::symlink(dir.join("nowhere"), &dangling).unwrap();
        let mut unusable = vec![open, dangling];
        // Root ignores directory permissions; nobody else can write here.
        if unsafe { libc::geteuid() } != 0 {
            let read_only = dir.join("read-only");
            fs::DirBuilder::new()
                .mode(0o500)
                .create(&read_only)
                .unwrap();
            unusable.push(read_only);
        }
        for place in &unusable {
            match check_lockout(place, "alice", now, 5) {
                Lockout::Unusable(_) => {}
                other => panic!("{}: {other:?}", place.display()),
            }
        }
        // Elsewhere the counter is created before the scan, with no failures.
        let state = dir.join("failures");
        assert_eq!(check_lockout(&state, "alice", now, 5), Lockout::Proceed);
        assert_eq!(fs::metadata(state.join("alice")).unwrap().len(), 0);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_movement_scans_without_a_face_count_as_no_face() {
        use status::ChildEnd;
        let update = |code, movement| counter_update(ChildEnd::Exited(code), movement);
        assert_eq!(update(0, true), CounterUpdate::Reset);
        assert_eq!(update(0, false), CounterUpdate::Reset);
        for movement in [true, false] {
            assert_eq!(update(11, movement), CounterUpdate::Failure);
            assert_eq!(update(16, movement), CounterUpdate::Failure);
            for code in [10, 12, 13, 14, 15, 99] {
                assert_eq!(update(code, movement), CounterUpdate::Unchanged, "{code}");
            }
        }
        // No face after a head-turn challenge: an attacker hiding a recording
        // whose turns do not match. Without the challenge nothing was shown.
        assert_eq!(update(17, true), CounterUpdate::NoFace);
        assert_eq!(update(17, false), CounterUpdate::Unchanged);
        assert_eq!(
            counter_update(
                ChildEnd::Signaled {
                    signal: 9,
                    name: "SIGKILL"
                },
                true
            ),
            CounterUpdate::Unchanged
        );
    }

    #[test]
    fn head_turns_are_shown_one_by_one_in_order_only() {
        use peekin_core::compare::{ChallengeMode, ChallengeOrder, Turn};
        let order = ChallengeOrder::from_turns([Turn::Right, Turn::Left, Turn::Right]);
        let mut prompts = StagePrompts::new(ChallengeMode::Movement(order));
        let shown: Vec<String> = (2..=7).map(|n| prompts.next(n).unwrap()).collect();
        assert_eq!(
            shown,
            [
                "Turn your head RIGHT",
                "Look straight at the camera again",
                "Turn your head LEFT",
                "Look straight at the camera again",
                "Turn your head RIGHT",
                "Look straight at the camera again",
            ]
        );
        // Nothing past the last stage, and nothing twice.
        assert!(prompts.next(8).is_err());
        assert!(prompts.next(7).is_err());
        // Skipping ahead, going back or the neutral stage is refused, so a
        // later turn is never shown early.
        for bad in [[3, 0], [4, 0], [1, 0], [0, 0], [2, 2], [2, 4], [2, 1]] {
            let mut prompts = StagePrompts::new(ChallengeMode::Movement(order));
            let first = prompts.next(bad[0]);
            let result = if bad[0] == 2 {
                prompts.next(bad[1])
            } else {
                first
            };
            assert!(result.is_err(), "{bad:?}");
        }
        // No stages at all without the challenge.
        assert!(StagePrompts::new(ChallengeMode::Passive).next(2).is_err());
    }

    #[test]
    fn exit_codes_match_main_hh() {
        assert_eq!(
            CompareError::from_exit_code(10),
            Some(CompareError::NoFaceModel)
        );
        assert_eq!(
            CompareError::from_exit_code(11),
            Some(CompareError::TimeoutReached)
        );
        assert_eq!(
            CompareError::from_exit_code(15),
            Some(CompareError::Rubberstamp)
        );
        assert_eq!(
            CompareError::from_exit_code(16),
            Some(CompareError::ChallengeFailed)
        );
        assert_eq!(
            CompareError::from_exit_code(17),
            Some(CompareError::NoFaceSeen)
        );
        assert_eq!(CompareError::from_exit_code(0), None);
        assert_eq!(CompareError::from_exit_code(99), None);
    }
}
