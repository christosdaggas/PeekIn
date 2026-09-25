//! `pam_peekin.so`: decides whether face authentication runs for a PAM request.

pub mod pam;
pub mod run;
pub mod status;

pub use status::{AuthDecision, ChildEnd, PamCode};

use peekin_core::config::FaceService;
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

impl Session {
    fn is_remote(&self) -> bool {
        let local = |h: &str| h.is_empty() || matches!(h, "localhost" | "127.0.0.1" | "::1");
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
