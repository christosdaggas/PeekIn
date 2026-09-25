//! Walk-away lock and away notifications for `peekin-session`. Settings live
//! in `~/.config/peekin/session.ini`. The helper only locks; unlocking goes
//! through PAM.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const MIN_AWAY_SECS: u32 = 30;
pub const MAX_AWAY_SECS: u32 = 600;
pub const DEFAULT_AWAY_SECS: u32 = 60;
/// Lock after this long without input and without a face in view.
pub const NO_FACE_GRACE: Duration = Duration::from_secs(10);

/// Camera for the walk-away lock. It authenticates no one, so any camera that
/// sees a face will do.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum CameraChoice {
    /// The face login camera (`[video] device_path`).
    #[default]
    SameAsLogin,
    AnyColour,
    AnyInfrared,
    Device(String),
}

impl CameraChoice {
    fn parse(value: &str) -> Option<Self> {
        match value.trim() {
            "same" => Some(Self::SameAsLogin),
            "colour" => Some(Self::AnyColour),
            "infrared" => Some(Self::AnyInfrared),
            path if crate::management::valid_device_path(path) && path.starts_with("/dev/") => {
                Some(Self::Device(path.to_string()))
            }
            _ => None,
        }
    }

    fn as_ini(&self) -> &str {
        match self {
            Self::SameAsLogin => "same",
            Self::AnyColour => "colour",
            Self::AnyInfrared => "infrared",
            Self::Device(path) => path,
        }
    }

    pub fn resolve(&self, cameras: &[crate::cameras::Camera]) -> AwayCamera {
        use crate::cameras::CameraKind;
        let first = |kinds: &[CameraKind]| {
            kinds
                .iter()
                .find_map(|k| cameras.iter().find(|c| c.kind == *k))
                .map_or(AwayCamera::NoneConnected, |c| {
                    AwayCamera::Device(c.path.clone())
                })
        };
        match self {
            Self::SameAsLogin => AwayCamera::LoginCamera,
            Self::AnyColour => first(&[CameraKind::Colour]),
            Self::AnyInfrared => {
                first(&[CameraKind::VerifiedInfrared, CameraKind::InfraredCandidate])
            }
            Self::Device(path) => AwayCamera::Device(PathBuf::from(path)),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AwayCamera {
    /// Use the face login camera setting.
    LoginCamera,
    Device(PathBuf),
    NoneConnected,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSettings {
    pub lock_when_away: bool,
    pub away_secs: u32,
    pub notify_failed_attempts: bool,
    pub camera: CameraChoice,
}

impl Default for SessionSettings {
    fn default() -> Self {
        Self {
            lock_when_away: false,
            away_secs: DEFAULT_AWAY_SECS,
            notify_failed_attempts: true,
            camera: CameraChoice::SameAsLogin,
        }
    }
}

fn parse_bool(value: &str) -> Option<bool> {
    match value.trim().to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

impl SessionSettings {
    pub fn path() -> Option<PathBuf> {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))?;
        Some(base.join("peekin/session.ini"))
    }

    /// Invalid values keep their defaults, so the lock stays off unless clearly on.
    pub fn parse(raw: &str) -> Self {
        let mut out = Self::default();
        for line in raw.lines() {
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            match key.trim() {
                "lock_when_away" => {
                    out.lock_when_away = parse_bool(value).unwrap_or(false);
                }
                "away_secs" => {
                    if let Some(v) = value
                        .trim()
                        .parse()
                        .ok()
                        .filter(|v| (MIN_AWAY_SECS..=MAX_AWAY_SECS).contains(v))
                    {
                        out.away_secs = v;
                    }
                }
                "notify_failed_attempts" => {
                    out.notify_failed_attempts = parse_bool(value).unwrap_or(true);
                }
                "camera" => {
                    if let Some(choice) = CameraChoice::parse(value) {
                        out.camera = choice;
                    }
                }
                _ => {}
            }
        }
        out
    }

    pub fn load(path: &Path) -> Self {
        std::fs::read_to_string(path)
            .map(|raw| Self::parse(&raw))
            .unwrap_or_default()
    }

    pub fn to_ini(&self) -> String {
        format!(
            "# PeekIn, this account only (the settings app writes this file).\n\
             [session]\n\
             lock_when_away = {}\n\
             away_secs = {}\n\
             notify_failed_attempts = {}\n\
             # same, colour, infrared or a device path such as /dev/v4l/by-id/...\n\
             camera = {}\n",
            self.lock_when_away,
            self.away_secs,
            self.notify_failed_attempts,
            self.camera.as_ini()
        )
    }

    /// Replace the file atomically (fsync, no temporary file left on
    /// failure), private to the user.
    pub fn save(&self, path: &Path) -> io::Result<()> {
        let dir = path
            .parent()
            .ok_or_else(|| io::Error::other("no parent directory"))?;
        crate::fsutil::create_dir_all_mode(dir, 0o700)?;
        crate::fsutil::atomic_write(path, self.to_ini().as_bytes(), Some(0o600))
    }
}

pub fn xdg_bases() -> Option<(PathBuf, PathBuf)> {
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let pick = |var: &str, fallback: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .or_else(|| home.as_ref().map(|h| h.join(fallback)))
    };
    Some((
        pick("XDG_CONFIG_HOME", ".config")?,
        pick("XDG_STATE_HOME", ".local/state")?,
    ))
}

/// Move this user's linux-hello session settings over unless PeekIn has its own.
pub fn migrate_legacy_files(config_base: &Path, state_base: &Path) -> io::Result<()> {
    for (base, name) in [(config_base, "session.ini"), (state_base, "notified")] {
        let (old, new) = (
            base.join("linux-hello").join(name),
            base.join("peekin").join(name),
        );
        if old.is_file() && !new.exists() {
            std::fs::create_dir_all(base.join("peekin"))?;
            std::fs::rename(&old, &new)?;
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    Face,
    NoFace,
    /// Too dark, busy or unavailable: assume present.
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Idle,
    Check,
    Lock,
}

/// Walk-away decision, fed every tick; asks for camera checks only while idle.
#[derive(Debug, Default)]
pub struct Presence {
    /// Since when checks have found no face.
    no_face_since: Option<Duration>,
}

impl Presence {
    /// `idle`: time since the last input; `inhibited`: something asks the desktop
    /// not to go idle; `seen`: result of the check asked for last tick.
    pub fn tick(
        &mut self,
        now: Duration,
        idle: Duration,
        inhibited: bool,
        away: Duration,
        seen: Option<Seen>,
    ) -> Action {
        if inhibited || idle < away {
            self.no_face_since = None;
            return Action::Idle;
        }
        match seen {
            Some(Seen::NoFace) => {
                let since = *self.no_face_since.get_or_insert(now);
                if now.saturating_sub(since) >= NO_FACE_GRACE {
                    self.no_face_since = None;
                    return Action::Lock;
                }
            }
            Some(Seen::Face | Seen::Unknown) => self.no_face_since = None,
            None => {}
        }
        Action::Check
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: fn(u64) -> Duration = Duration::from_secs;

    #[test]
    fn settings_default_off_and_round_trip() {
        let d = SessionSettings::default();
        assert!(!d.lock_when_away && d.notify_failed_attempts && d.away_secs == 60);
        let custom = SessionSettings {
            lock_when_away: true,
            away_secs: 120,
            notify_failed_attempts: false,
            camera: CameraChoice::Device("/dev/v4l/by-id/usb-cam-video-index0".into()),
        };
        assert_eq!(SessionSettings::parse(&custom.to_ini()), custom);
        let bad = SessionSettings::parse("lock_when_away = maybe\naway_secs = 5\n");
        assert_eq!(
            bad,
            SessionSettings::default(),
            "invalid values keep defaults"
        );
    }

    #[test]
    fn settings_are_saved_atomically_and_privately() {
        use std::os::unix::fs::PermissionsExt;
        let root = std::env::temp_dir().join(format!("peekin-session-save-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let path = root.join("peekin/session.ini");
        let on = SessionSettings {
            lock_when_away: true,
            ..SessionSettings::default()
        };
        on.save(&path).unwrap();
        assert_eq!(SessionSettings::load(&path), on);
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        // A save that cannot replace the file leaves it and nothing else behind.
        let blocked = root.join("blocked/session.ini");
        std::fs::create_dir_all(blocked.join("in-the-way")).unwrap();
        assert!(SessionSettings::default().save(&blocked).is_err());
        let left: Vec<_> = std::fs::read_dir(blocked.parent().unwrap())
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(left, ["session.ini"], "temporary file left behind");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn camera_choices_parse_and_resolve() {
        use crate::cameras::{Camera, CameraKind};
        let cam = |node: &str, kind| Camera {
            path: PathBuf::from(format!("/dev/v4l/by-path/{node}")),
            node: node.into(),
            name: "cam".into(),
            kind,
        };
        let both = [
            cam("video0", CameraKind::Colour),
            cam("video2", CameraKind::InfraredCandidate),
        ];
        let parse = |v: &str| SessionSettings::parse(&format!("camera = {v}\n")).camera;
        assert_eq!(parse("colour"), CameraChoice::AnyColour);
        assert_eq!(
            parse("../etc/passwd"),
            CameraChoice::SameAsLogin,
            "invalid keeps the default"
        );
        assert_eq!(
            parse("/etc/shadow").resolve(&both),
            AwayCamera::LoginCamera,
            "only /dev devices"
        );
        assert_eq!(
            CameraChoice::AnyInfrared.resolve(&both),
            AwayCamera::Device(PathBuf::from("/dev/v4l/by-path/video2"))
        );
        assert_eq!(
            CameraChoice::AnyColour.resolve(&both),
            AwayCamera::Device(PathBuf::from("/dev/v4l/by-path/video0"))
        );
        assert_eq!(
            CameraChoice::AnyInfrared.resolve(&both[..1]),
            AwayCamera::NoneConnected
        );
        assert_eq!(
            CameraChoice::SameAsLogin.resolve(&[]),
            AwayCamera::LoginCamera
        );
    }

    #[test]
    fn legacy_files_move_once_and_never_overwrite() {
        let root = std::env::temp_dir().join(format!("peekin-legacy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        let (config, state) = (root.join("config"), root.join("state"));
        std::fs::create_dir_all(config.join("linux-hello")).unwrap();
        std::fs::create_dir_all(state.join("linux-hello")).unwrap();
        std::fs::write(
            config.join("linux-hello/session.ini"),
            "lock_when_away = true\n",
        )
        .unwrap();
        std::fs::write(state.join("linux-hello/notified"), "5\n").unwrap();
        migrate_legacy_files(&config, &state).unwrap();
        assert!(SessionSettings::load(&config.join("peekin/session.ini")).lock_when_away);
        assert_eq!(
            std::fs::read_to_string(state.join("peekin/notified")).unwrap(),
            "5\n"
        );
        std::fs::create_dir_all(config.join("linux-hello")).unwrap();
        std::fs::write(
            config.join("linux-hello/session.ini"),
            "lock_when_away = false\n",
        )
        .unwrap();
        migrate_legacy_files(&config, &state).unwrap();
        assert!(
            SessionSettings::load(&config.join("peekin/session.ini")).lock_when_away,
            "kept"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn locks_only_after_idle_and_no_face_for_the_grace_time() {
        let away = S(60);
        let mut p = Presence::default();
        assert_eq!(p.tick(S(0), S(10), false, away, None), Action::Idle);
        assert_eq!(p.tick(S(60), S(60), false, away, None), Action::Check);
        assert_eq!(
            p.tick(S(63), S(63), false, away, Some(Seen::NoFace)),
            Action::Check
        );
        assert_eq!(
            p.tick(S(68), S(68), false, away, Some(Seen::NoFace)),
            Action::Check
        );
        assert_eq!(
            p.tick(S(73), S(73), false, away, Some(Seen::NoFace)),
            Action::Lock
        );
    }

    #[test]
    fn a_face_input_unknown_or_an_inhibitor_prevents_the_lock() {
        let away = S(60);
        let mut p = Presence::default();
        p.tick(S(60), S(60), false, away, None);
        p.tick(S(63), S(63), false, away, Some(Seen::NoFace));
        // Face seen: the grace starts again.
        assert_eq!(
            p.tick(S(70), S(70), false, away, Some(Seen::Face)),
            Action::Check
        );
        assert_eq!(
            p.tick(S(75), S(75), false, away, Some(Seen::NoFace)),
            Action::Check
        );
        assert_eq!(
            p.tick(S(80), S(80), false, away, Some(Seen::Unknown)),
            Action::Check
        );
        assert_eq!(
            p.tick(S(86), S(86), false, away, Some(Seen::NoFace)),
            Action::Check
        );
        // Input again: camera off.
        assert_eq!(
            p.tick(S(90), S(2), false, away, Some(Seen::NoFace)),
            Action::Idle
        );
        // A video player inhibiting idleness: never checks or locks.
        assert_eq!(
            p.tick(S(200), S(200), true, away, Some(Seen::NoFace)),
            Action::Idle
        );
    }
}
