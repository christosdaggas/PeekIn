//! `config.ini` access. Keys and sections are case-insensitive, indented lines
//! continue a value, and unparsable values fall back to the default (listed by
//! `invalid_values()`).

use crate::cameras::CameraKind;
use ini::{Ini, ParseOption};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config {0}: {1}")]
    Io(String, #[source] std::io::Error),
    #[error("cannot parse config {0}: {1}")]
    Parse(String, String),
}

/// OpenCV's published SFace operating point for cosine similarity.
pub const DEFAULT_MIN_SIMILARITY: f64 = 0.363;
pub const MIN_SIMILARITY: f64 = 0.2;
pub const MAX_SIMILARITY: f64 = 1.0;
/// Scan time (seconds to look for the user's face): default and upper bound.
pub const DEFAULT_TIMEOUT_SECS: i64 = 3;
pub const MAX_AUTH_TIMEOUT_SECS: i64 = 10;
/// Scan time the default config.ini of Linux Hello before 1.3.0.
pub const LEGACY_DEFAULT_TIMEOUT_SECS: i64 = 10;
/// Comment that old default config.ini carried next to its timeout.
const LEGACY_TIMEOUT_COMMENT: &str = "10 s is the new-install default";
/// Extra seconds for the head-movement challenge after the face is recognised.
pub const CHALLENGE_SECS: i64 = 8;
pub const DEFAULT_MAX_FAILED_ATTEMPTS: i64 = 5;
pub const MAX_FAILED_ATTEMPTS_LIMIT: i64 = 100;

/// Where face authentication may be used (`[services]`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceService {
    Sudo,
    /// The GDM login screen.
    LoginScreen,
    /// The GNOME lock screen.
    LockScreen,
    /// Administrator dialogs and `pkexec` (PAM service `polkit-1`).
    Polkit,
    /// Text console login (PAM service `login`).
    Console,
}

impl FaceService {
    pub const ALL: [FaceService; 5] = [
        Self::Sudo,
        Self::LoginScreen,
        Self::LockScreen,
        Self::Polkit,
        Self::Console,
    ];

    pub fn key(self) -> &'static str {
        match self {
            Self::Sudo => "sudo",
            Self::LoginScreen => "login_screen",
            Self::LockScreen => "lock_screen",
            Self::Polkit => "polkit",
            Self::Console => "console",
        }
    }

    /// sudo, login and lock screen were always enabled; newer places are opt-in.
    pub fn enabled_by_default(self) -> bool {
        matches!(self, Self::Sudo | Self::LoginScreen | Self::LockScreen)
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Bool,
    Int,
    Float,
    /// TPM2 PCR numbers joined by `+` (see [`parse_pcrs`]); empty is off.
    Pcrs,
}

/// Highest PCR index of a TPM 2.0 PC client (24 PCRs).
pub const MAX_PCR: u8 = 23;

/// `[core] tpm2_pcrs`: PCR numbers 0 to [`MAX_PCR`] joined by `+` or `,`,
/// each at most once, e.g. `7` or `7+14`; empty means no binding. Returned
/// sorted. `None` for anything else, so nothing but digits and `+` ever
/// reaches the `systemd-creds` command line.
pub fn parse_pcrs(value: &str) -> Option<Vec<u8>> {
    let value = value.trim();
    if value.is_empty() {
        return Some(Vec::new());
    }
    let mut out = Vec::new();
    for part in value.split(['+', ',']) {
        let part = part.trim();
        if part.is_empty() || part.len() > 2 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let pcr: u8 = part.parse().ok()?;
        if pcr > MAX_PCR || out.contains(&pcr) {
            return None;
        }
        out.push(pcr);
    }
    out.sort_unstable();
    Some(out)
}

const KNOWN_KEYS: &[(&str, &str, Kind)] = &[
    ("core", "detection_notice", Kind::Bool),
    ("core", "timeout_notice", Kind::Bool),
    ("core", "no_confirmation", Kind::Bool),
    ("core", "suppress_unknown", Kind::Bool),
    ("core", "abort_if_ssh", Kind::Bool),
    ("core", "abort_if_lid_closed", Kind::Bool),
    ("core", "disabled", Kind::Bool),
    ("core", "movement_challenge", Kind::Bool),
    ("core", "require_movement_without_ir", Kind::Bool),
    ("core", "max_failed_attempts", Kind::Int),
    ("core", "tpm2_pcrs", Kind::Pcrs),
    ("services", "sudo", Kind::Bool),
    ("services", "login_screen", Kind::Bool),
    ("services", "lock_screen", Kind::Bool),
    ("services", "polkit", Kind::Bool),
    ("services", "console", Kind::Bool),
    ("core", "use_cnn", Kind::Bool),
    ("video", "certainty", Kind::Float),
    ("video", "min_similarity", Kind::Float),
    ("video", "personal_threshold", Kind::Bool),
    ("video", "timeout", Kind::Int),
    ("video", "warn_no_device", Kind::Bool),
    ("video", "ir_only", Kind::Bool),
    ("video", "max_height", Kind::Float),
    ("video", "frame_width", Kind::Int),
    ("video", "frame_height", Kind::Int),
    ("video", "dark_threshold", Kind::Float),
    ("video", "brighten_screen", Kind::Bool),
    ("video", "force_mjpeg", Kind::Bool),
    ("video", "exposure", Kind::Int),
    ("video", "device_fps", Kind::Int),
    ("video", "rotate", Kind::Int),
    ("snapshots", "save_failed", Kind::Bool),
    ("snapshots", "save_successful", Kind::Bool),
    ("snapshots", "keep", Kind::Int),
    ("rubberstamps", "enabled", Kind::Bool),
    ("debug", "end_report", Kind::Bool),
    ("debug", "verbose_stamps", Kind::Bool),
    ("debug", "gtk_stdout", Kind::Bool),
];

/// Section a known option belongs to, e.g. `ir_only` -> `video`.
pub fn known_section(key: &str) -> Option<&'static str> {
    KNOWN_KEYS
        .iter()
        .chain(&[
            ("core", "workaround", Kind::Bool),
            ("video", "device_path", Kind::Bool),
            ("video", "recording_plugin", Kind::Bool),
            ("video", "device_format", Kind::Bool),
        ])
        .find(|(_, k, _)| k.eq_ignore_ascii_case(key))
        .map(|(section, _, _)| *section)
}

/// `none`, `auto` and empty all mean the preferred camera.
pub fn is_automatic_device(value: &str) -> bool {
    matches!(value.trim(), "" | "none" | "auto")
}

fn parse_bool(v: &str) -> Option<bool> {
    match v.to_ascii_lowercase().as_str() {
        "true" | "yes" | "on" | "1" => Some(true),
        "false" | "no" | "off" | "0" => Some(false),
        _ => None,
    }
}

/// [`PeekinConfig::movement_required`] for callers without a parsed config.
pub fn movement_required(
    movement_challenge: bool,
    require_movement_without_ir: bool,
    kind: Option<CameraKind>,
) -> bool {
    movement_challenge
        || (require_movement_without_ir && kind != Some(CameraKind::VerifiedInfrared))
}

#[derive(Debug, Clone)]
pub struct PeekinConfig {
    ini: Ini,
    path: String,
    /// The file still has the Linux Hello pre-1.3.0 scan time comment.
    legacy_timeout_comment: bool,
}

impl PeekinConfig {
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let s = path.to_string_lossy().to_string();
        let raw = std::fs::read_to_string(path).map_err(|io| ConfigError::Io(s.clone(), io))?;
        Self::parse(&raw, s)
    }

    pub fn parse(raw: &str, path: String) -> Result<Self, ConfigError> {
        let opt = ParseOption {
            enabled_quote: false,
            enabled_escape: false,
            enabled_indented_mutiline_value: true,
            enabled_preserve_key_leading_whitespace: false,
        };
        Ini::load_from_str_opt(raw, opt)
            .map(|ini| Self {
                ini,
                path: path.clone(),
                legacy_timeout_comment: raw.contains(LEGACY_TIMEOUT_COMMENT),
            })
            .map_err(|e| ConfigError::Parse(path, e.to_string()))
    }

    /// These settings with another camera and no `ir_only`, for the walk-away lock.
    pub fn with_camera(&self, device_path: &str) -> Self {
        let mut out = self.clone();
        out.ini
            .with_section(Some("video"))
            .set("device_path", device_path)
            .set("ir_only", "false");
        out
    }

    pub fn empty() -> Self {
        Self {
            ini: Ini::new(),
            path: "<memory>".into(),
            legacy_timeout_comment: false,
        }
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn get(&self, section: &str, key: &str) -> Option<String> {
        self.ini
            .get_from(Some(section), key)
            .map(|s| s.trim().to_string())
    }

    fn get_bool(&self, section: &str, key: &str, fallback: bool) -> bool {
        self.get(section, key)
            .and_then(|v| parse_bool(&v))
            .unwrap_or(fallback)
    }

    fn get_float(&self, section: &str, key: &str, fallback: f64) -> f64 {
        self.get(section, key)
            .and_then(|v| v.parse::<f64>().ok())
            .filter(|v| v.is_finite())
            .unwrap_or(fallback)
    }

    fn get_int(&self, section: &str, key: &str, fallback: i64) -> i64 {
        self.get(section, key)
            .and_then(|v| v.parse::<i64>().ok())
            .unwrap_or(fallback)
    }

    /// Descriptions of known keys whose value was ignored.
    pub fn invalid_values(&self) -> Vec<String> {
        let mut out = Vec::new();
        for &(section, key, kind) in KNOWN_KEYS {
            let Some(v) = self.get(section, key) else {
                continue;
            };
            let (ok, expected) = match kind {
                Kind::Bool => (parse_bool(&v).is_some(), "true/false"),
                Kind::Int => (v.parse::<i64>().is_ok(), "an integer"),
                Kind::Pcrs => (
                    parse_pcrs(&v).is_some(),
                    "a list of PCR numbers 0-23 joined by +",
                ),
                Kind::Float => (v.parse::<f64>().is_ok_and(f64::is_finite), "a number"),
            };
            if !ok {
                out.push(format!("[{section}] {key} = {v:?} is not {expected}"));
            }
        }
        if let Some(v) = self.get("video", "min_similarity") {
            if v.parse::<f64>()
                .is_ok_and(|s| s.is_finite() && !(MIN_SIMILARITY..=MAX_SIMILARITY).contains(&s))
            {
                out.push(format!(
                    "[video] min_similarity = {v} is outside [{MIN_SIMILARITY}, {MAX_SIMILARITY}]"
                ));
            }
        }
        if let Some(v) = self.get("video", "timeout") {
            if v.parse::<i64>()
                .is_ok_and(|n| !(1..=MAX_AUTH_TIMEOUT_SECS).contains(&n))
            {
                out.push(format!(
                    "[video] timeout = {v} is outside [1, {MAX_AUTH_TIMEOUT_SECS}]"
                ));
            }
        }
        if let Some(v) = self.get("snapshots", "keep") {
            let max = crate::snapshots::MAX_KEEP;
            if v.parse::<i64>()
                .is_ok_and(|n| !(1..=i64::from(max)).contains(&n))
            {
                out.push(format!("[snapshots] keep = {v} is outside [1, {max}]"));
            }
        }
        if let Some(v) = self.get("core", "max_failed_attempts") {
            if v.parse::<i64>()
                .is_ok_and(|n| !(0..=MAX_FAILED_ATTEMPTS_LIMIT).contains(&n))
            {
                out.push(format!(
                    "[core] max_failed_attempts = {v} is outside [0, {MAX_FAILED_ATTEMPTS_LIMIT}]"
                ));
            }
        }
        for (key, valid, description) in [
            (
                "dark_threshold",
                self.get_float("video", "dark_threshold", -1.0),
                "[1, 100]",
            ),
            (
                "max_height",
                self.get_float("video", "max_height", -1.0),
                "greater than 0",
            ),
        ] {
            let ok = if key == "dark_threshold" {
                (1.0..=100.0).contains(&valid)
            } else {
                valid > 0.0
            };
            if self.get("video", key).is_some()
                && !ok
                && !out
                    .iter()
                    .any(|e| e.starts_with(&format!("[video] {key} ")))
            {
                out.push(format!("[video] {key} must be {description}"));
            }
        }
        for key in ["frame_width", "frame_height"] {
            let value = self.get_int("video", key, -1);
            if self.get("video", key).is_some()
                && value != -1
                && value <= 0
                && !out
                    .iter()
                    .any(|e| e.starts_with(&format!("[video] {key} ")))
            {
                out.push(format!("[video] {key} must be -1 or positive"));
            }
        }
        out
    }

    /// Invalid values that could weaken authentication; PAM must fall back to the
    /// password when any exist.
    pub fn security_errors(&self) -> Vec<String> {
        const SECURITY_KEYS: &[(&str, &str)] = &[
            ("core", "disabled"),
            ("core", "abort_if_ssh"),
            ("core", "abort_if_lid_closed"),
            ("core", "movement_challenge"),
            ("core", "require_movement_without_ir"),
            ("core", "max_failed_attempts"),
            ("services", "sudo"),
            ("services", "login_screen"),
            ("services", "lock_screen"),
            ("services", "polkit"),
            ("services", "console"),
            ("video", "ir_only"),
            ("video", "min_similarity"),
            ("video", "personal_threshold"),
            ("video", "timeout"),
        ];
        self.invalid_values()
            .into_iter()
            .filter(|message| {
                SECURITY_KEYS
                    .iter()
                    .any(|(s, k)| message.starts_with(&format!("[{s}] {k} ")))
            })
            .collect()
    }

    pub fn validate(&self) -> Result<(), Vec<String>> {
        let errors = self.invalid_values();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    pub fn disabled(&self) -> bool {
        self.get_bool("core", "disabled", false)
    }
    pub fn abort_if_ssh(&self) -> bool {
        self.get_bool("core", "abort_if_ssh", true)
    }
    pub fn abort_if_lid_closed(&self) -> bool {
        self.get_bool("core", "abort_if_lid_closed", true)
    }
    pub fn no_confirmation(&self) -> bool {
        self.get_bool("core", "no_confirmation", true)
    }
    pub fn detection_notice(&self) -> bool {
        self.get_bool("core", "detection_notice", true)
    }
    /// Require the head-turn challenge after the identity match.
    pub fn movement_challenge(&self) -> bool {
        self.get_bool("core", "movement_challenge", true)
    }
    /// Keep the head-movement check on for cameras not attested as infrared.
    pub fn require_movement_without_ir(&self) -> bool {
        self.get_bool("core", "require_movement_without_ir", true)
    }
    /// Whether a camera of `kind` needs the head-movement check (unknown = colour).
    pub fn movement_required(&self, kind: Option<CameraKind>) -> bool {
        movement_required(
            self.movement_challenge(),
            self.require_movement_without_ir(),
            kind,
        )
    }
    pub fn service_enabled(&self, service: FaceService) -> bool {
        self.get_bool("services", service.key(), service.enabled_by_default())
    }
    /// Failed face attempts before face login pauses; 0 = no limit.
    pub fn max_failed_attempts(&self) -> u32 {
        let v = self.get_int("core", "max_failed_attempts", DEFAULT_MAX_FAILED_ATTEMPTS);
        if (0..=MAX_FAILED_ATTEMPTS_LIMIT).contains(&v) {
            v as u32
        } else {
            DEFAULT_MAX_FAILED_ATTEMPTS as u32
        }
    }
    /// PCRs the sealed face models are bound to; empty means none (the
    /// default). An invalid value is an error, never "no binding": sealing
    /// must then refuse rather than protect the models less than asked.
    pub fn tpm2_pcrs(&self) -> Result<Vec<u8>, String> {
        let value = self.get("core", "tpm2_pcrs").unwrap_or_default();
        parse_pcrs(&value).ok_or_else(|| {
            format!("[core] tpm2_pcrs = {value:?} is not a list of PCR numbers 0-23 joined by +")
        })
    }
    /// Only `off` is supported; a file without the key means `off` too.
    pub fn workaround(&self) -> String {
        self.get("core", "workaround").unwrap_or("off".into())
    }

    /// Minimum cosine similarity; values outside the shared range are ignored.
    pub fn min_similarity(&self) -> f64 {
        let v = self.get_float("video", "min_similarity", DEFAULT_MIN_SIMILARITY);
        if (MIN_SIMILARITY..=MAX_SIMILARITY).contains(&v) {
            v
        } else {
            DEFAULT_MIN_SIMILARITY
        }
    }
    /// Raise `min_similarity` per user from their enrollment; never lowers it.
    pub fn personal_threshold(&self) -> bool {
        self.get_bool("video", "personal_threshold", false)
    }
    pub fn effective_min_similarity(&self, known: &[(usize, Vec<f32>)]) -> f32 {
        let global = self.min_similarity() as f32;
        if !self.personal_threshold() {
            return global;
        }
        crate::matcher::personal_threshold(known).map_or(global, |personal| personal.max(global))
    }
    /// The scan time is still the Linux Hello pre-1.3.0 default kept by RPM in an edited
    /// config.ini.
    pub fn legacy_default_timeout(&self) -> bool {
        self.legacy_timeout_comment
            && self.get("video", "timeout").and_then(|v| v.parse().ok())
                == Some(LEGACY_DEFAULT_TIMEOUT_SECS)
    }

    /// Scan timeout in seconds, capped for PAM safety.
    pub fn video_timeout_secs(&self) -> i64 {
        self.get_int("video", "timeout", DEFAULT_TIMEOUT_SECS)
            .clamp(1, MAX_AUTH_TIMEOUT_SECS)
    }
    /// Longest an attempt may take: scan time plus the movement challenge time.
    pub fn attempt_secs(&self, movement: bool) -> i64 {
        self.video_timeout_secs() + if movement { CHALLENGE_SECS } else { 0 }
    }
    /// Raise the screen backlight while a colour camera scans a dark scene.
    pub fn brighten_screen(&self) -> bool {
        self.get_bool("video", "brighten_screen", true)
    }
    pub fn dark_threshold(&self) -> f64 {
        self.get_float("video", "dark_threshold", 60.0)
    }
    pub fn max_height(&self) -> f64 {
        self.get_float("video", "max_height", 320.0)
    }
    pub fn device_path(&self) -> String {
        self.get("video", "device_path").unwrap_or("none".into())
    }
    pub fn device_is_automatic(&self) -> bool {
        is_automatic_device(&self.device_path())
    }
    pub fn warn_no_device(&self) -> bool {
        self.get_bool("video", "warn_no_device", true)
    }
    pub fn ir_only(&self) -> bool {
        self.get_bool("video", "ir_only", false)
    }
    pub fn recording_plugin(&self) -> String {
        self.get("video", "recording_plugin")
            .unwrap_or("opencv".into())
    }
    pub fn rotate(&self) -> i64 {
        self.get_int("video", "rotate", 0)
    }
    pub fn exposure(&self) -> i64 {
        self.get_int("video", "exposure", -1)
    }
    pub fn force_mjpeg(&self) -> bool {
        self.get_bool("video", "force_mjpeg", false)
    }
    pub fn frame_width(&self) -> i64 {
        self.get_int("video", "frame_width", -1)
    }
    pub fn frame_height(&self) -> i64 {
        self.get_int("video", "frame_height", -1)
    }
    pub fn device_fps(&self) -> i64 {
        // 0 keeps the camera's FPS; new installs use -1.
        self.get_int("video", "device_fps", 0)
    }
    pub fn device_format(&self) -> String {
        self.get("video", "device_format").unwrap_or("v4l2".into())
    }

    /// Keep a photo of each failed face attempt.
    pub fn save_failed_snapshots(&self) -> bool {
        self.get_bool("snapshots", "save_failed", false)
    }
    pub fn snapshot_keep(&self) -> u32 {
        let v = self.get_int(
            "snapshots",
            "keep",
            i64::from(crate::snapshots::DEFAULT_KEEP),
        );
        u32::try_from(v)
            .ok()
            .filter(|n| (1..=crate::snapshots::MAX_KEEP).contains(n))
            .unwrap_or(crate::snapshots::DEFAULT_KEEP)
    }
    pub fn save_successful_snapshots(&self) -> bool {
        self.get_bool("snapshots", "save_successful", false)
    }
    pub fn end_report(&self) -> bool {
        self.get_bool("debug", "end_report", false)
    }
    pub fn rubberstamps_enabled(&self) -> bool {
        self.get_bool("rubberstamps", "enabled", false)
    }

    /// Parse the `disabled` argument: 1/true or 0/false.
    pub fn parse_disabled_arg(arg: &str) -> Option<bool> {
        match arg.to_lowercase().as_str() {
            "1" | "true" => Some(true),
            "0" | "false" => Some(false),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(body: &str) -> PeekinConfig {
        PeekinConfig::parse(body, "<test>".into()).unwrap()
    }

    #[test]
    fn fallback_defaults() {
        let cfg = PeekinConfig::empty();
        assert!(!cfg.disabled());
        assert!(cfg.abort_if_ssh());
        assert_eq!(cfg.min_similarity(), DEFAULT_MIN_SIMILARITY);
        assert_eq!(cfg.video_timeout_secs(), 3);
        assert_eq!(cfg.dark_threshold(), 60.0);
        assert_eq!(cfg.max_height(), 320.0);
        assert_eq!(cfg.recording_plugin(), "opencv");
        assert_eq!(cfg.exposure(), -1);
        assert!(cfg.invalid_values().is_empty());
    }

    #[test]
    fn reads_real_values() {
        let cfg = cfg("[core]\ndisabled = true\n[video]\nmin_similarity = 0.5\ntimeout = 10\n");
        assert!(cfg.disabled());
        assert_eq!(cfg.min_similarity(), 0.5);
        assert_eq!(cfg.video_timeout_secs(), 10);
    }

    #[test]
    fn ir_only_defaults_off_and_has_a_section() {
        assert!(!PeekinConfig::empty().ir_only());
        assert!(cfg("[video]\nir_only = true\n").ir_only());
        assert_eq!(known_section("ir_only"), Some("video"));
        assert_eq!(known_section("device_path"), Some("video"));
        assert_eq!(known_section("nonsense"), None);
    }

    #[test]
    fn movement_challenge_defaults_on_and_fails_closed_when_malformed() {
        assert!(PeekinConfig::empty().movement_challenge());
        assert!(!cfg("[core]\nmovement_challenge = false\n").movement_challenge());
        let bad = cfg("[core]\nmovement_challenge = sometimes\n");
        assert!(
            bad.movement_challenge(),
            "a typo must keep the challenge on"
        );
        assert_eq!(bad.security_errors().len(), 1);
        assert_eq!(known_section("movement_challenge"), Some("core"));
    }

    #[test]
    fn movement_stays_required_without_an_attested_infrared_camera() {
        let ir = Some(CameraKind::VerifiedInfrared);
        let others = [
            Some(CameraKind::Colour),
            Some(CameraKind::InfraredCandidate),
            None,
        ];
        let off = cfg("[core]\nmovement_challenge = false\n");
        assert!(off.require_movement_without_ir(), "on by default");
        assert!(!off.movement_required(ir));
        assert!(others.iter().all(|&kind| off.movement_required(kind)));
        let both_off =
            cfg("[core]\nmovement_challenge = false\nrequire_movement_without_ir = false\n");
        assert!(!both_off.movement_required(ir));
        assert!(others.iter().all(|&kind| !both_off.movement_required(kind)));
        let on = PeekinConfig::empty();
        assert!(on.movement_required(ir) && others.iter().all(|&k| on.movement_required(k)));
        let typo = cfg("[core]\nmovement_challenge = false\nrequire_movement_without_ir = maybe\n");
        assert!(
            typo.movement_required(Some(CameraKind::Colour)),
            "a typo keeps it on"
        );
        assert_eq!(typo.security_errors().len(), 1);
    }

    #[test]
    fn scan_time_defaults_to_three_seconds_and_the_challenge_adds_its_own() {
        assert_eq!(PeekinConfig::empty().video_timeout_secs(), 3);
        assert_eq!(PeekinConfig::empty().attempt_secs(true), 3 + CHALLENGE_SECS);
        let passive = cfg("[video]\ntimeout = 10\n");
        assert_eq!(passive.attempt_secs(false), 10);
        assert!(!cfg("[video]\ntimeout = 11\n").security_errors().is_empty());
    }

    #[test]
    fn failed_attempt_limit_defaults_and_fails_closed_when_malformed() {
        assert_eq!(PeekinConfig::empty().max_failed_attempts(), 5);
        assert_eq!(
            cfg("[core]\nmax_failed_attempts = 0\n").max_failed_attempts(),
            0
        );
        for bad in ["-1", "101", "many"] {
            let c = cfg(&format!("[core]\nmax_failed_attempts = {bad}\n"));
            assert_eq!(c.max_failed_attempts(), 5, "{bad}");
            assert_eq!(c.security_errors().len(), 1, "{bad}");
        }
    }

    #[test]
    fn pcr_binding_is_off_by_default_and_strictly_parsed() {
        assert_eq!(PeekinConfig::empty().tpm2_pcrs(), Ok(vec![]));
        assert_eq!(cfg("[core]\ntpm2_pcrs =\n").tpm2_pcrs(), Ok(vec![]));
        assert_eq!(cfg("[core]\ntpm2_pcrs = 7\n").tpm2_pcrs(), Ok(vec![7]));
        assert_eq!(
            cfg("[core]\ntpm2_pcrs = 14+7\n").tpm2_pcrs(),
            Ok(vec![7, 14])
        );
        assert_eq!(parse_pcrs("0,7 + 23"), Some(vec![0, 7, 23]));
        for bad in [
            "24",
            "7+7",
            "7+",
            "+7",
            "-1",
            "7;rm",
            "secure-boot-policy",
            "007",
            "7 14",
            "0x7",
        ] {
            let c = cfg(&format!("[core]\ntpm2_pcrs = {bad}\n"));
            assert!(c.tpm2_pcrs().is_err(), "{bad:?}");
            assert_eq!(c.invalid_values().len(), 1, "{bad:?}");
            // Encryption at rest, not an authentication decision.
            assert!(c.security_errors().is_empty(), "{bad:?}");
        }
        assert_eq!(known_section("tpm2_pcrs"), Some("core"));
    }

    #[test]
    fn services_default_to_the_original_three_and_fail_closed() {
        let c = PeekinConfig::empty();
        assert!(c.service_enabled(FaceService::Sudo));
        assert!(c.service_enabled(FaceService::LoginScreen));
        assert!(c.service_enabled(FaceService::LockScreen));
        assert!(!c.service_enabled(FaceService::Polkit));
        assert!(!c.service_enabled(FaceService::Console));
        let c = cfg("[services]\nlogin_screen = false\nconsole = true\n");
        assert!(!c.service_enabled(FaceService::LoginScreen));
        assert!(c.service_enabled(FaceService::Console));
        assert_eq!(known_section("lock_screen"), Some("services"));
        assert!(!cfg("[services]\npolkit = sometimes\n")
            .security_errors()
            .is_empty());
    }

    #[test]
    fn automatic_device_values() {
        for auto in ["none", "auto", "", "  none "] {
            assert!(is_automatic_device(auto), "{auto:?}");
        }
        assert!(PeekinConfig::empty().device_is_automatic());
        assert!(!cfg("[video]\ndevice_path = /dev/video0\n").device_is_automatic());
    }

    #[test]
    fn keys_and_sections_are_case_insensitive() {
        let cfg = cfg("[Core]\nDisabled = TRUE\n");
        assert!(cfg.disabled());
    }

    #[test]
    fn unparseable_bool_keeps_safe_default_and_is_reported() {
        let cfg = cfg("[core]\nabort_if_ssh = maybe\n");
        assert!(cfg.abort_if_ssh(), "SSH protection must stay on");
        let invalid = cfg.invalid_values();
        assert_eq!(invalid.len(), 1);
        assert!(invalid[0].contains("abort_if_ssh"));
    }

    #[test]
    fn malformed_security_values_are_fail_closed_signals_and_timeout_is_capped() {
        for body in [
            "[core]\ndisabled = maybe\n",
            "[video]\nir_only = maybe\n",
            "[video]\nmin_similarity = nope\n",
            "[video]\ntimeout = 999\n",
        ] {
            assert!(!cfg(body).security_errors().is_empty(), "{body}");
        }
        assert_eq!(
            cfg("[video]\ntimeout = 999\n").video_timeout_secs(),
            MAX_AUTH_TIMEOUT_SECS
        );
    }

    #[test]
    fn min_similarity_rejects_values_that_would_accept_anyone() {
        for bad in ["0", "-1", "1.5", "nan", "inf"] {
            let c = cfg(&format!("[video]\nmin_similarity = {bad}\n"));
            assert_eq!(c.min_similarity(), DEFAULT_MIN_SIMILARITY, "{bad}");
            assert_eq!(c.invalid_values().len(), 1, "{bad}");
        }
    }

    #[test]
    fn indented_lines_continue_a_value() {
        let c = cfg("[core]\nworkaround = off\n\n[rubberstamps]\nenabled = false\nstamp_rules =\n\tnod\t\t5s\t\tfailsafe     min_distance=12\n\n[debug]\nend_report = false\n");
        let rules = c.get("rubberstamps", "stamp_rules").unwrap();
        assert!(
            rules.contains("nod") && rules.contains("min_distance=12"),
            "{rules:?}"
        );
        assert_eq!(
            c.ini.section(Some("rubberstamps")).unwrap().len(),
            2,
            "no junk keys"
        );
        assert_eq!(c.workaround(), "off");
        assert!(c.invalid_values().is_empty(), "{:?}", c.invalid_values());
    }

    #[test]
    fn personal_threshold_only_tightens_and_is_off_by_default() {
        let unit = |deg: f32| {
            let r = deg.to_radians();
            vec![r.cos(), r.sin()]
        };
        // Least similar pair cos(40°) ≈ 0.766 → personal ≈ 0.466.
        let spread = vec![(0, unit(0.0)), (0, unit(40.0))];
        // Least similar pair cos(80°) ≈ 0.174 → personal < global: ignored.
        let wide = vec![(0, unit(0.0)), (0, unit(80.0))];
        let off = PeekinConfig::empty();
        assert!(!off.personal_threshold());
        assert_eq!(off.effective_min_similarity(&spread), 0.363);
        let on = cfg("[video]\npersonal_threshold = true\n");
        assert!((on.effective_min_similarity(&spread) - 0.466).abs() < 0.001);
        assert_eq!(on.effective_min_similarity(&wide), 0.363);
        assert_eq!(on.effective_min_similarity(&[]), 0.363);
        let strict = cfg("[video]\npersonal_threshold = true\nmin_similarity = 0.6\n");
        assert_eq!(strict.effective_min_similarity(&spread), 0.6);
        let typo = cfg("[video]\npersonal_threshold = sure\n");
        assert_eq!(typo.security_errors().len(), 1);
    }

    #[test]
    fn only_an_untouched_pre_1_3_scan_time_is_legacy() {
        // The [video] lines of the config.ini of Linux Hello up to 1.2.0.
        let old = "[video]\n# challenge needs time to turn in both directions; 10 s is the new-install default.\n# Valid range is 1..15; PAM also enforces this cap independently.\ntimeout = 10\n";
        assert!(cfg(old).legacy_default_timeout());
        assert!(!cfg(&old.replace("timeout = 10", "timeout = 3")).legacy_default_timeout());
        assert!(!cfg("[video]\ntimeout = 10\n").legacy_default_timeout());
        assert!(!PeekinConfig::empty().legacy_default_timeout());
    }

    #[test]
    fn with_camera_overrides_only_the_camera() {
        let c = cfg("[video]\ndevice_path = /dev/video2\nir_only = true\ntimeout = 5\n");
        let away = c.with_camera("/dev/video0");
        assert_eq!(away.device_path(), "/dev/video0");
        assert!(!away.ir_only());
        assert_eq!(away.video_timeout_secs(), 5);
        assert_eq!(c.device_path(), "/dev/video2", "the original is untouched");
    }

    #[test]
    fn snapshots_are_off_by_default_and_keep_is_bounded() {
        let c = PeekinConfig::empty();
        assert!(!c.save_failed_snapshots());
        assert_eq!(c.snapshot_keep(), 20);
        let set = cfg("[snapshots]\nsave_failed = true\nkeep = 5\n");
        assert!(set.save_failed_snapshots() && set.snapshot_keep() == 5);
        let wild = cfg("[snapshots]\nkeep = 500\n");
        assert_eq!(wild.snapshot_keep(), 20);
        assert_eq!(wild.invalid_values().len(), 1);
        assert!(
            wild.security_errors().is_empty(),
            "privacy setting, not security"
        );
    }

    #[test]
    fn every_config_key_is_documented_in_the_man_page() {
        let page = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../data/man/peekin-config.5"
        ))
        .unwrap();
        for (section, key, _) in KNOWN_KEYS {
            assert!(
                page.contains(key),
                "[{section}] {key} missing from peekin-config(5)"
            );
        }
        for key in ["device_path", "workaround"] {
            assert!(page.contains(key), "{key} missing from peekin-config(5)");
        }
    }

    #[test]
    fn rust_default_config_is_valid() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../data/config.ini"
        ))
        .unwrap();
        let c = cfg(&raw);
        assert!(c.invalid_values().is_empty(), "{:?}", c.invalid_values());
        assert_eq!(c.min_similarity(), DEFAULT_MIN_SIMILARITY);
        assert_eq!(c.workaround(), "off");
        assert_eq!((c.frame_width(), c.frame_height()), (640, 480));
        assert!(c.detection_notice() && !c.disabled() && !c.rubberstamps_enabled());
        assert!(c.movement_challenge());
        assert!(!c.legacy_default_timeout());
    }

    #[test]
    fn values_are_taken_literally() {
        let c = cfg("[video]\ndevice_path = \"/dev/v4l/by-path/a\\b\"\n");
        assert_eq!(c.device_path(), "\"/dev/v4l/by-path/a\\b\"");
    }

    #[test]
    fn parse_disabled_arg_values() {
        assert_eq!(PeekinConfig::parse_disabled_arg("1"), Some(true));
        assert_eq!(PeekinConfig::parse_disabled_arg("true"), Some(true));
        assert_eq!(PeekinConfig::parse_disabled_arg("0"), Some(false));
        assert_eq!(PeekinConfig::parse_disabled_arg("FaLsE"), Some(false));
        assert_eq!(PeekinConfig::parse_disabled_arg("2"), None);
    }
}
