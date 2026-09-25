//! Pure UI state decisions, kept independent from GTK for headless tests.

use peekin_core::gtk_models::ListedModel;
use peekin_core::i18n::{tr, tr_args, trn};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Operation {
    #[default]
    Idle,
    Loading,
    Saving,
    Removing,
    Resuming,
    LoadingSnapshots,
    ClearingSnapshots,
    Enrolling,
    Testing,
}

impl Operation {
    pub fn is_write(self) -> bool {
        matches!(
            self,
            Self::Saving | Self::Removing | Self::Resuming | Self::ClearingSnapshots
        )
    }

    pub fn status(self) -> String {
        match self {
            Self::Idle => String::new(),
            Self::Loading => tr("Authorizing and loading models…"),
            Self::Saving => tr("Authorizing and saving…"),
            Self::Removing => tr("Authorizing and removing model…"),
            Self::Resuming => tr("Authorizing and resuming face login…"),
            Self::LoadingSnapshots => tr("Authorizing and loading photos…"),
            Self::ClearingSnapshots => tr("Authorizing and deleting photos…"),
            Self::Enrolling => tr("Capturing face model…"),
            Self::Testing => tr("Running recognition test…"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReadinessValue {
    Unknown(String),
    Ready(String),
    Blocked(String),
}

impl ReadinessValue {
    pub fn text(&self) -> &str {
        match self {
            Self::Unknown(text) => text,
            Self::Ready(text) | Self::Blocked(text) => text,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Readiness {
    pub config: ReadinessValue,
    pub camera: ReadinessValue,
    pub pam: ReadinessValue,
    pub models: ReadinessValue,
    pub attempts: ReadinessValue,
}

impl Default for Readiness {
    fn default() -> Self {
        Self {
            config: ReadinessValue::Unknown(tr("not loaded")),
            camera: ReadinessValue::Unknown(tr("not checked")),
            pam: ReadinessValue::Unknown(tr("not checked")),
            models: ReadinessValue::Unknown(tr("not loaded")),
            attempts: ReadinessValue::Unknown(tr("not loaded")),
        }
    }
}

pub fn pam_rule_present(body: &str) -> bool {
    let (mut face, mut password, mut deny) = (false, false, false);
    for raw in body.lines() {
        let line = raw.split_once(" #").map_or(raw, |(line, _)| line).trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.first() == Some(&"@include") || fields.first() == Some(&"-auth") {
            return false;
        }
        if fields.first() != Some(&"auth") {
            continue;
        }
        let own = fields == ["auth", "sufficient", "pam_peekin.so"]
            || fields == ["auth", "[success=done", "default=ignore]", "pam_peekin.so"];
        if own {
            if face || password {
                return false;
            }
            face = true;
        } else if face && !password {
            if fields.get(1) != Some(&"sufficient") || fields.get(2) != Some(&"pam_unix.so") {
                return false;
            }
            password = true;
        } else if password {
            if !deny
                && fields.get(1) == Some(&"required")
                && fields.get(2) == Some(&"pam_faillock.so")
                && fields.contains(&"authfail")
            {
                continue;
            }
            if !deny
                && fields.get(1) == Some(&"optional")
                && fields.get(2) == Some(&"pam_gnome_keyring.so")
            {
                continue;
            }
            if deny
                || fields.len() != 3
                || !matches!(fields.get(1), Some(&"required" | &"requisite"))
                || fields[2] != "pam_deny.so"
            {
                return false;
            }
            deny = true;
        } else if fields.len() < 3
            || !(matches!(fields.get(1), Some(&"required" | &"requisite"))
                || fields.get(1) == Some(&"sufficient")
                    && matches!(fields.get(2), Some(&"pam_fprintd.so" | &"pam_u2f.so")))
            || ["pam_unix.so", "pam_peekin.so", "pam_deny.so"]
                .iter()
                .any(|name| fields[2].ends_with(name))
        {
            return false;
        }
    }
    face && password && deny
}

pub fn authselect_services(sudo: &str, gdm: &str) -> bool {
    fn lines(body: &str) -> Vec<Vec<&str>> {
        body.lines()
            .filter_map(|raw| {
                let line = raw.split_once(" #").map_or(raw, |(line, _)| line).trim();
                (!line.is_empty()
                    && !line.starts_with('#')
                    && line.split_whitespace().next() == Some("auth"))
                .then(|| line.split_whitespace().collect())
            })
            .collect()
    }
    let sudo = lines(sudo);
    let gdm = lines(gdm);
    sudo == [vec!["auth", "include", "system-auth"]]
        && gdm.first()
            == Some(&vec![
                "auth",
                "[success=done",
                "ignore=ignore",
                "default=bad]",
                "pam_selinux_permit.so",
            ])
        && gdm.get(1) == Some(&vec!["auth", "substack", "password-auth"])
        && gdm[2..].iter().all(|line| {
            line == &["auth", "optional", "pam_gnome_keyring.so"]
                || line == &["auth", "include", "postlogin"]
        })
}

pub fn parse_model_metadata(
    output: &str,
    expected_user: &str,
) -> Result<(Vec<ListedModel>, usize), String> {
    let parsed: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| format!("invalid helper response: {error}"))?;
    if parsed.get("version").and_then(|value| value.as_u64()) != Some(1) {
        return Err("unsupported helper response version".into());
    }
    if parsed.get("user").and_then(|value| value.as_str()) != Some(expected_user) {
        return Err("privileged metadata identity mismatch".into());
    }
    let rows = parsed
        .get("models")
        .and_then(|value| value.as_array())
        .ok_or_else(|| "incomplete helper response".to_string())?;
    let mut usable = 0;
    let mut models = Vec::with_capacity(rows.len());
    for row in rows {
        let id = row
            .get("id")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| "model metadata has no numeric id".to_string())?;
        let label = row
            .get("label")
            .and_then(|value| value.as_str())
            .ok_or_else(|| "model metadata has no label".to_string())?;
        let time = row
            .get("time")
            .and_then(|value| value.as_i64())
            .ok_or_else(|| "model metadata has no timestamp".to_string())?;
        usable += usize::from(row.get("usable").and_then(|value| value.as_bool()) == Some(true));
        models.push(ListedModel {
            id: id.to_string(),
            created: format!("Unix time {time}"),
            label: label.to_string(),
        });
    }
    Ok((models, usable))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Attempts {
    pub failures: u32,
    /// `[core] max_failed_attempts`; 0 means no limit.
    pub limit: u32,
    /// When face login resumes by itself, while it is paused.
    pub paused_until: Option<i64>,
}

/// Missing or unreadable state is an error, never "no failures".
pub fn parse_attempts(output: &str) -> Result<Attempts, String> {
    let parsed: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| format!("invalid helper response: {error}"))?;
    let attempts = parsed
        .get("attempts")
        .ok_or_else(|| "helper does not report failed attempts".to_string())?;
    if let Some(error) = attempts.get("error").and_then(|value| value.as_str()) {
        return Err(format!("cannot read failed attempts: {error}"));
    }
    let count = |key: &str| {
        attempts
            .get(key)
            .and_then(|value| value.as_u64())
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| format!("failed-attempt state has no {key}"))
    };
    let paused_until = match attempts.get("paused_until") {
        Some(serde_json::Value::Null) => None,
        Some(value) => Some(
            value
                .as_i64()
                .ok_or_else(|| "failed-attempt state has an invalid pause time".to_string())?,
        ),
        None => return Err("failed-attempt state has no pause time".into()),
    };
    Ok(Attempts {
        failures: count("failures")?,
        limit: count("limit")?,
        paused_until,
    })
}

/// Named combinations of the recognition settings (see docs/THRESHOLDS.md).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Preset {
    Fast,
    Balanced,
    Secure,
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Recognition {
    pub movement_challenge: bool,
    pub require_movement_without_ir: bool,
    pub min_similarity: f64,
    pub personal_threshold: bool,
}

impl Preset {
    pub const ALL: [Preset; 4] = [Self::Fast, Self::Balanced, Self::Secure, Self::Custom];

    pub fn values(self) -> Option<Recognition> {
        let base = Recognition {
            movement_challenge: true,
            require_movement_without_ir: true,
            min_similarity: 0.363,
            personal_threshold: false,
        };
        match self {
            Self::Fast => Some(Recognition {
                movement_challenge: false,
                ..base
            }),
            Self::Balanced => Some(base),
            Self::Secure => Some(Recognition {
                min_similarity: 0.45,
                personal_threshold: true,
                ..base
            }),
            Self::Custom => None,
        }
    }

    pub fn of(settings: Recognition) -> Self {
        Self::ALL
            .into_iter()
            .find(|p| {
                p.values().is_some_and(|v| {
                    v.movement_challenge == settings.movement_challenge
                        && v.require_movement_without_ir == settings.require_movement_without_ir
                        && v.personal_threshold == settings.personal_threshold
                        && (v.min_similarity - settings.min_similarity).abs() < 0.0005
                })
            })
            .unwrap_or(Self::Custom)
    }

    pub fn name(self) -> String {
        match self {
            Self::Fast => tr("Fast"),
            Self::Balanced => tr("Balanced"),
            Self::Secure => tr("Secure"),
            Self::Custom => tr("Custom"),
        }
    }

    pub fn description(self) -> String {
        match self {
            Self::Fast => tr(
                "Just look at the camera. Head turns only without an approved \
                infrared camera. About 1 stranger in 240 could match your face model",
            ),
            Self::Balanced => tr("Head turns after recognising you. About 1 stranger in 240 \
                could match your face model; a photo alone does not unlock"),
            Self::Secure => tr(
                "Head turns and a stricter match: about 1 stranger in 5,700 or \
                fewer. Your own face may be rejected a little more often",
            ),
            Self::Custom => tr("Your own combination of the settings below"),
        }
    }
}

pub fn service_name(key: &str) -> String {
    match key {
        "sudo" => "sudo".to_string(),
        "login_screen" => tr("Login screen"),
        "lock_screen" => tr("Lock screen"),
        "polkit" => tr("Administrator dialog"),
        "console" => tr("Text console"),
        other => other.to_string(),
    }
}

pub fn outcome_text(outcome: peekin_core::activity::Outcome) -> String {
    use peekin_core::activity::Outcome;
    match outcome {
        Outcome::Success => tr("Recognised"),
        Outcome::Rejected => tr("Face not recognised"),
        Outcome::ChallengeFailed => tr("Head movement not followed"),
        Outcome::NoFace => tr("No face seen"),
        Outcome::Unavailable => tr("Camera not available"),
        Outcome::Paused => tr("Face login paused"),
    }
}

/// (unix time, base64 JPEG), newest first; the reply must be for `expected_user`.
pub fn parse_snapshots(output: &str, expected_user: &str) -> Result<Vec<(i64, String)>, String> {
    let parsed: serde_json::Value = serde_json::from_str(output)
        .map_err(|error| format!("invalid helper response: {error}"))?;
    if parsed.get("version").and_then(|v| v.as_u64()) != Some(1) {
        return Err("unsupported helper response version".into());
    }
    if parsed.get("user").and_then(|v| v.as_str()) != Some(expected_user) {
        return Err("privileged response identity mismatch".into());
    }
    parsed
        .get("snapshots")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "incomplete helper response".to_string())?
        .iter()
        .map(|row| {
            let entry = || {
                Some((
                    row.get("time")?.as_i64()?,
                    row.get("jpeg")?.as_str()?.to_string(),
                ))
            };
            entry().ok_or_else(|| "photo entry is incomplete".to_string())
        })
        .collect()
}

/// Present when any model has at least two samples.
pub fn parse_personal_threshold(output: &str) -> Option<f64> {
    serde_json::from_str::<serde_json::Value>(output)
        .ok()?
        .get("personal_threshold")?
        .as_f64()
        .filter(|t| t.is_finite())
}

/// `resume_at` is the pause end already formatted as local time.
pub fn attempts_readiness(attempts: Attempts, resume_at: &str) -> ReadinessValue {
    if attempts.paused_until.is_some() {
        return ReadinessValue::Blocked(tr_args(
            "face login paused after {failures} failed attempts until {resume_at}; \
             your password still works",
            &[("failures", &attempts.failures), ("resume_at", &resume_at)],
        ));
    }
    let recent = match attempts.failures {
        0 => tr("no recent failed attempts"),
        n => trn(
            "{n} recent failed attempt",
            "{n} recent failed attempts",
            n.into(),
        ),
    };
    ReadinessValue::Ready(match attempts.limit {
        0 => tr_args("{recent}; no limit", &[("recent", &recent)]),
        limit => tr_args(
            "{recent}; pauses after {limit}",
            &[("recent", &recent), ("limit", &limit)],
        ),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_status_is_specific_and_write_boundary_is_conservative() {
        assert_eq!(
            Operation::Loading.status(),
            "Authorizing and loading models…"
        );
        assert_eq!(
            Operation::Removing.status(),
            "Authorizing and removing model…"
        );
        assert!(Operation::Saving.is_write());
        assert!(Operation::Removing.is_write());
        assert!(!Operation::Loading.is_write());
    }

    #[test]
    fn pam_status_uses_exact_uncommented_rule() {
        assert!(pam_rule_present(
            "auth required pam_env.so\nauth [success=done default=ignore] pam_peekin.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n"
        ));
        assert!(!pam_rule_present("# auth sufficient pam_peekin.so\n"));
        assert!(!pam_rule_present(
            "auth required pam_echo.so pam_peekin.so\n"
        ));
        assert!(!pam_rule_present("auth sufficient pam_peekin.so debug\n"));
        assert!(!pam_rule_present("auth sufficient pam_peekin.so\nauth requisite pam_deny.so\nauth sufficient pam_unix.so\nauth required pam_deny.so\n"));
    }

    #[test]
    fn authselect_readiness_requires_the_shared_stacks_and_supported_services() {
        let sudo = "#%PAM-1.0\nauth include system-auth\n";
        let gdm = "auth [success=done ignore=ignore default=bad] pam_selinux_permit.so\nauth substack password-auth\nauth optional pam_gnome_keyring.so\nauth include postlogin\n";
        assert!(authselect_services(sudo, gdm));
        assert!(!authselect_services(
            "auth requisite pam_deny.so\nauth include system-auth",
            gdm
        ));
        assert!(pam_rule_present("auth required pam_env.so\nauth sufficient pam_fprintd.so\nauth [success=done default=ignore] pam_peekin.so\nauth sufficient pam_unix.so nullok\nauth required pam_deny.so\n"));
    }

    #[test]
    fn attempts_are_parsed_and_unreadable_state_is_an_error() {
        let paused =
            parse_attempts(r#"{"attempts":{"failures":5,"limit":5,"paused_until":1790000000}}"#)
                .unwrap();
        assert_eq!(paused.paused_until, Some(1_790_000_000));
        let text = attempts_readiness(paused, "14:32");
        assert!(matches!(text, ReadinessValue::Blocked(_)));
        assert!(text.text().contains("until 14:32"), "{text:?}");
        let calm =
            parse_attempts(r#"{"attempts":{"failures":2,"limit":5,"paused_until":null}}"#).unwrap();
        assert_eq!(
            attempts_readiness(calm, ""),
            ReadinessValue::Ready("2 recent failed attempts; pauses after 5".into())
        );
        let off =
            parse_attempts(r#"{"attempts":{"failures":0,"limit":0,"paused_until":null}}"#).unwrap();
        assert_eq!(
            attempts_readiness(off, ""),
            ReadinessValue::Ready("no recent failed attempts; no limit".into())
        );
        assert!(
            parse_attempts(r#"{"attempts":{"error":"permission denied"}}"#)
                .unwrap_err()
                .contains("permission denied")
        );
        assert!(parse_attempts(r#"{"version":1}"#).is_err());
        assert!(parse_attempts(r#"{"attempts":{"failures":1,"limit":5}}"#).is_err());
        assert!(
            parse_attempts(r#"{"attempts":{"failures":-1,"limit":5,"paused_until":null}}"#)
                .is_err()
        );
    }

    #[test]
    fn presets_round_trip_and_anything_else_is_custom() {
        for preset in [Preset::Fast, Preset::Balanced, Preset::Secure] {
            assert_eq!(Preset::of(preset.values().unwrap()), preset);
        }
        let mut custom = Preset::Secure.values().unwrap();
        custom.min_similarity = 0.5;
        assert_eq!(Preset::of(custom), Preset::Custom);
        // The shipped defaults are "Balanced", so nothing changes on upgrade.
        let shipped = Recognition {
            movement_challenge: true,
            require_movement_without_ir: true,
            min_similarity: 0.363,
            personal_threshold: false,
        };
        assert_eq!(Preset::of(shipped), Preset::Balanced);
        assert!(Preset::Custom.values().is_none());
    }

    #[test]
    fn history_entries_have_readable_names() {
        use peekin_core::activity::Outcome;
        assert_eq!(service_name("lock_screen"), "Lock screen");
        assert_eq!(service_name("sudo"), "sudo");
        assert_eq!(service_name("cockpit"), "cockpit");
        assert_eq!(
            outcome_text(Outcome::ChallengeFailed),
            "Head movement not followed"
        );
    }

    #[test]
    fn snapshots_reply_is_checked_before_use() {
        let ok = r#"{"version":1,"user":"alice","snapshots":[{"time":5,"jpeg":"Zm9v"}]}"#;
        assert_eq!(
            parse_snapshots(ok, "alice").unwrap(),
            vec![(5, "Zm9v".to_string())]
        );
        assert!(parse_snapshots(ok, "bob").is_err());
        assert!(parse_snapshots(r#"{"version":1,"user":"alice"}"#, "alice").is_err());
        assert!(parse_snapshots(
            r#"{"version":1,"user":"alice","snapshots":[{"time":5}]}"#,
            "alice"
        )
        .is_err());
        assert!(Operation::ClearingSnapshots.is_write() && !Operation::LoadingSnapshots.is_write());
    }

    #[test]
    fn personal_threshold_is_read_when_present() {
        assert_eq!(
            parse_personal_threshold(r#"{"personal_threshold":0.466}"#),
            Some(0.466)
        );
        assert_eq!(
            parse_personal_threshold(r#"{"personal_threshold":null}"#),
            None
        );
        assert_eq!(parse_personal_threshold(r#"{"version":1}"#), None);
        assert_eq!(parse_personal_threshold("not json"), None);
    }

    #[test]
    fn metadata_errors_never_become_no_models() {
        assert!(parse_model_metadata("not json", "alice").is_err());
        assert!(
            parse_model_metadata(r#"{"version":1,"user":"mallory","models":[]}"#, "alice").is_err()
        );
        let (models, usable) =
            parse_model_metadata(r#"{"version":1,"user":"alice","models":[]}"#, "alice").unwrap();
        assert!(models.is_empty());
        assert_eq!(usable, 0);
    }
}
