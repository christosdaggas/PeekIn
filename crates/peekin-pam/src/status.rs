//! Maps how `peekin-compare` ended onto a PAM result and messages.

use crate::CompareError;
use peekin_core::i18n::{tr, tr_args};

/// PAM return codes (`security/pam_modules.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(i32)]
pub enum PamCode {
    Success = 0,
    AuthErr = 7,
    AuthinfoUnavail = 9,
    Ignore = 25,
    SystemErr = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChildEnd {
    Exited(u8),
    Signaled { signal: i32, name: &'static str },
}

/// PAM code plus the conversation and syslog lines to emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthDecision {
    pub pam_code: PamCode,
    pub conv_message: Option<ConvMessage>,
    pub syslog: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConvMessage {
    pub is_error: bool,
    pub text: String,
}

pub fn compare_error_decision(end: ChildEnd) -> AuthDecision {
    let auth_err = |syslog: String, conv: Option<ConvMessage>| AuthDecision {
        pam_code: PamCode::AuthErr,
        conv_message: conv,
        syslog,
    };
    let err_conv = |text: String| {
        Some(ConvMessage {
            is_error: true,
            text,
        })
    };
    // Every failure after a face prompt says why, so the password prompt that follows is not a mystery.
    match end {
        ChildEnd::Exited(code) => match CompareError::from_exit_code(code) {
            Some(CompareError::NoFaceModel) => {
                auth_err("Not authenticated: no face model enrolled".into(), None)
            }
            Some(CompareError::TimeoutReached) => auth_err(
                "Not authenticated: no matching face before the time limit".into(),
                err_conv(tr("Face not recognised in time; use your password")),
            ),
            Some(CompareError::Abort) => auth_err(
                "Not authenticated: the recognition worker stopped".into(),
                err_conv(tr(
                    "Face authentication is unavailable (see the system log); use your password",
                )),
            ),
            Some(CompareError::TooDark) => auth_err(
                "Not authenticated: the camera image was too dark".into(),
                err_conv(tr("Camera image too dark; use your password")),
            ),
            Some(CompareError::InvalidDevice) => auth_err(
                "Not authenticated: the camera could not be opened".into(),
                err_conv(tr("The camera could not be opened; use your password")),
            ),
            Some(CompareError::Rubberstamp) => auth_err(
                "Not authenticated: rubber stamps are not supported".into(),
                None,
            ),
            Some(CompareError::ChallengeFailed) => auth_err(
                "Not authenticated: the head movement did not match".into(),
                err_conv(tr(
                    "Head movement did not follow the instructions; use your password",
                )),
            ),
            Some(CompareError::NoFaceSeen) => auth_err(
                "Not authenticated: nobody in front of the camera".into(),
                Some(ConvMessage {
                    is_error: false,
                    text: tr("No face seen; use your password"),
                }),
            ),
            None => auth_err(
                format!("Not authenticated: unknown worker exit code {code}"),
                err_conv(tr_args("Unknown error: {code}", &[("code", &code)])),
            ),
        },
        ChildEnd::Signaled { signal, name } => auth_err(
            format!("Not authenticated: the worker was killed by {name} ({signal})"),
            err_conv(tr(
                "Face authentication failed unexpectedly; use your password",
            )),
        ),
    }
}

pub fn status_decision(end: ChildEnd, username: &str, no_confirmation: bool) -> AuthDecision {
    match end {
        ChildEnd::Exited(0) => {
            let conv_message = if no_confirmation {
                None
            } else {
                Some(ConvMessage {
                    is_error: false,
                    text: tr_args("Face recognised: {username}", &[("username", &username)]),
                })
            };
            AuthDecision {
                pam_code: PamCode::Success,
                conv_message,
                syslog: "Face recognised; authenticated".into(),
            }
        }
        other => compare_error_decision(other),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn success_with_and_without_confirmation() {
        let d = status_decision(ChildEnd::Exited(0), "alice", false);
        assert_eq!(d.pam_code, PamCode::Success);
        assert_eq!(d.conv_message.unwrap().text, "Face recognised: alice");
        assert_eq!(d.syslog, "Face recognised; authenticated");
        let d2 = status_decision(ChildEnd::Exited(0), "alice", true);
        assert_eq!(d2.pam_code, PamCode::Success);
        assert_eq!(d2.conv_message, None);
    }

    #[test]
    fn timeout_reports_to_user_and_syslog() {
        let d = status_decision(ChildEnd::Exited(11), "alice", false);
        assert_eq!(d.pam_code, PamCode::AuthErr);
        let conv = d.conv_message.unwrap();
        assert!(conv.is_error);
        assert_eq!(conv.text, "Face not recognised in time; use your password");
        assert_eq!(
            d.syslog,
            "Not authenticated: no matching face before the time limit"
        );
    }

    #[test]
    fn dark_reports_image_message() {
        let d = status_decision(ChildEnd::Exited(13), "alice", false);
        assert_eq!(
            d.conv_message.unwrap().text,
            "Camera image too dark; use your password"
        );
        assert_eq!(d.syslog, "Not authenticated: the camera image was too dark");
    }

    #[test]
    fn only_a_missing_model_is_silent() {
        let d = status_decision(ChildEnd::Exited(10), "alice", false);
        assert_eq!(d.pam_code, PamCode::AuthErr);
        assert_eq!(d.conv_message, None);
        assert_eq!(d.syslog, "Not authenticated: no face model enrolled");
        for (code, log, text) in [
            (
                12u8,
                "Not authenticated: the recognition worker stopped",
                "Face authentication is unavailable (see the system log); use your password",
            ),
            (
                14u8,
                "Not authenticated: the camera could not be opened",
                "The camera could not be opened; use your password",
            ),
            (
                16u8,
                "Not authenticated: the head movement did not match",
                "Head movement did not follow the instructions; use your password",
            ),
        ] {
            let d = status_decision(ChildEnd::Exited(code), "alice", false);
            assert_eq!(d.pam_code, PamCode::AuthErr);
            let conv = d.conv_message.unwrap();
            assert!(conv.is_error);
            assert_eq!(conv.text, text);
            assert_eq!(d.syslog, log);
        }
    }

    #[test]
    fn unknown_exit_code() {
        let d = status_decision(ChildEnd::Exited(99), "alice", false);
        assert_eq!(d.pam_code, PamCode::AuthErr);
        assert!(d.syslog.contains("99"));
        assert!(d.conv_message.unwrap().text.contains("99"));
    }

    #[test]
    fn signal_death_logged() {
        let d = status_decision(
            ChildEnd::Signaled {
                signal: 9,
                name: "SIGKILL",
            },
            "alice",
            false,
        );
        assert_eq!(d.pam_code, PamCode::AuthErr);
        assert_eq!(
            d.syslog,
            "Not authenticated: the worker was killed by SIGKILL (9)"
        );
        assert!(d.conv_message.unwrap().is_error);
    }
}
