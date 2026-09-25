//! `peekin-compare [--config-dir DIR] [--data-dir DIR] USER`: spawned by pam_peekin.so to recognise USER.
//! Exit codes: 0 match, 10 no face model, 11 timeout, 12 abort, 13 too dark, 14 camera unavailable,
//! 16 movement challenge failed, 17 no face seen. Diagnostics go to stderr (the system log).

use peekin_core::cameras;
use peekin_core::compare::{
    verify_with_mode, ChallengeMode, CompareExit, VerifyOutcome, VerifyParams,
};
use peekin_core::lockout;
use peekin_core::lowlight::{LowLightNotice, LOW_LIGHT_SIGNAL, MATCHED_MODEL_PREFIX};
use peekin_core::models::{load_user_models, usable_embeddings, ModelError};
use peekin_core::paths::validate_username;
use peekin_core::snapshots;
use peekin_core::source::{Face, FaceSource, FrameStats, SourceError};
use peekin_core::{PeekinConfig, PeekinPaths};
use peekin_vision::{OpenCvFaceSource, OpenError};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant};

const USAGE: &str = "usage: peekin-compare [--config-dir DIR] [--data-dir DIR] --challenge left,right,left|none -- USER";

fn exit(code: CompareExit) -> ExitCode {
    ExitCode::from(code as u8)
}

fn parse_args_from(
    mut args: impl ExactSizeIterator<Item = String>,
) -> Option<(PathBuf, PathBuf, ChallengeMode, String)> {
    let mut config_dir = PathBuf::from("/etc/peekin");
    let mut data_dir = PathBuf::from("/usr/share/peekin");
    let mut user = None;
    let mut challenge = None;
    let mut challenge_seen = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config-dir" => config_dir = args.next()?.into(),
            "--data-dir" => data_dir = args.next()?.into(),
            "--challenge" => {
                if challenge_seen {
                    return None;
                }
                challenge_seen = true;
                challenge = Some(ChallengeMode::parse(&args.next()?)?);
            }
            "--" => user = Some(args.next()?),
            _ if arg.starts_with('-') => return None,
            _ => user = Some(arg),
        }
        if user.is_some() && args.len() > 0 {
            return None;
        }
    }
    Some((config_dir, data_dir, challenge?, user?))
}

fn main() -> ExitCode {
    if let Err(error) = peekin_core::process::disable_dumpability() {
        eprintln!("cannot disable process dumpability: {error}");
        return exit(CompareExit::Abort);
    }
    let started = Instant::now();
    let Some((config_dir, data_dir, challenge, user)) = parse_args_from(std::env::args().skip(1))
    else {
        eprintln!("{USAGE}");
        return exit(CompareExit::Abort);
    };
    if let Err(e) = validate_username(&user) {
        eprintln!("{e}");
        return exit(CompareExit::Abort);
    }
    let paths = PeekinPaths::from_dirs(config_dir, data_dir);
    let config = match PeekinConfig::load(&paths.config_file_path()) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("{e}");
            return exit(CompareExit::Abort);
        }
    };
    for warning in config.invalid_values() {
        eprintln!("config: {warning}");
    }
    if !config.security_errors().is_empty() {
        eprintln!("security-critical configuration is invalid; refusing face authentication");
        return exit(CompareExit::Abort);
    }
    if config.rubberstamps_enabled() {
        eprintln!(
            "rubberstamps are enabled but not supported by this version; \
             refusing face authentication rather than skipping them"
        );
        return exit(CompareExit::Abort);
    }
    if config.save_successful_snapshots() {
        eprintln!("[snapshots] save_successful is not supported, ignoring it");
    }

    let models = match load_user_models(paths.user_models_dir(), &user) {
        Ok(m) => m,
        Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => {
            return exit(CompareExit::NoFaceModel)
        }
        Err(e) => {
            eprintln!("cannot load face models for {user}: {e}");
            return exit(CompareExit::Abort);
        }
    };
    let known = usable_embeddings(&models);
    if known.is_empty() {
        if !models.is_empty() {
            eprintln!("{user} only has legacy dlib face models; re-enroll with `peekin add`");
        }
        return exit(CompareExit::NoFaceModel);
    }

    let mut source = match OpenCvFaceSource::open(&config, &paths) {
        Ok(s) => s,
        Err(OpenError::NoDevice(reason)) => {
            if config.warn_no_device() {
                eprintln!("{}", OpenError::NoDevice(reason));
            }
            return exit(CompareExit::InvalidDevice);
        }
        Err(e @ OpenError::Camera(..)) => {
            eprintln!("{e}");
            return exit(CompareExit::InvalidDevice);
        }
        Err(e) => {
            eprintln!("{e}");
            return exit(CompareExit::Abort);
        }
    };
    let camera = cameras::kind_of(source.device());
    if !challenge.satisfies(config.movement_required(camera)) {
        eprintln!(
            "--challenge none, but the settings require the head-movement check with camera \
             {} (settings or camera changed during the attempt?); refusing face authentication",
            source.device().display()
        );
        return exit(CompareExit::Abort);
    }
    for warning in source.warnings() {
        eprintln!("{warning}");
    }
    if config.end_report() || config.device_is_automatic() {
        eprintln!("camera {}", source.device().display());
    }

    let params = VerifyParams::authentication(
        Duration::from_secs(config.video_timeout_secs() as u64),
        config.dark_threshold(),
        config.effective_min_similarity(&known),
    );
    // Ask PAM (root) to raise the backlight in a dark scene; a failed write is harmless.
    let brighten = config.brighten_screen() && camera == Some(cameras::CameraKind::Colour);
    let mut frames = FaceFrames {
        source: &mut source,
        keep: config.save_failed_snapshots(),
        last: None,
    };
    let mut watched = LowLightNotice::new(&mut frames, brighten, || {
        let mut out = std::io::stdout();
        let _ = writeln!(out, "{LOW_LIGHT_SIGNAL}").and_then(|()| out.flush());
    });
    let outcome = match verify_with_mode(&mut watched, &known, &params, challenge) {
        Ok(o) => o,
        Err(e) => {
            eprintln!("{e}");
            return exit(CompareExit::InvalidDevice);
        }
    };

    match outcome {
        VerifyOutcome::Matched {
            model,
            similarity,
            at,
            frames,
        } => {
            eprintln!(
                "matched model {} ({:?}) with similarity {similarity:.3} after {} ms, {frames} frames",
                models[model].id,
                models[model].label,
                at.as_millis()
            );
            let mut out = std::io::stdout();
            let _ = writeln!(out, "{MATCHED_MODEL_PREFIX}{}", models[model].id)
                .and_then(|()| out.flush());
        }
        VerifyOutcome::TimedOut {
            all_dark: true,
            frames,
            ..
        } => eprintln!("all {frames} frames were too dark (dark_threshold); no face could be checked"),
        VerifyOutcome::TimedOut {
            challenge_failed: true,
            frames,
            ..
        } => eprintln!(
            "movement challenge failed (wrong order, missed step, too slow, or unclear face) after {frames} frames"
        ),
        VerifyOutcome::TimedOut {
            best_similarity,
            frames,
            black,
            dark,
            ..
        } => eprintln!(
            "no match within {}s: best similarity {}, {frames} frames ({dark} dark, {black} black)",
            params.timeout.as_secs(),
            best_similarity.map_or("none (no face seen)".into(), |s| format!("{s:.3}")),
        ),
    }
    let face_seen = matches!(
        outcome,
        VerifyOutcome::TimedOut {
            best_similarity: Some(_),
            ..
        } | VerifyOutcome::TimedOut {
            challenge_failed: true,
            ..
        }
    );
    if let (true, Some(image)) = (face_seen, frames.last.take()) {
        save_snapshot(&config, &user, &image);
    }
    if config.end_report() {
        let (w, h) = source.frame_size();
        let t = source.timings();
        eprintln!(
            "report: total={}ms models={}ms camera={}ms first_frame={}ms detection={}ms/{} recognition={}ms/{} capture={w}x{h} min_similarity={}",
            started.elapsed().as_millis(),
            t.models.as_millis(), t.camera.as_millis(), t.first_frame.unwrap_or_default().as_millis(),
            t.detection.as_millis(), t.detections, t.recognition.as_millis(), t.recognitions,
            params.min_similarity
        );
    }
    exit(outcome.exit())
}

/// Keeps (when `keep`) the last analysed frame with a face: the photo of a failed attempt.
struct FaceFrames<'a> {
    source: &'a mut OpenCvFaceSource,
    keep: bool,
    last: Option<opencv::core::Mat>,
}

impl FaceSource for FaceFrames<'_> {
    fn next_frame(&mut self) -> Result<FrameStats, SourceError> {
        self.source.next_frame()
    }
    fn analyze(&mut self) -> Result<Vec<Face>, SourceError> {
        let faces = self.source.analyze()?;
        if self.keep && !faces.is_empty() {
            self.last = self.source.last_image();
        }
        Ok(faces)
    }
}

fn save_snapshot(config: &PeekinConfig, user: &str, image: &opencv::core::Mat) {
    let saved = peekin_vision::jpeg(image).and_then(|bytes| {
        snapshots::save(
            Path::new(snapshots::SNAPSHOT_DIR),
            user,
            lockout::now(),
            &bytes,
            config.snapshot_keep(),
        )
        .map_err(|e| e.to_string())
    });
    match saved {
        Ok(path) => eprintln!("saved a photo of the failed attempt: {}", path.display()),
        Err(error) => eprintln!("cannot save a photo of the failed attempt: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parsed(args: &[&str]) -> Option<(PathBuf, PathBuf, ChallengeMode, String)> {
        parse_args_from(
            args.iter()
                .map(|s| s.to_string())
                .collect::<Vec<_>>()
                .into_iter(),
        )
    }
    #[test]
    fn cannot_compare_without_a_valid_unique_challenge() {
        assert!(parsed(&["--", "alice"]).is_none());
        assert!(parsed(&["--challenge", "bogus", "--", "alice"]).is_none());
        assert!(parsed(&["--challenge", "left-right", "--", "alice"]).is_none());
        assert!(parsed(&["--challenge", "left,right", "--", "alice"]).is_none());
        assert!(parsed(&[
            "--challenge",
            "bogus",
            "--challenge",
            "left,right,left",
            "--",
            "alice"
        ])
        .is_none());
        assert!(parsed(&[
            "--challenge",
            "left,right,left",
            "--challenge",
            "right,left,right",
            "--",
            "alice"
        ])
        .is_none());
        let (.., challenge, user) =
            parsed(&["--challenge", "right,left,right", "--", "alice"]).unwrap();
        assert_eq!(user, "alice");
        let ChallengeMode::Movement(order) = challenge else {
            panic!("{challenge:?}")
        };
        assert_eq!(
            order.turns(),
            [
                peekin_core::compare::Turn::Right,
                peekin_core::compare::Turn::Left,
                peekin_core::compare::Turn::Right
            ]
        );
        let (.., challenge, _) = parsed(&["--challenge", "none", "--", "alice"]).unwrap();
        assert_eq!(challenge, ChallengeMode::Passive);
        assert!(parsed(&["--challenge", "", "--", "alice"]).is_none());
    }
}
