//! `peekin add [label]`. Enrollment waits for auto-exposure to settle and takes
//! several spaced samples; early frames matched later sessions poorly.

use crate::compare::{classify_frame, FrameClass};
use crate::models::FaceModel;
use crate::source::FaceSource;
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EnrollError {
    #[error("Camera saw only black frames - is the camera covered or the IR emitter off?")]
    OnlyBlackFrames,
    #[error("Every frame was too dark; add light or adjust dark_threshold")]
    AllFramesDark,
    #[error("No face in view; enrollment stopped")]
    NoFace,
    #[error("More than one face in view; enrollment stopped")]
    MultipleFaces,
    #[error("Face samples were inconsistent; keep the same person in view and retry")]
    InconsistentFace,
    #[error("Only {got} of {wanted} face samples captured, please hold still and retry")]
    NotEnoughSamples { got: usize, wanted: usize },
    #[error("Camera error: {0}")]
    Camera(String),
}

/// More models than this slow recognition down.
pub const ENROLL_SLOWDOWN_WARN_COUNT: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EnrollParams {
    pub timeout: Duration,
    pub dark_threshold: f64,
    pub settle: Duration,
    pub spacing: Duration,
    pub min_detect_score: f32,
    pub samples: usize,
    pub min_face_width: f32,
    pub max_face_aspect: f32,
    pub min_sample_similarity: f32,
    pub min_sharpness: f32,
    pub max_pose_imbalance: f32,
}

impl EnrollParams {
    pub fn with_dark_threshold(dark_threshold: f64) -> Self {
        Self {
            timeout: Duration::from_secs(10),
            dark_threshold,
            settle: Duration::from_millis(1500),
            spacing: Duration::from_millis(250),
            min_detect_score: 0.7,
            samples: 5,
            min_face_width: 80.0,
            max_face_aspect: 1.8,
            min_sample_similarity: 0.65,
            min_sharpness: 25.0,
            max_pose_imbalance: 0.25,
        }
    }
}

pub fn enroll<S: FaceSource>(
    source: &mut S,
    params: &EnrollParams,
) -> Result<Vec<Vec<f32>>, EnrollError> {
    enroll_with_progress(source, params, |_| {})
}

pub fn enroll_with_progress<S: FaceSource>(
    source: &mut S,
    params: &EnrollParams,
    mut on_sample: impl FnMut(usize),
) -> Result<Vec<Vec<f32>>, EnrollError> {
    enroll_with_feedback(source, params, |feedback| {
        if let EnrollFeedback::Sample(n, _) = feedback {
            on_sample(n);
        }
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollFeedback {
    Settling,
    Covered,
    TooDark,
    NoFace,
    MultipleFaces,
    LowConfidence,
    TooSmall,
    Blurry,
    Pose,
    Inconsistent,
    Sample(usize, usize),
}

pub fn enroll_with_feedback<S: FaceSource>(
    source: &mut S,
    params: &EnrollParams,
    mut on_feedback: impl FnMut(EnrollFeedback),
) -> Result<Vec<Vec<f32>>, EnrollError> {
    let mut samples: Vec<Vec<f32>> = Vec::new();
    let (mut valid, mut dark) = (0u64, 0u64);
    let mut last_sample: Option<Duration> = None;
    loop {
        let stats = source.next_frame().map_err(|e| EnrollError::Camera(e.0))?;
        if stats.at > params.timeout {
            break;
        }
        match classify_frame(&stats.hist, params.dark_threshold) {
            FrameClass::Black => {
                on_feedback(EnrollFeedback::Covered);
                continue;
            }
            FrameClass::Dark { .. } => {
                valid += 1;
                dark += 1;
                on_feedback(EnrollFeedback::TooDark);
                continue;
            }
            FrameClass::Scan { .. } => valid += 1,
        }
        if stats.at < params.settle || last_sample.is_some_and(|t| stats.at - t < params.spacing) {
            on_feedback(EnrollFeedback::Settling);
            continue;
        }
        let faces = source
            .analyze_for_enrollment()
            .map_err(|e| EnrollError::Camera(e.0))?;
        match faces.as_slice() {
            [] => on_feedback(EnrollFeedback::NoFace),
            [face] if face.score >= params.min_detect_score => {
                let aspect = (face.rect[2] / face.rect[3].max(1.0))
                    .max(face.rect[3] / face.rect[2].max(1.0));
                if face.rect[2] < params.min_face_width
                    || face.rect[3] < params.min_face_width
                    || aspect > params.max_face_aspect
                {
                    on_feedback(EnrollFeedback::TooSmall);
                    continue;
                }
                if face.sharpness.is_some_and(|v| v < params.min_sharpness) {
                    on_feedback(EnrollFeedback::Blurry);
                    continue;
                }
                if face
                    .pose_imbalance
                    .is_some_and(|v| v > params.max_pose_imbalance)
                {
                    on_feedback(EnrollFeedback::Pose);
                    continue;
                }
                if samples.iter().any(|sample| {
                    crate::matcher::cosine_similarity(sample, &face.embedding)
                        < params.min_sample_similarity
                }) {
                    on_feedback(EnrollFeedback::Inconsistent);
                    return Err(EnrollError::InconsistentFace);
                }
                samples.push(face.embedding.clone());
                last_sample = Some(stats.at);
                on_feedback(EnrollFeedback::Sample(samples.len(), params.samples));
                if samples.len() == params.samples {
                    return Ok(samples);
                }
            }
            [_] => on_feedback(EnrollFeedback::LowConfidence),
            _ => {
                on_feedback(EnrollFeedback::MultipleFaces);
                return Err(EnrollError::MultipleFaces);
            }
        }
    }
    Err(if valid == 0 {
        EnrollError::OnlyBlackFrames
    } else if valid == dark {
        EnrollError::AllFramesDark
    } else if samples.is_empty() {
        EnrollError::NoFace
    } else {
        EnrollError::NotEnoughSamples {
            got: samples.len(),
            wanted: params.samples,
        }
    })
}

/// Label: the given one, else the `-y` default `"Model #<next_id>"`, else the
/// prompt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LabelSource {
    Arg(String),
    Default,
    Prompt(String),
}

pub fn pick_label(source: LabelSource, next_id: i64) -> String {
    let raw = match source {
        LabelSource::Arg(l) => l,
        LabelSource::Default => format!("Model #{next_id}"),
        // Empty prompt input keeps the default.
        LabelSource::Prompt(input) if input.is_empty() => format!("Model #{next_id}"),
        LabelSource::Prompt(input) => input,
    };
    FaceModel::sanitise_label(&raw)
}

pub fn slowdown_warning_applies(existing_models: usize) -> bool {
    existing_models > ENROLL_SLOWDOWN_WARN_COUNT
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::fake::{face, Scripted, BLACK, BRIGHT, DARK};
    use crate::source::Face;

    fn params() -> EnrollParams {
        EnrollParams {
            samples: 3,
            ..EnrollParams::with_dark_threshold(60.0)
        }
    }

    fn bright_every(
        step_ms: u64,
        until_ms: u64,
        faces: Vec<Face>,
    ) -> Vec<(u64, [f64; 8], Vec<Face>)> {
        (0..=until_ms / step_ms)
            .map(|i| (i * step_ms, BRIGHT, faces.clone()))
            .collect()
    }

    #[test]
    fn samples_only_after_settle_and_spaced() {
        let frames = bright_every(100, 3000, vec![face(0.9, &[1.0, 0.0])]);
        let mut src = Scripted::new(frames);
        let samples = enroll(&mut src, &params()).unwrap();
        assert_eq!(samples.len(), 3);
        // Taken at 1500, 1800 and 2100 ms: 3 analyses, none during settle.
        assert_eq!(src.analyzed, 3);
    }

    #[test]
    fn progress_is_reported_per_sample() {
        let mut src = Scripted::new(bright_every(100, 3000, vec![face(0.9, &[1.0, 0.0])]));
        let mut seen = Vec::new();
        enroll_with_progress(&mut src, &params(), |n| seen.push(n)).unwrap();
        assert_eq!(seen, [1, 2, 3]);
    }

    #[test]
    fn low_confidence_faces_are_skipped() {
        let mut frames = bright_every(100, 3000, vec![face(0.5, &[1.0, 0.0])]);
        frames.push((20_000, BRIGHT, vec![]));
        let mut src = Scripted::new(frames);
        assert_eq!(enroll(&mut src, &params()), Err(EnrollError::NoFace));
    }

    #[test]
    fn multiple_faces_abort() {
        let mut src = Scripted::new(bright_every(
            100,
            3000,
            vec![face(0.9, &[1.0]), face(0.9, &[0.5])],
        ));
        assert_eq!(enroll(&mut src, &params()), Err(EnrollError::MultipleFaces));
    }

    #[test]
    fn rejects_blurry_bad_pose_and_identity_changes() {
        let mut blurry = face(0.9, &[1.0, 0.0]);
        blurry.sharpness = Some(1.0);
        let mut posed = face(0.9, &[1.0, 0.0]);
        posed.pose_imbalance = Some(0.8);
        let mut frames = bright_every(100, 1800, vec![blurry]);
        frames.extend(
            bright_every(100, 1800, vec![posed])
                .into_iter()
                .map(|(ms, h, f)| (ms + 1900, h, f)),
        );
        frames.push((20_000, BRIGHT, vec![]));
        assert_eq!(
            enroll(&mut Scripted::new(frames), &params()),
            Err(EnrollError::NoFace)
        );

        let mut frames = bright_every(100, 1500, vec![face(0.9, &[1.0, 0.0])]);
        frames.extend(
            bright_every(100, 2000, vec![face(0.9, &[0.0, 1.0])])
                .into_iter()
                .map(|(ms, h, f)| (ms + 1600, h, f)),
        );
        assert_eq!(
            enroll(&mut Scripted::new(frames), &params()),
            Err(EnrollError::InconsistentFace)
        );
    }

    #[test]
    fn failure_diagnosis() {
        let only = |hist| {
            Scripted::new(vec![
                (100, hist, vec![]),
                (2000, hist, vec![]),
                (20_000, hist, vec![]),
            ])
        };
        assert_eq!(
            enroll(&mut only(BLACK), &params()),
            Err(EnrollError::OnlyBlackFrames)
        );
        assert_eq!(
            enroll(&mut only(DARK), &params()),
            Err(EnrollError::AllFramesDark)
        );
        assert_eq!(
            enroll(&mut only(BRIGHT), &params()),
            Err(EnrollError::NoFace)
        );
    }

    #[test]
    fn too_few_samples_before_timeout() {
        let mut frames = bright_every(100, 1600, vec![face(0.9, &[1.0])]);
        frames.push((20_000, BRIGHT, vec![]));
        let mut src = Scripted::new(frames);
        assert_eq!(
            enroll(&mut src, &params()),
            Err(EnrollError::NotEnoughSamples { got: 1, wanted: 3 })
        );
    }

    #[test]
    fn label_precedence() {
        assert_eq!(pick_label(LabelSource::Arg("work".into()), 3), "work");
        assert_eq!(pick_label(LabelSource::Default, 3), "Model #3");
        assert_eq!(pick_label(LabelSource::Prompt("".into()), 3), "Model #3");
        assert_eq!(pick_label(LabelSource::Prompt("mine".into()), 3), "mine");
        assert_eq!(pick_label(LabelSource::Arg("a,b".into()), 0), "ab");
    }

    #[test]
    fn slowdown_warning_threshold() {
        assert!(!slowdown_warning_applies(3));
        assert!(slowdown_warning_applies(4));
    }
}
