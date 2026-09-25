//! Camera and face model boundary; `peekin-vision` implements [`FaceSource`].

use std::time::Duration;
use thiserror::Error;

/// One frame: time since the source opened and its 8-bin histogram.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FrameStats {
    pub at: Duration,
    pub hist: [f64; 8],
}

#[derive(Debug, Clone, PartialEq)]
pub struct Face {
    pub score: f32,
    /// `[x, y, width, height]` in the analysed image.
    pub rect: [f32; 4],
    pub embedding: Vec<f32>,
    /// Variance of Laplacian; higher is sharper.
    pub sharpness: Option<f32>,
    /// Landmark asymmetry; lower is better.
    pub pose_imbalance: Option<f32>,
    /// Nose offset from the eye midpoint over eye separation; `None` when
    /// unmeasurable, which never counts as a turn.
    pub yaw: Option<f32>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DetectedFace {
    pub score: f32,
    pub rect: [f32; 4],
}

#[derive(Debug, Error)]
#[error("{0}")]
pub struct SourceError(pub String);

pub trait FaceSource {
    fn next_frame(&mut self) -> Result<FrameStats, SourceError>;
    /// Detect and embed all faces in the last frame.
    fn analyze(&mut self) -> Result<Vec<Face>, SourceError>;
    fn analyze_for_enrollment(&mut self) -> Result<Vec<Face>, SourceError> {
        self.analyze()
    }
    /// Detection only, for previews: no embeddings.
    fn detect(&mut self) -> Result<Vec<DetectedFace>, SourceError> {
        Ok(self
            .analyze()?
            .into_iter()
            .map(|f| DetectedFace {
                score: f.score,
                rect: f.rect,
            })
            .collect())
    }
}

#[cfg(test)]
pub(crate) mod fake {
    use super::*;
    use std::collections::VecDeque;

    pub const BLACK: [f64; 8] = [0.0; 8];
    pub const DARK: [f64; 8] = [90.0, 2.0, 2.0, 2.0, 1.0, 1.0, 1.0, 1.0];
    pub const BRIGHT: [f64; 8] = [5.0, 10.0, 20.0, 25.0, 20.0, 10.0, 5.0, 5.0];

    /// Scripted frames: (timestamp ms, histogram, faces seen by `analyze`).
    pub struct Scripted {
        frames: VecDeque<(u64, [f64; 8], Vec<Face>)>,
        current: Vec<Face>,
        pub analyzed: usize,
    }

    impl Scripted {
        pub fn new(frames: Vec<(u64, [f64; 8], Vec<Face>)>) -> Self {
            Self {
                frames: frames.into(),
                current: Vec::new(),
                analyzed: 0,
            }
        }
    }

    impl FaceSource for Scripted {
        fn next_frame(&mut self) -> Result<FrameStats, SourceError> {
            let (ms, hist, faces) = self
                .frames
                .pop_front()
                .ok_or_else(|| SourceError("camera read failed".into()))?;
            self.current = faces;
            Ok(FrameStats {
                at: Duration::from_millis(ms),
                hist,
            })
        }

        fn analyze(&mut self) -> Result<Vec<Face>, SourceError> {
            self.analyzed += 1;
            Ok(self.current.clone())
        }
    }

    pub fn face(score: f32, embedding: &[f32]) -> Face {
        Face {
            score,
            rect: [20.0, 20.0, 160.0, 160.0],
            embedding: embedding.to_vec(),
            sharpness: Some(100.0),
            pose_imbalance: Some(0.0),
            yaw: Some(0.0),
        }
    }
}
