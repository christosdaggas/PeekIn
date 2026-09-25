//! Detect a dark scene at the start of a scan so the PAM module can raise the
//! backlight. The unprivileged worker only prints [`LOW_LIGHT_SIGNAL`]. Colour
//! cameras only; IR frames look dark anyway.

use crate::source::{Face, FaceSource, FrameStats, SourceError};

pub const LOW_LIGHT_SIGNAL: &str = "low-light";
/// Prefix of the worker line naming the matched model, e.g. `matched-model 3`.
pub const MATCHED_MODEL_PREFIX: &str = "matched-model ";
/// Share (percent) of pixels in the darkest histogram bin that marks a frame
/// dark. Below `dark_threshold`, so dim but usable scenes get light too.
pub const LOW_LIGHT_DARKNESS: f64 = 40.0;
/// Frames checked at the start of a scan, and how many must be dark.
pub const LOW_LIGHT_WINDOW: u32 = 10;
pub const LOW_LIGHT_FRAMES: u32 = 3;

/// Counts dark frames at the start of a scan; fires at most once.
#[derive(Debug, Default)]
pub struct LowLightWatch {
    seen: u32,
    dark: u32,
    fired: bool,
}

impl LowLightWatch {
    /// True once, when the scene has turned out to be dark.
    pub fn observe(&mut self, hist: &[f64; 8]) -> bool {
        if self.fired || self.seen >= LOW_LIGHT_WINDOW {
            return false;
        }
        self.seen += 1;
        let total: f64 = hist.iter().sum();
        if total <= 0.0 || hist[0] / total * 100.0 >= LOW_LIGHT_DARKNESS {
            self.dark += 1;
        }
        self.fired = self.dark >= LOW_LIGHT_FRAMES;
        self.fired
    }
}

/// A [`FaceSource`] that calls `notify` once when the first frames are dark.
pub struct LowLightNotice<'a, S, F: FnMut()> {
    source: &'a mut S,
    watch: Option<LowLightWatch>,
    notify: F,
}

impl<'a, S: FaceSource, F: FnMut()> LowLightNotice<'a, S, F> {
    pub fn new(source: &'a mut S, enabled: bool, notify: F) -> Self {
        Self {
            source,
            watch: enabled.then(LowLightWatch::default),
            notify,
        }
    }
}

impl<S: FaceSource, F: FnMut()> FaceSource for LowLightNotice<'_, S, F> {
    fn next_frame(&mut self) -> Result<FrameStats, SourceError> {
        let stats = self.source.next_frame()?;
        if self.watch.as_mut().is_some_and(|w| w.observe(&stats.hist)) {
            (self.notify)();
        }
        Ok(stats)
    }
    fn analyze(&mut self) -> Result<Vec<Face>, SourceError> {
        self.source.analyze()
    }
    fn analyze_for_enrollment(&mut self) -> Result<Vec<Face>, SourceError> {
        self.source.analyze_for_enrollment()
    }
    fn detect(&mut self) -> Result<Vec<crate::source::DetectedFace>, SourceError> {
        self.source.detect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source::fake::{Scripted, BLACK, BRIGHT, DARK};

    const DIM: [f64; 8] = [45.0, 20.0, 15.0, 10.0, 5.0, 3.0, 1.0, 1.0];

    #[test]
    fn fires_once_after_enough_dark_frames_at_the_start() {
        let mut watch = LowLightWatch::default();
        assert!(!watch.observe(&DIM));
        assert!(!watch.observe(&BRIGHT));
        assert!(!watch.observe(&DARK));
        assert!(watch.observe(&BLACK), "third dark frame");
        assert!(!watch.observe(&DARK), "only once");
    }

    #[test]
    fn a_lit_scene_or_late_darkness_never_fires() {
        let mut lit = LowLightWatch::default();
        assert!((0..50).all(|_| !lit.observe(&BRIGHT)));
        let mut late = LowLightWatch::default();
        for _ in 0..LOW_LIGHT_WINDOW {
            assert!(!late.observe(&BRIGHT));
        }
        assert!((0..10).all(|_| !late.observe(&DARK)));
    }

    #[test]
    fn the_wrapper_notifies_once_and_only_when_enabled() {
        let frames = || (0..6).map(|i| (i * 30, DARK, Vec::new())).collect();
        let mut calls = 0;
        let mut source = Scripted::new(frames());
        let mut watched = LowLightNotice::new(&mut source, true, || calls += 1);
        for _ in 0..6 {
            watched.next_frame().unwrap();
        }
        assert_eq!(calls, 1);
        let mut calls = 0;
        let mut source = Scripted::new(frames());
        let mut off = LowLightNotice::new(&mut source, false, || calls += 1);
        for _ in 0..6 {
            off.next_frame().unwrap();
        }
        assert_eq!(calls, 0);
    }
}
