//! Face verification loop run by the PAM worker.
//!
//! Not certified liveness detection (ISO/IEC 30107): screen replays, deepfakes
//! and 3D masks can still pass, so the password stays the real secret.

use crate::i18n::tr;
use crate::matcher::{best_match, is_match};
use crate::source::{FaceSource, SourceError};
use std::io;
use std::time::Duration;

/// Worker exit codes, shared with the PAM module.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompareExit {
    Success = 0,
    NoFaceModel = 10,
    TimeoutReached = 11,
    Abort = 12,
    TooDark = 13,
    InvalidDevice = 14,
    Rubberstamp = 15,
    /// Face matched, but the head turns were wrong, incomplete or too slow.
    ChallengeFailed = 16,
    /// No face was seen at all.
    NoFaceSeen = 17,
}

impl CompareExit {
    pub fn code(self) -> i32 {
        self as i32
    }
}

/// Classify a grayscale frame by the share of pixels in histogram bin 0.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FrameClass {
    Black,
    Dark { darkness: f64 },
    Scan { darkness: f64 },
}

pub fn classify_frame(hist: &[f64; 8], dark_threshold: f64) -> FrameClass {
    let total: f64 = hist.iter().sum();
    if total == 0.0 {
        return FrameClass::Black;
    }
    let darkness = hist[0] / total * 100.0;
    if darkness == 100.0 {
        return FrameClass::Black;
    }
    if darkness > dark_threshold {
        FrameClass::Dark { darkness }
    } else {
        FrameClass::Scan { darkness }
    }
}

/// Rotations to try for this frame: `rotate` 0 none, 1 cycles all three,
/// 2 portrait only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameRotation {
    None,
    CounterClockwise,
    Clockwise,
}

pub fn rotation_for_frame(rotate_mode: i64, frame_number: u64) -> FrameRotation {
    match rotate_mode {
        1 => match frame_number % 3 {
            1 => FrameRotation::CounterClockwise,
            2 => FrameRotation::Clockwise,
            _ => FrameRotation::None,
        },
        2 => {
            if frame_number.is_multiple_of(2) {
                FrameRotation::CounterClockwise
            } else {
                FrameRotation::Clockwise
            }
        }
        _ => FrameRotation::None,
    }
}

/// Outcome of the timeout check at the top of each loop iteration.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum LoopOutcome {
    Continue,
    Timeout { all_dark: bool, save_snapshot: bool },
}

pub fn check_timeout(
    elapsed_secs: f64,
    timeout_secs: f64,
    dark_tries: u64,
    valid_frames: u64,
    save_failed: bool,
) -> LoopOutcome {
    if elapsed_secs <= timeout_secs {
        return LoopOutcome::Continue;
    }
    LoopOutcome::Timeout {
        all_dark: dark_tries == valid_frames,
        save_snapshot: save_failed,
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct VerifyParams {
    pub timeout: Duration,
    pub dark_threshold: f64,
    pub min_similarity: f32,
    pub required_matches: u8,
    pub min_match_interval: Duration,
    pub max_match_interval: Duration,
    /// Time limit for each stage of the movement challenge.
    pub stage_deadline: Duration,
    /// Extra time for the movement challenge, counted from the identity match.
    pub challenge_time: Duration,
}

impl VerifyParams {
    pub fn authentication(timeout: Duration, dark_threshold: f64, min_similarity: f32) -> Self {
        Self {
            timeout,
            dark_threshold,
            min_similarity,
            required_matches: 3,
            min_match_interval: Duration::from_millis(80),
            max_match_interval: Duration::from_millis(1500),
            stage_deadline: Duration::from_secs(4),
            challenge_time: Duration::from_secs(crate::config::CHALLENGE_SECS as u64),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TemporalDecision {
    Rejected {
        similarity: Option<f32>,
    },
    Progress {
        model: usize,
        similarity: f32,
        count: u8,
    },
    Accepted {
        model: usize,
        similarity: f32,
    },
}

/// Shared temporal acceptance state used by PAM and the visual test.
pub struct TemporalMatcher {
    params: VerifyParams,
    streak: Option<(usize, u8, Duration)>,
}

impl TemporalMatcher {
    pub fn new(params: VerifyParams) -> Self {
        Self {
            params,
            streak: None,
        }
    }

    pub fn reset(&mut self) -> TemporalDecision {
        self.streak = None;
        TemporalDecision::Rejected { similarity: None }
    }

    pub fn observe(&mut self, at: Duration, candidate: Option<(usize, f32)>) -> TemporalDecision {
        if self.streak.is_some_and(|(_, _, previous)| at <= previous) {
            return self.reset();
        }
        let Some((model, similarity)) = candidate else {
            return self.reset();
        };
        if !similarity.is_finite() || !is_match(similarity, self.params.min_similarity) {
            self.streak = None;
            return TemporalDecision::Rejected {
                similarity: Some(similarity),
            };
        }
        let count = match self.streak {
            Some((previous, count, previous_at))
                if previous == model
                    && at.saturating_sub(previous_at) >= self.params.min_match_interval
                    && at.saturating_sub(previous_at) <= self.params.max_match_interval =>
            {
                count.saturating_add(1)
            }
            Some((previous, count, previous_at))
                if previous == model
                    && at.saturating_sub(previous_at) < self.params.min_match_interval =>
            {
                return TemporalDecision::Progress {
                    model,
                    similarity,
                    count,
                };
            }
            _ => 1,
        };
        self.streak = Some((model, count, at));
        if count >= self.params.required_matches.max(2) {
            TemporalDecision::Accepted { model, similarity }
        } else {
            TemporalDecision::Progress {
                model,
                similarity,
                count,
            }
        }
    }
}

/// Head turns per challenge: 2^3 = 8 possible sequences.
pub const CHALLENGE_TURNS: usize = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Turn {
    Left,
    Right,
}

impl Turn {
    /// Positive for a left turn (the nose moves to the subject's left).
    fn sign(self) -> f32 {
        match self {
            Self::Left => 1.0,
            Self::Right => -1.0,
        }
    }

    fn arg(self) -> &'static str {
        match self {
            Self::Left => "left",
            Self::Right => "right",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "left" => Some(Self::Left),
            "right" => Some(Self::Right),
            _ => None,
        }
    }
}

/// Random head-turn sequence for one attempt, drawn from the OS CSPRNG.
/// Turns must come in order, with a return to centre in between.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeOrder {
    turns: [Turn; CHALLENGE_TURNS],
}

impl ChallengeOrder {
    /// Stages: neutral, each turn, the centre returns between turns, final centre.
    pub const STAGES: u8 = (CHALLENGE_TURNS as u8) * 2 + 1;

    /// Fails when the OS RNG fails, so callers fall back to the password.
    pub fn random() -> io::Result<Self> {
        let mut bytes = [0u8; CHALLENGE_TURNS];
        loop {
            let n = unsafe {
                libc::getrandom(bytes.as_mut_ptr().cast(), bytes.len(), libc::GRND_NONBLOCK)
            };
            if n == bytes.len() as isize {
                return Ok(Self {
                    turns: bytes.map(|byte| {
                        if byte & 1 == 0 {
                            Turn::Left
                        } else {
                            Turn::Right
                        }
                    }),
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    /// Fixed sequence for tests and tools; authentication uses [`Self::random`].
    pub const fn from_turns(turns: [Turn; CHALLENGE_TURNS]) -> Self {
        Self { turns }
    }

    pub fn turns(self) -> [Turn; CHALLENGE_TURNS] {
        self.turns
    }

    /// Wire form, e.g. `"left,right,left"`: the one line PAM writes to the
    /// worker's stdin (never its command line, which others can read).
    pub fn arg(self) -> String {
        self.turns
            .iter()
            .map(|turn| turn.arg())
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Parse [`Self::arg`]; anything but exactly `CHALLENGE_TURNS` turns is rejected.
    pub fn parse(value: &str) -> Option<Self> {
        let mut turns = [Turn::Left; CHALLENGE_TURNS];
        let mut count = 0;
        for part in value.split(',') {
            if count >= CHALLENGE_TURNS {
                return None;
            }
            turns[count] = Turn::parse(part)?;
            count += 1;
        }
        (count == CHALLENGE_TURNS).then_some(Self { turns })
    }
}

/// Prompt for a scan without the movement challenge.
pub const PASSIVE_PROMPT: &str = "Face check: look at the camera.";

/// Prefix of the worker's stdout line announcing the challenge stage it has
/// just entered, followed by [`ChallengeStage::number`].
pub const CHALLENGE_STAGE_PREFIX: &str = "challenge-stage ";

/// What PAM asks of the user on top of the identity match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeMode {
    /// Randomized head-turn sequence (`[core] movement_challenge = true`).
    Movement(ChallengeOrder),
    /// Identity match on several temporally distinct frames only.
    Passive,
}

impl ChallengeMode {
    pub fn for_config(movement_challenge: bool) -> io::Result<Self> {
        if movement_challenge {
            ChallengeOrder::random().map(Self::Movement)
        } else {
            Ok(Self::Passive)
        }
    }

    /// `--challenge` argument: `movement` or `none`. The sequence itself goes
    /// through stdin ([`Self::stdin_line`]).
    pub fn arg(self) -> &'static str {
        match self {
            Self::Movement(_) => "movement",
            Self::Passive => "none",
        }
    }

    /// What PAM writes to the worker's stdin: the sequence and a newline, or
    /// nothing without the challenge.
    pub fn stdin_line(self) -> String {
        match self {
            Self::Movement(order) => format!("{}\n", order.arg()),
            Self::Passive => String::new(),
        }
    }

    /// The worker's side of [`Self::arg`] and [`Self::stdin_line`]: `None`
    /// for anything else, including a sequence without the challenge.
    pub fn from_wire(arg: &str, stdin: &[u8]) -> Option<Self> {
        match (arg, stdin) {
            ("none", []) => Some(Self::Passive),
            ("movement", line) => {
                let line = std::str::from_utf8(line).ok()?.strip_suffix('\n')?;
                ChallengeOrder::parse(line).map(Self::Movement)
            }
            _ => None,
        }
    }

    /// Shown before the scan. With the challenge it names no turn: each one is
    /// shown only once the previous step was performed.
    pub fn prompt(self) -> String {
        match self {
            Self::Movement(_) => {
                tr("Face check: look at the camera, then follow the head-turn instructions.")
            }
            Self::Passive => tr("Face check: look at the camera."),
        }
    }

    pub fn is_movement(self) -> bool {
        matches!(self, Self::Movement(_))
    }

    /// Whether this mode is at least as strict as `required`.
    pub fn satisfies(self, movement_required: bool) -> bool {
        self.is_movement() || !movement_required
    }
}

/// Challenge stage; the tracker only moves forward.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChallengeStage {
    Neutral,
    /// Turn `i` of the challenge (`i < CHALLENGE_TURNS`).
    Turn(u8),
    /// Return-to-centre after turn `i` (not used after the final turn).
    Center(u8),
    FinalCenter,
    Complete,
    Failed,
}

impl ChallengeStage {
    /// 1-based position in the ordered sequence, for progress display.
    pub fn number(self) -> u8 {
        match self {
            Self::Neutral => 1,
            Self::Turn(i) => 2 + 2 * i,
            Self::Center(i) => 3 + 2 * i,
            Self::FinalCenter | Self::Complete | Self::Failed => ChallengeOrder::STAGES,
        }
    }

    /// The stage a worker announces with [`CHALLENGE_STAGE_PREFIX`]: one that
    /// asks something new of the user, never the first or a final state.
    pub fn announced(number: u8) -> Option<Self> {
        let last_turn = CHALLENGE_TURNS as u8 - 1;
        match number {
            n if n == ChallengeOrder::STAGES => Some(Self::FinalCenter),
            n if (2..ChallengeOrder::STAGES).contains(&n) && n % 2 == 0 => {
                Some(Self::Turn(n / 2 - 1))
            }
            n if (3..ChallengeOrder::STAGES).contains(&n) && (n - 3) / 2 < last_turn => {
                Some(Self::Center((n - 3) / 2))
            }
            _ => None,
        }
    }

    pub fn instruction(self, order: ChallengeOrder) -> String {
        match self {
            Self::Neutral => tr("Look straight at the camera"),
            Self::Turn(i) => match order.turns().get(i as usize) {
                Some(Turn::Left) => tr("Turn your head LEFT"),
                Some(Turn::Right) => tr("Turn your head RIGHT"),
                None => tr("Turn your head as instructed"),
            },
            Self::Center(_) | Self::FinalCenter => tr("Look straight at the camera again"),
            Self::Complete => tr("Movement challenge completed"),
            Self::Failed => tr(
                "Movement challenge failed (wrong order, missed step, or too slow); \
                 use your password or retry",
            ),
        }
    }
}

/// Tracks one movement challenge (PAM worker and GTK test). Each stage needs
/// two frames within the match interval before `stage_deadline`; a wrong turn
/// or a rewound clock fails at once.
pub struct ChallengeTracker {
    order: ChallengeOrder,
    model: usize,
    stage: ChallengeStage,
    baseline: f32,
    neutral_sum: f32,
    samples: u8,
    last: Option<Duration>,
    /// Latest timestamp seen; an older frame means replayed footage.
    high_water: Option<Duration>,
    /// Start of the current stage; `None` until its first frame.
    stage_entered: Option<Duration>,
}

impl ChallengeTracker {
    pub fn new(order: ChallengeOrder, model: usize) -> Self {
        Self {
            order,
            model,
            stage: ChallengeStage::Neutral,
            baseline: 0.0,
            neutral_sum: 0.0,
            samples: 0,
            last: None,
            high_water: None,
            stage_entered: None,
        }
    }

    pub fn stage(&self) -> ChallengeStage {
        self.stage
    }

    /// Start over from the neutral stage.
    pub fn reset(&mut self) {
        self.stage = ChallengeStage::Neutral;
        self.baseline = 0.0;
        self.neutral_sum = 0.0;
        self.samples = 0;
        self.last = None;
        self.stage_entered = None;
    }

    /// Sample: (model index, similarity, nose offset). `None` never advances.
    pub fn observe(
        &mut self,
        at: Duration,
        sample: Option<(usize, f32, f32)>,
        params: &VerifyParams,
    ) -> ChallengeStage {
        if matches!(
            self.stage,
            ChallengeStage::Complete | ChallengeStage::Failed
        ) {
            return self.stage;
        }
        if self.high_water.is_some_and(|high| at <= high) {
            // A rewound clock means replayed footage.
            self.stage = ChallengeStage::Failed;
            return self.stage;
        }
        self.high_water = Some(at);
        match self.stage_entered {
            None => self.stage_entered = Some(at),
            Some(entered) if at.saturating_sub(entered) > params.stage_deadline => {
                self.stage = ChallengeStage::Failed;
                return self.stage;
            }
            Some(_) => {}
        }
        let Some((model, similarity, yaw)) = sample else {
            return self.stage;
        };
        if model != self.model
            || !similarity.is_finite()
            || similarity < params.min_similarity
            || !yaw.is_finite()
        {
            return self.stage;
        }
        let delta = yaw - self.baseline;
        if let ChallengeStage::Turn(i) = self.stage {
            let instructed = self.order.turns()[i as usize].sign();
            if delta * instructed <= -0.16 {
                self.stage = ChallengeStage::Failed;
                return self.stage;
            }
        }
        let valid = match self.stage {
            ChallengeStage::Neutral => yaw.abs() <= 0.22,
            ChallengeStage::Turn(i) => delta * self.order.turns()[i as usize].sign() >= 0.16,
            ChallengeStage::Center(_) | ChallengeStage::FinalCenter => delta.abs() <= 0.10,
            ChallengeStage::Complete | ChallengeStage::Failed => return self.stage,
        };
        if !valid {
            return self.stage;
        }
        if let Some(last) = self.last {
            let gap = at - last;
            if gap < params.min_match_interval {
                return self.stage;
            }
            if gap > params.max_match_interval {
                self.samples = 0;
                self.neutral_sum = 0.0;
            }
        }
        self.last = Some(at);
        self.samples += 1;
        if self.stage == ChallengeStage::Neutral {
            self.neutral_sum += yaw;
        }
        if self.samples >= 2 {
            self.stage = match self.stage {
                ChallengeStage::Neutral => {
                    self.baseline = self.neutral_sum / 2.0;
                    ChallengeStage::Turn(0)
                }
                ChallengeStage::Turn(i) if i as usize + 1 < CHALLENGE_TURNS => {
                    ChallengeStage::Center(i)
                }
                ChallengeStage::Turn(_) => ChallengeStage::FinalCenter,
                ChallengeStage::Center(i) => ChallengeStage::Turn(i + 1),
                ChallengeStage::FinalCenter => ChallengeStage::Complete,
                ChallengeStage::Complete | ChallengeStage::Failed => self.stage,
            };
            self.samples = 0;
            self.last = None;
            self.neutral_sum = 0.0;
            self.stage_entered = Some(at);
        }
        self.stage
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum VerifyOutcome {
    Matched {
        model: usize,
        similarity: f32,
        at: Duration,
        frames: u64,
    },
    TimedOut {
        all_dark: bool,
        best_similarity: Option<f32>,
        frames: u64,
        black: u64,
        dark: u64,
        /// Face matched but the movement challenge failed.
        challenge_failed: bool,
    },
}

impl VerifyOutcome {
    pub fn exit(&self) -> CompareExit {
        match self {
            Self::Matched { .. } => CompareExit::Success,
            Self::TimedOut { all_dark: true, .. } => CompareExit::TooDark,
            Self::TimedOut {
                challenge_failed: true,
                ..
            } => CompareExit::ChallengeFailed,
            Self::TimedOut {
                best_similarity: None,
                ..
            } => CompareExit::NoFaceSeen,
            Self::TimedOut { .. } => CompareExit::TimeoutReached,
        }
    }
}

/// Scan until one model matches on several frames. `known` pairs each
/// embedding with its model index.
pub fn verify<S: FaceSource>(
    source: &mut S,
    known: &[(usize, Vec<f32>)],
    params: &VerifyParams,
) -> Result<VerifyOutcome, SourceError> {
    let (mut frames, mut black, mut dark, mut valid) = (0u64, 0u64, 0u64, 0u64);
    let mut best_similarity: Option<f32> = None;
    let mut temporal = TemporalMatcher::new(*params);
    loop {
        let stats = source.next_frame()?;
        frames += 1;
        let outcome = check_timeout(
            stats.at.as_secs_f64(),
            params.timeout.as_secs_f64(),
            dark,
            valid,
            false,
        );
        if let LoopOutcome::Timeout { all_dark, .. } = outcome {
            return Ok(VerifyOutcome::TimedOut {
                all_dark,
                best_similarity,
                frames,
                black,
                dark,
                challenge_failed: false,
            });
        }
        match classify_frame(&stats.hist, params.dark_threshold) {
            FrameClass::Black => {
                black += 1;
                continue;
            }
            FrameClass::Dark { .. } => {
                valid += 1;
                dark += 1;
                continue;
            }
            FrameClass::Scan { .. } => valid += 1,
        }
        let faces = source.analyze()?;
        let [face] = faces.as_slice() else {
            temporal.reset();
            continue;
        };
        let candidate = best_match(known, &face.embedding);
        if let Some((_, similarity)) = candidate {
            best_similarity = Some(best_similarity.map_or(similarity, |best| best.max(similarity)));
        }
        if let TemporalDecision::Accepted { model, similarity } =
            temporal.observe(stats.at, candidate)
        {
            return Ok(VerifyOutcome::Matched {
                model,
                similarity,
                at: stats.at,
                frames,
            });
        }
    }
}

/// Identity match followed by the movement challenge, with no fallback to
/// plain matching.
/// `on_stage` is called with each stage the tracker enters that asks
/// something new of the user (see [`ChallengeStage::announced`]), in order.
pub fn verify_with_challenge<S: FaceSource>(
    source: &mut S,
    known: &[(usize, Vec<f32>)],
    params: &VerifyParams,
    order: ChallengeOrder,
    on_stage: &mut dyn FnMut(ChallengeStage),
) -> Result<VerifyOutcome, SourceError> {
    let initial = verify(source, known, params)?;
    let VerifyOutcome::Matched {
        model,
        similarity: identity_similarity,
        at: identified_at,
        frames: initial_frames,
    } = initial
    else {
        return Ok(initial);
    };
    let mut tracker = ChallengeTracker::new(order, model);
    let (mut frames, mut dark, mut black) = (initial_frames, 0, 0);
    loop {
        let stats = source.next_frame()?;
        frames += 1;
        if stats.at > identified_at + params.challenge_time {
            // The face was recognised; only the movement was missing.
            return Ok(VerifyOutcome::TimedOut {
                all_dark: false,
                best_similarity: Some(identity_similarity),
                frames,
                black,
                dark,
                challenge_failed: false,
            });
        }
        match classify_frame(&stats.hist, params.dark_threshold) {
            FrameClass::Black => {
                black += 1;
                continue;
            }
            FrameClass::Dark { .. } => {
                dark += 1;
                continue;
            }
            FrameClass::Scan { .. } => {}
        }
        let faces = source.analyze()?;
        let sample = if let [face] = faces.as_slice() {
            best_match(known, &face.embedding)
                .zip(face.yaw)
                .map(|((index, similarity), yaw)| (index, similarity, yaw))
        } else {
            None
        };
        let before = tracker.stage();
        let stage = tracker.observe(stats.at, sample, params);
        if stage != before && ChallengeStage::announced(stage.number()) == Some(stage) {
            on_stage(stage);
        }
        if stage == ChallengeStage::Failed {
            return Ok(VerifyOutcome::TimedOut {
                all_dark: false,
                best_similarity: sample.map(|(_, score, _)| score),
                frames,
                black,
                dark,
                challenge_failed: true,
            });
        }
        if stage == ChallengeStage::Complete {
            return Ok(VerifyOutcome::Matched {
                model,
                similarity: sample.expect("completion requires a valid face").1,
                at: stats.at,
                frames,
            });
        }
    }
}

pub fn verify_with_mode<S: FaceSource>(
    source: &mut S,
    known: &[(usize, Vec<f32>)],
    params: &VerifyParams,
    mode: ChallengeMode,
    on_stage: &mut dyn FnMut(ChallengeStage),
) -> Result<VerifyOutcome, SourceError> {
    match mode {
        ChallengeMode::Movement(order) => {
            verify_with_challenge(source, known, params, order, on_stage)
        }
        ChallengeMode::Passive => verify(source, known, params),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn challenge_frames(yaws: &[f32]) -> crate::source::fake::Scripted {
        use crate::source::fake::{face, Scripted, BRIGHT};
        let frames = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .chain(yaws.iter().enumerate().map(|(i, yaw)| {
                let mut seen = face(0.9, &[1.0, 0.0]);
                seen.yaw = Some(*yaw);
                (400 + i as u64 * 100, BRIGHT, vec![seen])
            }))
            .chain(std::iter::once((5_000, BRIGHT, vec![])))
            .collect();
        Scripted::new(frames)
    }

    /// Yaw samples that answer `seq` correctly.
    fn successful_yaws(order: ChallengeOrder) -> Vec<f32> {
        let mut yaws = vec![0.0, 0.0];
        for (i, turn) in order.turns().into_iter().enumerate() {
            let yaw = match turn {
                Turn::Left => 0.3,
                Turn::Right => -0.3,
            };
            yaws.extend([yaw, yaw]);
            if i + 1 < CHALLENGE_TURNS {
                yaws.extend([0.0, 0.0]);
            }
        }
        yaws.extend([0.0, 0.0]);
        yaws
    }

    fn challenge_params() -> VerifyParams {
        let mut params = VerifyParams::authentication(Duration::from_secs(4), 60.0, 0.363);
        params.challenge_time = Duration::from_secs(4);
        params
    }

    const LRL: ChallengeOrder = ChallengeOrder::from_turns([Turn::Left, Turn::Right, Turn::Left]);

    /// A fixed recording passes only when the random sequence equals it (1 in 8).
    #[test]
    fn prerecorded_loop_only_wins_for_its_own_sequence_one_in_eight() {
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        let mut wins = 0;
        for bits in 0..8u32 {
            let turns = [0, 1, 2].map(|shift| {
                if bits >> shift & 1 == 0 {
                    Turn::Left
                } else {
                    Turn::Right
                }
            });
            let challenge = ChallengeOrder::from_turns(turns);
            let recording = successful_yaws(LRL);
            let outcome = verify_with_challenge(
                &mut challenge_frames(&recording),
                &known,
                &params,
                challenge,
                &mut |_| {},
            )
            .unwrap();
            if turns == LRL.turns() {
                assert!(
                    matches!(outcome, VerifyOutcome::Matched { frames: 17, at, .. } if at == Duration::from_millis(1_700)),
                    "the matching sequence must complete all 7 stages: {outcome:?}"
                );
                wins += 1;
            } else {
                assert!(
                    matches!(
                        outcome,
                        VerifyOutcome::TimedOut {
                            challenge_failed: true,
                            frames,
                            ..
                        } if frames <= 3 + 14
                    ),
                    "challenge {challenge:?} must reject the LRL recording without waiting for the clock: {outcome:?}"
                );
            }
        }
        assert_eq!(wins, 1, "a fixed recording must match exactly one sequence");
    }

    /// A photo matches but never completes the challenge.
    #[test]
    fn static_photo_never_completes_the_challenge() {
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        let outcome = verify_with_challenge(
            &mut challenge_frames(&[0.0; 20]),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: false,
                ..
            }
        ));
        assert_eq!(outcome.exit(), CompareExit::TimeoutReached);
    }

    /// Starting with the opposite of the instructed turn fails immediately.
    #[test]
    fn wrong_first_turn_fails_fast_to_password() {
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        let mut yaws = successful_yaws(LRL);
        yaws[2] = -0.3;
        let outcome = verify_with_challenge(
            &mut challenge_frames(&yaws),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                frames: 6,
                ..
            }
        ));
        assert_eq!(outcome.exit(), CompareExit::ChallengeFailed);
    }

    /// A held pose cannot skip the centre return between turns.
    #[test]
    fn held_pose_cannot_skip_the_centre_return() {
        let mut params = challenge_params();
        params.stage_deadline = Duration::from_millis(300);
        let known = [(0, vec![1.0, 0.0])];
        let mut yaws = vec![0.0, 0.0, 0.3, 0.3];
        yaws.extend([0.3; 8]);
        let outcome = verify_with_challenge(
            &mut challenge_frames(&yaws),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                ..
            }
        ));
    }

    /// A pause longer than `stage_deadline` fails the attempt.
    #[test]
    fn slow_stage_fails_the_challenge() {
        use crate::source::fake::{face, Scripted, BRIGHT};
        let mut params = challenge_params();
        params.stage_deadline = Duration::from_millis(250);
        let known = [(0, vec![1.0, 0.0])];
        // The second turn sample arrives after the 250 ms stage budget.
        let frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .chain(
                [(400, 0.0), (500, 0.0), (600, 0.3), (1_100, 0.3)].map(|(at, yaw)| {
                    let mut seen = face(0.9, &[1.0, 0.0]);
                    seen.yaw = Some(yaw);
                    (at, BRIGHT, vec![seen])
                }),
            )
            .chain(std::iter::once((5_000, BRIGHT, vec![])))
            .collect();
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                ..
            }
        ));
        // Control: the same deadline is comfortable for an uninterrupted run.
        let outcome = verify_with_challenge(
            &mut challenge_frames(&successful_yaws(LRL)),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, VerifyOutcome::Matched { .. }));
    }

    /// A different person mid-challenge never completes it.
    #[test]
    fn identity_swap_mid_challenge_fails() {
        use crate::source::fake::{face, Scripted, BRIGHT};
        let mut params = challenge_params();
        params.stage_deadline = Duration::from_millis(300);
        let known = [(0, vec![1.0, 0.0]), (1, vec![0.0, 1.0])];
        let mut frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .collect();
        for (i, yaw) in successful_yaws(LRL).iter().enumerate() {
            // From the second turn onward the footage shows a different person.
            let embedding: &[f32] = if i >= 6 { &[0.0, 1.0] } else { &[1.0, 0.0] };
            let mut seen = face(0.9, embedding);
            seen.yaw = Some(*yaw);
            frames.push((400 + i as u64 * 100, BRIGHT, vec![seen]));
        }
        frames.push((5_000, BRIGHT, vec![]));
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                ..
            }
        ));
    }

    /// Missing or ambiguous landmarks never advance the challenge.
    #[test]
    fn missing_or_ambiguous_landmarks_fail_to_password() {
        use crate::source::fake::{face, Scripted, BRIGHT};
        let mut params = challenge_params();
        params.stage_deadline = Duration::from_millis(500);
        let known = [(0, vec![1.0, 0.0])];

        // Landmarks present but ambiguous: eye span too small -> yaw = None.
        let mut no_yaw = face(0.9, &[1.0, 0.0]);
        no_yaw.yaw = None;
        let frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .chain((0..12).map(|i| (400 + i * 100, BRIGHT, vec![no_yaw.clone()])))
            .chain(std::iter::once((5_000, BRIGHT, vec![])))
            .collect();
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                ..
            }
        ));

        // Two faces at once is ambiguous and must never advance either.
        let frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .chain((0..12).map(|i| {
                (
                    400 + i * 100,
                    BRIGHT,
                    vec![face(0.9, &[1.0, 0.0]), face(0.9, &[1.0, 0.0])],
                )
            }))
            .chain(std::iter::once((5_000, BRIGHT, vec![])))
            .collect();
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(
            outcome,
            VerifyOutcome::TimedOut {
                challenge_failed: true,
                ..
            }
        ));
    }

    /// Unlit frames are skipped without advancing the challenge.
    #[test]
    fn dark_ir_frames_do_not_advance_or_break_the_challenge() {
        use crate::source::fake::{face, Scripted, BRIGHT, DARK};
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        // Only unlit frames after the identity match: no progress, timeout.
        let frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .chain((0..30).map(|i| (400 + i * 100, DARK, vec![])))
            .chain(std::iter::once((5_000, DARK, vec![])))
            .collect();
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, VerifyOutcome::TimedOut { .. }));
        assert_ne!(outcome.exit(), CompareExit::Success);

        // Interleaved unlit frames are skipped and the challenge completes.
        let mut frames: Vec<(u64, [f64; 8], Vec<crate::source::Face>)> = (0..3)
            .map(|i| (100 + i * 100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]))
            .collect();
        for (i, yaw) in successful_yaws(LRL).iter().enumerate() {
            let mut seen = face(0.9, &[1.0, 0.0]);
            seen.yaw = Some(*yaw);
            frames.push((400 + i as u64 * 100, BRIGHT, vec![seen]));
            if i % 3 == 2 {
                frames.push((450 + i as u64 * 100, DARK, vec![]));
            }
        }
        let outcome = verify_with_challenge(
            &mut Scripted::new(frames),
            &known,
            &params,
            LRL,
            &mut |_| {},
        )
        .unwrap();
        assert!(matches!(outcome, VerifyOutcome::Matched { .. }));
    }

    /// Frame timestamps must move forward.
    #[test]
    fn backwards_timestamps_fail_the_challenge() {
        let params = challenge_params();
        let mut challenge = ChallengeTracker::new(LRL, 0);
        assert_eq!(
            challenge.observe(Duration::from_millis(100), Some((0, 0.9, 0.0)), &params),
            ChallengeStage::Neutral
        );
        // Two neutral samples complete the stage and arm the turn.
        assert_eq!(
            challenge.observe(Duration::from_millis(200), Some((0, 0.9, 0.0)), &params),
            ChallengeStage::Turn(0)
        );
        // A rewound clock fails even across the stage boundary.
        assert_eq!(
            challenge.observe(Duration::from_millis(150), Some((0, 0.9, 0.0)), &params),
            ChallengeStage::Failed
        );
        // Failed is terminal.
        assert_eq!(
            challenge.observe(Duration::from_millis(300), Some((0, 0.9, 0.1)), &params),
            ChallengeStage::Failed
        );
    }

    #[test]
    fn tracker_advances_through_all_ordered_stages() {
        let params = challenge_params();
        let mut challenge = ChallengeTracker::new(LRL, 0);
        let mut at = 100u64;
        let mut step = |challenge: &mut ChallengeTracker, yaw: f32| {
            at += 100;
            challenge.observe(Duration::from_millis(at), Some((0, 0.9, yaw)), &params)
        };
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Neutral);
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Turn(0));
        assert_eq!(step(&mut challenge, 0.3), ChallengeStage::Turn(0));
        assert_eq!(step(&mut challenge, 0.3), ChallengeStage::Center(0));
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Center(0));
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Turn(1));
        assert_eq!(step(&mut challenge, -0.3), ChallengeStage::Turn(1));
        assert_eq!(step(&mut challenge, -0.3), ChallengeStage::Center(1));
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Center(1));
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Turn(2));
        assert_eq!(step(&mut challenge, 0.3), ChallengeStage::Turn(2));
        assert_eq!(step(&mut challenge, 0.3), ChallengeStage::FinalCenter);
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::FinalCenter);
        assert_eq!(step(&mut challenge, 0.0), ChallengeStage::Complete);
    }

    #[test]
    fn stage_numbering_and_instructions_follow_the_sequence() {
        assert_eq!(ChallengeStage::Neutral.number(), 1);
        assert_eq!(ChallengeStage::Turn(0).number(), 2);
        assert_eq!(ChallengeStage::Center(0).number(), 3);
        assert_eq!(ChallengeStage::Turn(2).number(), 6);
        assert_eq!(ChallengeStage::FinalCenter.number(), ChallengeOrder::STAGES);
        assert_eq!(ChallengeOrder::STAGES, 7);
        assert_eq!(
            ChallengeStage::Turn(0).instruction(LRL),
            "Turn your head LEFT"
        );
        assert_eq!(
            ChallengeStage::Turn(1).instruction(LRL),
            "Turn your head RIGHT"
        );
        assert_eq!(
            ChallengeStage::Turn(2).instruction(LRL),
            "Turn your head LEFT"
        );
        // The prompt before the scan names no turn.
        let prompt = ChallengeMode::Movement(LRL).prompt();
        assert!(
            !prompt.contains("LEFT") && !prompt.contains("RIGHT"),
            "{prompt}"
        );
    }

    /// Each stage is reported once, in order, only when it is reached: the
    /// next turn is never known to the user before the previous step.
    #[test]
    fn stages_are_reported_one_at_a_time_as_they_are_reached() {
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        let mut seen = Vec::new();
        let outcome = verify_with_challenge(
            &mut challenge_frames(&successful_yaws(LRL)),
            &known,
            &params,
            LRL,
            &mut |stage| seen.push(stage),
        )
        .unwrap();
        assert!(
            matches!(outcome, VerifyOutcome::Matched { .. }),
            "{outcome:?}"
        );
        use ChallengeStage::*;
        assert_eq!(
            seen,
            [Turn(0), Center(0), Turn(1), Center(1), Turn(2), FinalCenter]
        );
        assert!(seen
            .iter()
            .all(|s| ChallengeStage::announced(s.number()) == Some(*s)));
        // A wrong first turn: only the first turn was ever announced.
        let mut yaws = successful_yaws(LRL);
        yaws[2] = -0.3;
        let mut seen = Vec::new();
        verify_with_challenge(
            &mut challenge_frames(&yaws),
            &known,
            &params,
            LRL,
            &mut |stage| seen.push(stage),
        )
        .unwrap();
        assert_eq!(seen, [Turn(0)]);
        // A photo: the face matches, but no turn is announced past the first.
        let mut seen = Vec::new();
        verify_with_challenge(
            &mut challenge_frames(&[0.0; 20]),
            &known,
            &params,
            LRL,
            &mut |stage| seen.push(stage),
        )
        .unwrap();
        assert_eq!(seen, [Turn(0)]);
        for (number, stage) in [
            (1, None),
            (0, None),
            (8, None),
            (2, Some(Turn(0))),
            (7, Some(FinalCenter)),
        ] {
            assert_eq!(ChallengeStage::announced(number), stage, "{number}");
        }
    }

    #[test]
    fn challenge_mode_wire_format_and_config_agreement() {
        let passive = ChallengeMode::Passive;
        assert_eq!((passive.arg(), passive.stdin_line().as_str()), ("none", ""));
        assert_eq!(ChallengeMode::from_wire("none", b""), Some(passive));
        let movement = ChallengeMode::Movement(LRL);
        // The sequence is never on the command line.
        assert_eq!(movement.arg(), "movement");
        assert_eq!(movement.stdin_line(), "left,right,left\n");
        assert_eq!(
            ChallengeMode::from_wire(movement.arg(), movement.stdin_line().as_bytes()),
            Some(movement)
        );
        for (arg, stdin) in [
            ("none", &b"left,right,left\n"[..]),
            ("movement", b""),
            ("movement", b"left,right,left"),
            ("movement", b"left,right,left\n\n"),
            ("movement", b"left,right,left\nleft,left,left\n"),
            ("movement", b"left,right\n"),
            ("movement", b"\xff\n"),
            ("left,right,left", b""),
            ("None", b""),
            ("", b""),
        ] {
            assert_eq!(
                ChallengeMode::from_wire(arg, stdin),
                None,
                "{arg:?} {stdin:?}"
            );
        }
        assert!(movement.satisfies(true) && movement.satisfies(false));
        assert!(ChallengeMode::Passive.satisfies(false));
        assert!(!ChallengeMode::Passive.satisfies(true));
        assert_eq!(
            ChallengeMode::for_config(false).unwrap(),
            ChallengeMode::Passive
        );
        assert!(matches!(
            ChallengeMode::for_config(true).unwrap(),
            ChallengeMode::Movement(_)
        ));
        assert_eq!(ChallengeMode::Passive.prompt(), PASSIVE_PROMPT);
    }

    /// Without the challenge a still face unlocks; with it, it never does.
    #[test]
    fn passive_mode_accepts_a_still_face_that_the_challenge_rejects() {
        let params = challenge_params();
        let known = [(0, vec![1.0, 0.0])];
        let passive = verify_with_mode(
            &mut challenge_frames(&[0.0; 20]),
            &known,
            &params,
            ChallengeMode::Passive,
            &mut |_| panic!("no stages without the challenge"),
        )
        .unwrap();
        assert!(
            matches!(passive, VerifyOutcome::Matched { frames: 3, .. }),
            "{passive:?}"
        );
        let movement = verify_with_mode(
            &mut challenge_frames(&[0.0; 20]),
            &known,
            &params,
            ChallengeMode::Movement(LRL),
            &mut |_| {},
        )
        .unwrap();
        assert!(
            matches!(movement, VerifyOutcome::TimedOut { .. }),
            "{movement:?}"
        );
    }

    #[test]
    fn challenge_wire_format_roundtrips_and_rejects_downgrades() {
        for bits in 0..8u32 {
            let turns = [0, 1, 2].map(|shift| {
                if bits >> shift & 1 == 0 {
                    Turn::Left
                } else {
                    Turn::Right
                }
            });
            let challenge = ChallengeOrder::from_turns(turns);
            assert_eq!(ChallengeOrder::parse(&challenge.arg()), Some(challenge));
            assert_eq!(challenge.turns(), turns);
        }
        // Legacy 1-bit values, wrong lengths and typos are not accepted.
        for bad in [
            "left-right",
            "right-left",
            "left",
            "left,right",
            "left,right,left,right",
            "left,up,left",
            "left,,left",
            "",
            "left, right,left",
        ] {
            assert_eq!(ChallengeOrder::parse(bad), None, "{bad:?}");
        }
        let fresh = ChallengeOrder::random().expect("getrandom must work in tests");
        assert_eq!(ChallengeOrder::parse(&fresh.arg()), Some(fresh));
    }

    #[test]
    fn unlit_ir_frames_do_not_count_or_break_a_short_matching_sequence() {
        use crate::source::fake::{face, Scripted, BLACK, BRIGHT, DARK};
        let mut source = Scripted::new(vec![
            (100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (140, BLACK, vec![]),
            (200, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (240, DARK, vec![]),
            (300, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
        ]);
        let params = VerifyParams::authentication(Duration::from_secs(4), 80.0, 0.363);
        assert!(matches!(
            verify(&mut source, &[(0, vec![1.0, 0.0])], &params).unwrap(),
            VerifyOutcome::Matched { frames: 5, .. }
        ));
        assert_eq!(source.analyzed, 3);
    }

    #[test]
    fn temporal_acceptance_rejects_nonfinite_and_backwards_timestamps() {
        let params = VerifyParams::authentication(Duration::from_secs(4), 80.0, 0.363);
        let mut matcher = TemporalMatcher::new(params);
        matcher.observe(Duration::from_millis(100), Some((0, 0.9)));
        assert!(matches!(
            matcher.observe(Duration::from_millis(90), Some((0, 0.9))),
            TemporalDecision::Rejected { .. }
        ));
        assert!(matches!(
            matcher.observe(Duration::from_millis(200), Some((0, f32::INFINITY))),
            TemporalDecision::Rejected { .. }
        ));
        assert!(matches!(
            matcher.observe(Duration::from_millis(300), Some((0, 0.9))),
            TemporalDecision::Progress { count: 1, .. }
        ));
    }

    #[test]
    fn exit_codes_match_main_hh() {
        assert_eq!(CompareExit::NoFaceModel.code(), 10);
        assert_eq!(CompareExit::TimeoutReached.code(), 11);
        assert_eq!(CompareExit::Abort.code(), 12);
        assert_eq!(CompareExit::TooDark.code(), 13);
        assert_eq!(CompareExit::InvalidDevice.code(), 14);
        assert_eq!(CompareExit::Rubberstamp.code(), 15);
        assert_eq!(CompareExit::ChallengeFailed.code(), 16);
        assert_eq!(CompareExit::NoFaceSeen.code(), 17);
        assert_eq!(CompareExit::Success.code(), 0);
    }

    #[test]
    fn frame_classification() {
        assert_eq!(classify_frame(&[0.0; 8], 60.0), FrameClass::Black);
        assert_eq!(
            classify_frame(&[100.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0], 60.0),
            FrameClass::Black
        );
        // 70% in bin 0, threshold 60 -> dark
        assert!(matches!(
            classify_frame(&[70.0, 10.0, 10.0, 5.0, 2.0, 1.0, 1.0, 1.0], 60.0),
            FrameClass::Dark { .. }
        ));
        // 10% in bin 0 -> scan
        assert!(matches!(
            classify_frame(&[10.0, 20.0, 20.0, 20.0, 10.0, 10.0, 5.0, 5.0], 60.0),
            FrameClass::Scan { .. }
        ));
        // exactly at threshold is NOT dark (strict `>`)
        let h = [60.0, 10.0, 10.0, 10.0, 5.0, 2.0, 2.0, 1.0]; // sums to exactly 100
        assert!(matches!(classify_frame(&h, 60.0), FrameClass::Scan { .. }));
    }

    #[test]
    fn rotation_policy() {
        assert_eq!(rotation_for_frame(0, 7), FrameRotation::None);
        assert_eq!(rotation_for_frame(1, 3), FrameRotation::None);
        assert_eq!(rotation_for_frame(1, 4), FrameRotation::CounterClockwise);
        assert_eq!(rotation_for_frame(1, 5), FrameRotation::Clockwise);
        assert_eq!(rotation_for_frame(2, 4), FrameRotation::CounterClockwise);
        assert_eq!(rotation_for_frame(2, 5), FrameRotation::Clockwise);
    }

    #[test]
    fn timeout_branch() {
        assert_eq!(check_timeout(2.0, 4.0, 0, 0, false), LoopOutcome::Continue);
        assert_eq!(
            check_timeout(5.0, 4.0, 3, 3, true),
            LoopOutcome::Timeout {
                all_dark: true,
                save_snapshot: true
            }
        );
        assert_eq!(
            check_timeout(5.0, 4.0, 1, 3, false),
            LoopOutcome::Timeout {
                all_dark: false,
                save_snapshot: false
            }
        );
    }

    use crate::source::fake::{face, Scripted, BLACK, BRIGHT, DARK};

    const PARAMS: VerifyParams = VerifyParams {
        timeout: Duration::from_secs(4),
        dark_threshold: 60.0,
        min_similarity: 0.363,
        required_matches: 3,
        min_match_interval: Duration::from_millis(80),
        max_match_interval: Duration::from_millis(1500),
        stage_deadline: Duration::from_secs(4),
        challenge_time: Duration::from_secs(8),
    };

    fn known() -> Vec<(usize, Vec<f32>)> {
        vec![(0, vec![1.0, 0.0]), (2, vec![0.0, 1.0])]
    }

    #[test]
    fn matches_after_skipping_black_and_dark_frames_without_analyzing_them() {
        let mut src = Scripted::new(vec![
            (100, BLACK, vec![]),
            (130, DARK, vec![]),
            (160, BRIGHT, vec![face(0.9, &[0.1, 0.9])]),
            (260, BRIGHT, vec![face(0.9, &[0.1, 0.9])]),
            (360, BRIGHT, vec![face(0.9, &[0.1, 0.9])]),
        ]);
        let out = verify(&mut src, &known(), &PARAMS).unwrap();
        let VerifyOutcome::Matched {
            model,
            similarity,
            at,
            frames,
        } = out
        else {
            panic!("{out:?}")
        };
        assert_eq!((model, frames, at), (2, 5, Duration::from_millis(360)));
        assert!(similarity > 0.9);
        assert_eq!(src.analyzed, 3);
        assert_eq!(out.exit(), CompareExit::Success);
    }

    #[test]
    fn ambiguity_resets_temporal_acceptance() {
        let mut src = Scripted::new(vec![
            (100, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (200, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (
                300,
                BRIGHT,
                vec![face(0.9, &[1.0, 0.0]), face(0.9, &[1.0, 0.0])],
            ),
            (400, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (500, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
            (600, BRIGHT, vec![face(0.9, &[1.0, 0.0])]),
        ]);
        assert!(matches!(
            verify(&mut src, &known(), &PARAMS).unwrap(),
            VerifyOutcome::Matched { frames: 6, .. }
        ));
    }

    #[test]
    fn temporal_state_handles_boundaries_identity_changes_and_resets() {
        let mut state = TemporalMatcher::new(PARAMS);
        assert!(matches!(
            state.observe(Duration::from_millis(100), Some((0, 0.9))),
            TemporalDecision::Progress { count: 1, .. }
        ));
        assert!(matches!(
            state.observe(Duration::from_millis(150), Some((0, 0.9))),
            TemporalDecision::Progress { count: 1, .. }
        ));
        assert!(matches!(
            state.observe(Duration::from_millis(180), Some((0, 0.9))),
            TemporalDecision::Progress { count: 2, .. }
        ));
        state.reset();
        assert!(matches!(
            state.observe(Duration::from_millis(260), Some((1, 0.9))),
            TemporalDecision::Progress {
                model: 1,
                count: 1,
                ..
            }
        ));
        assert!(matches!(
            state.observe(Duration::from_millis(1800), Some((1, 0.9))),
            TemporalDecision::Progress { count: 1, .. }
        ));
        assert!(matches!(
            state.observe(Duration::from_millis(1900), Some((1, 0.1))),
            TemporalDecision::Rejected {
                similarity: Some(_),
                ..
            }
        ));
    }

    #[test]
    fn stranger_times_out_with_best_similarity() {
        let mut src = Scripted::new(vec![
            (100, BRIGHT, vec![face(0.9, &[-1.0, 0.1])]),
            (200, BRIGHT, vec![]),
            (4001, BRIGHT, vec![]),
        ]);
        let out = verify(&mut src, &known(), &PARAMS).unwrap();
        let VerifyOutcome::TimedOut {
            all_dark,
            best_similarity,
            frames,
            ..
        } = out
        else {
            panic!("{out:?}")
        };
        assert!(!all_dark);
        assert_eq!(frames, 3);
        assert!(best_similarity.unwrap() < 0.363);
        assert_eq!(out.exit(), CompareExit::TimeoutReached);
    }

    /// Nobody in view: report no face seen, not a rejected face.
    #[test]
    fn no_face_until_timeout_is_reported_as_no_face_seen() {
        let frames = (1..=45).map(|i| (i * 100, BRIGHT, vec![])).collect();
        let out = verify(&mut Scripted::new(frames), &known(), &PARAMS).unwrap();
        assert!(
            matches!(
                out,
                VerifyOutcome::TimedOut {
                    frames: 41,
                    best_similarity: None,
                    ..
                }
            ),
            "{out:?}"
        );
        assert_eq!(out.exit(), CompareExit::NoFaceSeen);
    }

    #[test]
    fn only_dark_frames_is_too_dark() {
        let mut src = Scripted::new(vec![
            (100, DARK, vec![]),
            (200, DARK, vec![]),
            (5000, DARK, vec![]),
        ]);
        let out = verify(&mut src, &known(), &PARAMS).unwrap();
        assert!(matches!(
            out,
            VerifyOutcome::TimedOut {
                all_dark: true,
                dark: 2,
                ..
            }
        ));
        assert_eq!(out.exit(), CompareExit::TooDark);
    }

    #[test]
    fn camera_failure_propagates() {
        let mut src = Scripted::new(vec![(100, BRIGHT, vec![])]);
        assert!(verify(&mut src, &known(), &PARAMS).is_err());
    }
}
