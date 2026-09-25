//! Process-isolated camera preview and enrollment: closing the dialog kills the worker, so a stuck driver read leaves no orphan.

use async_channel::{Receiver, RecvError};
use peekin_core::compare::{
    classify_frame, ChallengeMode, ChallengeOrder, ChallengeStage, ChallengeTracker, FrameClass,
    TemporalDecision, TemporalMatcher, VerifyParams,
};
use peekin_core::enroll::{enroll_with_feedback, EnrollFeedback, EnrollParams};
use peekin_core::i18n::tr_noop;
use peekin_core::matcher::best_match;
use peekin_core::models::{load_user_models, usable_embeddings};
use peekin_core::source::{DetectedFace, FaceSource, FrameStats, SourceError};
use peekin_core::{PeekinConfig, PeekinPaths};
use peekin_vision::OpenCvFaceSource;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const BOX_COLOUR: [u8; 3] = [46, 194, 126];
const BOX_THICKNESS: i32 = 3;
const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

pub struct Frame {
    pub width: i32,
    pub height: i32,
    pub rgb: Vec<u8>,
    pub faces: usize,
    pub verdict: Option<(bool, f32)>,
    pub remaining: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TestState {
    Starting = 0,
    Dark = 1,
    Covered = 2,
    NoFace = 3,
    MultipleFaces = 4,
    NoMatch = 5,
    Matching = 6,
    Match = 7,
    Challenge = 8,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct TestStatus {
    pub state: TestState,
    pub similarity: Option<f32>,
    pub streak: u8,
    pub required: u8,
    pub remaining: u32,
}

pub enum Event {
    Frame(Frame),
    Sample(usize, usize),
    Quality(String),
    /// Must never be dropped in favour of newer frames/status events.
    Challenge(String),
    Status(TestStatus),
    Finished(Result<Vec<Vec<f32>>, String>),
    Failed(String),
    FrameReady,
}

pub struct Events {
    rx: Receiver<Event>,
    latest: Arc<Mutex<Option<Frame>>>,
    frame_pending: Arc<AtomicBool>,
    control: Arc<Control>,
}

impl Drop for Events {
    fn drop(&mut self) {
        self.control.cancel.store(true, Ordering::Release);
    }
}

impl Events {
    pub async fn recv(&self) -> Result<Event, RecvError> {
        loop {
            match self.rx.recv().await? {
                Event::FrameReady => {
                    self.frame_pending.store(false, Ordering::Release);
                    if let Some(frame) = self.latest.lock().unwrap().take() {
                        return Ok(Event::Frame(frame));
                    }
                }
                event => return Ok(event),
            }
        }
    }
}

#[derive(Default)]
pub struct Control {
    pub capture: AtomicBool,
    pub cancel: AtomicBool,
    child: Mutex<Option<Child>>,
}

struct CancellableReader<R> {
    inner: R,
    control: Arc<Control>,
    deadline: Instant,
}

impl<R: Read + AsRawFd> CancellableReader<R> {
    fn new(inner: R, control: Arc<Control>, deadline: Instant) -> std::io::Result<Self> {
        let fd = inner.as_raw_fd();
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self {
            inner,
            control,
            deadline,
        })
    }
}

impl<R: Read> Read for CancellableReader<R> {
    fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.control.cancel.load(Ordering::Acquire) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::ConnectionAborted,
                    "camera operation cancelled",
                ));
            }
            if Instant::now() >= self.deadline {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "camera operation deadline exceeded",
                ));
            }
            match self.inner.read(bytes) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5))
                }
                result => return result,
            }
        }
    }
}

pub fn draw_rect(rgb: &mut [u8], width: i32, height: i32, rect: [f32; 4], colour: [u8; 3]) {
    if width <= 0 || height <= 0 {
        return;
    }
    let x0 = (rect[0].round() as i32).clamp(0, width - 1);
    let y0 = (rect[1].round() as i32).clamp(0, height - 1);
    let x1 = ((rect[0] + rect[2]).round() as i32).clamp(0, width - 1);
    let y1 = ((rect[1] + rect[3]).round() as i32).clamp(0, height - 1);
    let mut put = |x: i32, y: i32| {
        let i = ((y * width + x) * 3) as usize;
        rgb[i..i + 3].copy_from_slice(&colour);
    };
    for t in 0..BOX_THICKNESS {
        for x in x0..=x1 {
            put(x, (y0 + t).min(y1));
            put(x, (y1 - t).max(y0));
        }
        for y in y0..=y1 {
            put((x0 + t).min(x1), y);
            put((x1 - t).max(x0), y);
        }
    }
}

pub fn mirror(rgb: &mut [u8], width: i32, height: i32) {
    if width <= 0 {
        return;
    }
    let row = (width * 3) as usize;
    for line in rgb.chunks_exact_mut(row).take(height.max(0) as usize) {
        let (mut l, mut r) = (0usize, width as usize - 1);
        while l < r {
            for c in 0..3 {
                line.swap(l * 3 + c, r * 3 + c);
            }
            l += 1;
            r -= 1;
        }
    }
}

struct Previewing {
    inner: OpenCvFaceSource,
    dark_threshold: f64,
    last_at: Duration,
    t0: Duration,
    send: Box<dyn FnMut(Event) -> Result<(), SourceError>>,
}

impl FaceSource for Previewing {
    fn next_frame(&mut self) -> Result<FrameStats, SourceError> {
        let stats = self.inner.next_frame()?;
        self.last_at = stats.at;
        if matches!(
            classify_frame(&stats.hist, self.dark_threshold),
            FrameClass::Scan { .. }
        ) {
            let faces: Vec<DetectedFace> = self.inner.detect()?;
            if let Some((width, height, mut rgb)) = self.inner.last_image_rgb() {
                for face in &faces {
                    draw_rect(&mut rgb, width, height, face.rect, BOX_COLOUR);
                }
                mirror(&mut rgb, width, height);
                (self.send)(Event::Frame(Frame {
                    width,
                    height,
                    rgb,
                    faces: faces.len(),
                    verdict: None,
                    remaining: 0,
                }))?;
            }
        }
        Ok(FrameStats {
            at: stats.at.saturating_sub(self.t0),
            hist: stats.hist,
        })
    }
    fn analyze(&mut self) -> Result<Vec<peekin_core::source::Face>, SourceError> {
        self.inner.analyze()
    }
    fn analyze_for_enrollment(&mut self) -> Result<Vec<peekin_core::source::Face>, SourceError> {
        self.inner.analyze_for_enrollment()
    }
}

fn write_packet(out: &mut impl Write, event: Event) -> std::io::Result<()> {
    let (tag, body) = match event {
        Event::Frame(f) => {
            let mut b = Vec::with_capacity(21 + f.rgb.len());
            b.extend(f.width.to_le_bytes());
            b.extend(f.height.to_le_bytes());
            b.extend((f.faces as u32).to_le_bytes());
            let (flag, similarity) = match f.verdict {
                None => (0u8, 0.0),
                Some((true, s)) => (1, s),
                Some((false, s)) => (2, s),
            };
            b.push(flag);
            b.extend(similarity.to_le_bytes());
            b.extend(f.remaining.to_le_bytes());
            b.extend(f.rgb);
            (1u8, b)
        }
        Event::Sample(n, total) => (2, serde_json::to_vec(&(n, total))?),
        Event::Finished(result) => (3, serde_json::to_vec(&result)?),
        Event::Failed(message) => (4, message.into_bytes()),
        Event::Status(status) => (
            5,
            serde_json::to_vec(&(
                status.state as u8,
                status.similarity,
                status.streak,
                status.required,
                status.remaining,
            ))?,
        ),
        Event::Quality(message) => (6, message.into_bytes()),
        Event::Challenge(message) => (7, message.into_bytes()),
        Event::FrameReady => unreachable!("FrameReady is in-process only"),
    };
    out.write_all(&[tag])?;
    out.write_all(&(body.len() as u32).to_le_bytes())?;
    out.write_all(&body)?;
    out.flush()
}

pub fn report_failure(message: String) {
    let _ = write_packet(&mut std::io::stdout(), Event::Failed(message));
}

fn read_packet(input: &mut impl Read) -> Result<Event, String> {
    let mut header = [0u8; 5];
    input.read_exact(&mut header).map_err(|e| e.to_string())?;
    let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
    let limit = match header[0] {
        1 => MAX_FRAME_BYTES,
        3 => 256 * 1024,
        2 | 4 | 5 | 6 | 7 => 4096,
        _ => return Err("invalid preview packet type".into()),
    };
    if len > limit {
        return Err("preview packet exceeds limit".into());
    }
    let mut body = vec![0; len];
    input.read_exact(&mut body).map_err(|e| e.to_string())?;
    match header[0] {
        1 if len >= 21 => {
            let width = i32::from_le_bytes(body[0..4].try_into().unwrap());
            let height = i32::from_le_bytes(body[4..8].try_into().unwrap());
            let faces = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
            let flag = body[12];
            let similarity = f32::from_le_bytes(body[13..17].try_into().unwrap());
            let remaining = u32::from_le_bytes(body[17..21].try_into().unwrap());
            let verdict = match flag {
                0 => None,
                1 => Some((true, similarity)),
                2 => Some((false, similarity)),
                _ => return Err("invalid preview verdict".into()),
            };
            let rgb = body.split_off(21);
            let expected = (width as usize)
                .checked_mul(height as usize)
                .and_then(|n| n.checked_mul(3));
            if width <= 0 || height <= 0 || expected != Some(rgb.len()) || !similarity.is_finite() {
                return Err("invalid preview frame".into());
            }
            Ok(Event::Frame(Frame {
                width,
                height,
                rgb,
                faces,
                verdict,
                remaining,
            }))
        }
        2 => {
            let (n, total) = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            if total == 0 || total > 20 || n > total {
                return Err("invalid sample progress".into());
            }
            Ok(Event::Sample(n, total))
        }
        3 => Ok(Event::Finished(
            serde_json::from_slice(&body).map_err(|e| e.to_string())?,
        )),
        4 => Ok(Event::Failed(String::from_utf8_lossy(&body).into_owned())),
        5 => {
            let (state, similarity, streak, required, remaining): (u8, Option<f32>, u8, u8, u32) =
                serde_json::from_slice(&body).map_err(|e| e.to_string())?;
            let state = match state {
                0 => TestState::Starting,
                1 => TestState::Dark,
                2 => TestState::Covered,
                3 => TestState::NoFace,
                4 => TestState::MultipleFaces,
                5 => TestState::NoMatch,
                6 => TestState::Matching,
                7 => TestState::Match,
                8 => TestState::Challenge,
                _ => return Err("invalid test status".into()),
            };
            if similarity.is_some_and(|s| !s.is_finite())
                || required < 2
                || streak > required
                || remaining > 30
            {
                return Err("invalid test status values".into());
            }
            Ok(Event::Status(TestStatus {
                state,
                similarity,
                streak,
                required,
                remaining,
            }))
        }
        6 => Ok(Event::Quality(String::from_utf8_lossy(&body).into_owned())),
        7 => Ok(Event::Challenge(
            String::from_utf8_lossy(&body).into_owned(),
        )),
        _ => Err("invalid preview packet".into()),
    }
}

/// Hidden worker mode, invoked before GTK initialization.
pub fn worker_main(config_dir: &Path, data_dir: &Path) -> Result<(), String> {
    let capture = Arc::new(AtomicBool::new(false));
    let capture_reader = capture.clone();
    std::thread::spawn(move || {
        let mut byte = [0];
        loop {
            match std::io::stdin().read_exact(&mut byte) {
                Ok(()) if byte[0] == b'C' => capture_reader.store(true, Ordering::Release),
                _ => unsafe { libc::_exit(0) },
            }
        }
    });
    let paths = PeekinPaths::from_dirs(config_dir.into(), data_dir.into());
    let config = PeekinConfig::load(&paths.config_file_path()).map_err(|e| e.to_string())?;
    let source = OpenCvFaceSource::open(&config, &paths).map_err(|e| e.to_string())?;
    let out = Arc::new(Mutex::new(std::io::stdout()));
    let writer = out.clone();
    let mut preview = Previewing {
        inner: source,
        dark_threshold: config.dark_threshold(),
        last_at: Duration::ZERO,
        t0: Duration::ZERO,
        send: Box::new(move |e| {
            write_packet(&mut *writer.lock().unwrap(), e).map_err(|x| SourceError(x.to_string()))
        }),
    };
    preview.inner.set_keep_image(true);
    while !capture.load(Ordering::Acquire) {
        preview.next_frame().map_err(|e| e.0)?;
    }
    preview.t0 = preview.last_at;
    let params = EnrollParams::with_dark_threshold(config.dark_threshold());
    let writer = out.clone();
    let result = enroll_with_feedback(&mut preview, &params, |feedback| {
        let event = match feedback {
            EnrollFeedback::Sample(n, total) => Event::Sample(n, total),
            EnrollFeedback::Settling => {
                Event::Quality(tr_noop("Waiting for camera exposure…").into())
            }
            EnrollFeedback::Covered => Event::Quality(tr_noop("Camera appears covered").into()),
            EnrollFeedback::TooDark => Event::Quality(tr_noop("Image is too dark").into()),
            EnrollFeedback::NoFace => Event::Quality(tr_noop("Move your face into view").into()),
            EnrollFeedback::MultipleFaces => {
                Event::Quality(tr_noop("Only one person may be visible").into())
            }
            EnrollFeedback::LowConfidence => {
                Event::Quality(tr_noop("Hold still and face the camera").into())
            }
            EnrollFeedback::TooSmall => Event::Quality(tr_noop("Move closer to the camera").into()),
            EnrollFeedback::Blurry => Event::Quality(tr_noop("Image is blurry; hold still").into()),
            EnrollFeedback::Pose => Event::Quality(tr_noop("Look straight at the camera").into()),
            EnrollFeedback::Inconsistent => {
                Event::Quality(tr_noop("Face samples are inconsistent").into())
            }
        };
        let _ = write_packet(&mut *writer.lock().unwrap(), event);
    });
    let sent = write_packet(
        &mut *out.lock().unwrap(),
        Event::Finished(result.map_err(|e| e.to_string())),
    )
    .map_err(|e| e.to_string());
    sent
}

pub fn test_worker_main(
    config_dir: &Path,
    data_dir: &Path,
    user: &str,
    seconds: u32,
) -> Result<(), String> {
    peekin_core::paths::validate_username(user).map_err(|e| e.to_string())?;
    if !(1..=30).contains(&seconds) {
        return Err("invalid test duration".into());
    }
    std::thread::spawn(|| {
        let mut byte = [0];
        let _ = std::io::stdin().read(&mut byte);
        unsafe { libc::_exit(0) }
    });
    let paths = PeekinPaths::from_dirs(config_dir.into(), data_dir.into());
    let config = PeekinConfig::load(&paths.config_file_path()).map_err(|e| e.to_string())?;
    if !config.security_errors().is_empty() {
        return Err("security-critical configuration is invalid".into());
    }
    let known = usable_embeddings(
        &load_user_models(paths.user_models_dir(), user).map_err(|e| e.to_string())?,
    );
    if known.is_empty() {
        return Err("no usable face model; enroll first".into());
    }
    let mut source = OpenCvFaceSource::open(&config, &paths).map_err(|e| e.to_string())?;
    source.set_keep_image(true);
    let mut out = std::io::stdout();
    let camera = peekin_core::cameras::kind_of(source.device());
    let mode = ChallengeMode::for_config(config.movement_required(camera))
        .map_err(|e| format!("cannot create face challenge: {e}"))?;
    let scan_time = Duration::from_secs(config.attempt_secs(mode.is_movement()) as u64)
        .min(Duration::from_secs(seconds as u64));
    let params = VerifyParams::authentication(
        scan_time,
        config.dark_threshold(),
        config.effective_min_similarity(&known),
    );
    let mut temporal = TemporalMatcher::new(params);
    let mut movement: Option<ChallengeTracker> = None;
    let mut accepted = false;
    loop {
        let stats = source.next_frame().map_err(|e| e.0)?;
        if stats.at >= scan_time {
            break;
        }
        let remaining = (scan_time.as_secs() as u32).saturating_sub(stats.at.as_secs() as u32);
        let class = classify_frame(&stats.hist, config.dark_threshold());
        if !matches!(class, FrameClass::Scan { .. }) {
            // IR emitters may alternate lit and unlit frames; unlit ones do not count.
            write_packet(
                &mut out,
                Event::Status(TestStatus {
                    state: if matches!(class, FrameClass::Black) {
                        TestState::Covered
                    } else {
                        TestState::Dark
                    },
                    similarity: None,
                    streak: 0,
                    required: params.required_matches,
                    remaining,
                }),
            )
            .map_err(|e| e.to_string())?;
            continue;
        }
        let faces = source.analyze().map_err(|e| e.0)?;
        // Same sample policy as `verify_with_challenge`.
        let (candidate, yaw) = if let [face] = faces.as_slice() {
            (best_match(&known, &face.embedding), face.yaw)
        } else {
            (None, None)
        };
        let sample = candidate
            .zip(yaw)
            .map(|((model, similarity), yaw)| (model, similarity, yaw));
        let status = if let Some(tracker) = movement.as_mut() {
            let prior = tracker.stage();
            let stage = tracker.observe(stats.at, sample, &params);
            let ChallengeMode::Movement(challenge) = mode else {
                unreachable!("a tracker only exists in movement mode")
            };
            if stage != prior {
                // Challenge instructions use the reliable event channel so none is dropped under a frame flood.
                write_packet(&mut out, Event::Challenge(stage.instruction(challenge)))
                    .map_err(|e| e.to_string())?;
            }
            if stage == ChallengeStage::Failed {
                write_packet(
                    &mut out,
                    Event::Finished(Err(tr_noop(
                        "Movement challenge failed (wrong order, missed step, or too slow); \
                         use your password or retry",
                    )
                    .into())),
                )
                .map_err(|e| e.to_string())?;
                return Ok(());
            }
            TestStatus {
                state: if stage == ChallengeStage::Complete {
                    TestState::Match
                } else {
                    TestState::Challenge
                },
                similarity: candidate.map(|(_, similarity)| similarity),
                streak: stage.number(),
                required: ChallengeOrder::STAGES,
                remaining,
            }
        } else {
            let decision = temporal.observe(stats.at, candidate);
            match (faces.len(), decision) {
                (0, _) => TestStatus {
                    state: TestState::NoFace,
                    similarity: None,
                    streak: 0,
                    required: params.required_matches,
                    remaining,
                },
                (count, _) if count > 1 => TestStatus {
                    state: TestState::MultipleFaces,
                    similarity: None,
                    streak: 0,
                    required: params.required_matches,
                    remaining,
                },
                (_, TemporalDecision::Rejected { similarity }) => TestStatus {
                    state: TestState::NoMatch,
                    similarity,
                    streak: 0,
                    required: params.required_matches,
                    remaining,
                },
                (
                    _,
                    TemporalDecision::Progress {
                        similarity, count, ..
                    },
                ) => TestStatus {
                    state: TestState::Matching,
                    similarity: Some(similarity),
                    streak: count,
                    required: params.required_matches,
                    remaining,
                },
                (_, TemporalDecision::Accepted { model, similarity }) => match mode {
                    ChallengeMode::Movement(challenge) => {
                        movement = Some(ChallengeTracker::new(challenge, model));
                        write_packet(&mut out, Event::Challenge(challenge.prompt()))
                            .map_err(|e| e.to_string())?;
                        TestStatus {
                            state: TestState::Challenge,
                            similarity: Some(similarity),
                            streak: 1,
                            required: ChallengeOrder::STAGES,
                            remaining,
                        }
                    }
                    ChallengeMode::Passive => TestStatus {
                        state: TestState::Match,
                        similarity: Some(similarity),
                        streak: params.required_matches,
                        required: params.required_matches,
                        remaining,
                    },
                },
            }
        };
        write_packet(&mut out, Event::Status(status)).map_err(|e| e.to_string())?;
        let verdict = status
            .similarity
            .map(|similarity| (status.state == TestState::Match, similarity));
        if let Some((width, height, mut rgb)) = source.last_image_rgb() {
            for face in &faces {
                draw_rect(
                    &mut rgb,
                    width,
                    height,
                    face.rect,
                    if verdict.is_some_and(|v| v.0) {
                        BOX_COLOUR
                    } else {
                        [224, 27, 36]
                    },
                );
            }
            mirror(&mut rgb, width, height);
            write_packet(
                &mut out,
                Event::Frame(Frame {
                    width,
                    height,
                    rgb,
                    faces: faces.len(),
                    verdict,
                    remaining,
                }),
            )
            .map_err(|e| e.to_string())?;
        }
        if status.state == TestState::Match {
            accepted = true;
            break;
        }
    }
    write_packet(
        &mut out,
        Event::Finished(if accepted {
            Ok(Vec::new())
        } else {
            Err(match mode {
                ChallengeMode::Movement(_) => tr_noop(
                    "No face completed the identity and movement challenge before the timeout",
                ),
                ChallengeMode::Passive => {
                    tr_noop("No enrolled face was recognised before the timeout")
                }
            }
            .into())
        }),
    )
    .map_err(|e| e.to_string())
}

fn terminate_child(child: &mut Child) {
    // EOF reaches a root broker even when we have no signal permission.
    child.stdin.take();
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_secs(2);
    while Instant::now() < deadline {
        if child.try_wait().ok().flatten().is_some() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

fn start_command(mut command: Command, max_runtime: Duration) -> (Events, Arc<Control>) {
    let (tx, rx) = async_channel::bounded(64);
    let latest = Arc::new(Mutex::new(None));
    let frame_pending = Arc::new(AtomicBool::new(false));
    let control = Arc::new(Control::default());
    let terminal = Arc::new(AtomicBool::new(false));
    let deadline = Instant::now() + max_runtime;
    match command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            let stdout = child.stdout.take();
            *control.child.lock().unwrap() = Some(child);
            let reader_tx = tx.clone();
            let (reader_latest, reader_pending) = (latest.clone(), frame_pending.clone());
            let reader_control = control.clone();
            let reader_terminal = terminal.clone();
            std::thread::spawn(move || {
                let Some(stdout) = stdout else {
                    let _ = reader_tx
                        .send_blocking(Event::Failed("preview worker has no output".into()));
                    return;
                };
                let mut stdout =
                    match CancellableReader::new(stdout, reader_control.clone(), deadline) {
                        Ok(reader) => reader,
                        Err(error) => {
                            reader_control.cancel.store(true, Ordering::Release);
                            reader_terminal.store(true, Ordering::Release);
                            let _ = reader_tx.send_blocking(Event::Failed(error.to_string()));
                            return;
                        }
                    };
                loop {
                    match read_packet(&mut stdout) {
                        Ok(Event::Frame(f)) => {
                            *reader_latest.lock().unwrap() = Some(f);
                            if !reader_pending.swap(true, Ordering::AcqRel)
                                && reader_tx.try_send(Event::FrameReady).is_err()
                            {
                                reader_pending.store(false, Ordering::Release);
                            }
                        }
                        Ok(e) => {
                            let done = matches!(e, Event::Finished(_) | Event::Failed(_));
                            if done && reader_terminal.swap(true, Ordering::AcqRel) {
                                break;
                            }
                            let ephemeral = matches!(
                                &e,
                                Event::Quality(_)
                                    | Event::Status(TestStatus {
                                        state: TestState::Starting
                                            | TestState::Dark
                                            | TestState::Covered
                                            | TestState::NoFace
                                            | TestState::MultipleFaces
                                            | TestState::NoMatch
                                            | TestState::Matching
                                            | TestState::Challenge,
                                        ..
                                    })
                            );
                            if ephemeral {
                                let _ = reader_tx.try_send(e);
                                continue;
                            }
                            if reader_tx.send_blocking(e).is_err() {
                                reader_control.cancel.store(true, Ordering::Release);
                                break;
                            }
                            if done {
                                reader_control.cancel.store(true, Ordering::Release);
                                break;
                            }
                        }
                        Err(e) => {
                            if !reader_terminal.swap(true, Ordering::AcqRel) {
                                let _ = reader_tx.send_blocking(Event::Failed(e));
                            }
                            reader_control.cancel.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            });
            let ctl = control.clone();
            let monitor_terminal = terminal.clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_millis(20));
                let mut guard = ctl.child.lock().unwrap();
                let Some(child) = guard.as_mut() else {
                    break;
                };
                if ctl.cancel.load(Ordering::Acquire) || Instant::now() >= deadline {
                    let timed_out = !ctl.cancel.load(Ordering::Acquire);
                    if !monitor_terminal.swap(true, Ordering::AcqRel) {
                        let _ = tx.send_blocking(Event::Failed(if timed_out {
                            "camera operation deadline exceeded".into()
                        } else {
                            "camera operation cancelled".into()
                        }));
                    }
                    terminate_child(child);
                    *guard = None;
                    break;
                }
                if ctl.capture.swap(false, Ordering::AcqRel) {
                    if let Some(stdin) = child.stdin.as_mut() {
                        let _ = stdin.write_all(b"C");
                    }
                }
                if child.try_wait().ok().flatten().is_some()
                    && monitor_terminal.load(Ordering::Acquire)
                {
                    *guard = None;
                    break;
                }
            });
        }
        Err(e) => {
            let _ = tx.send_blocking(Event::Failed(format!("cannot start preview worker: {e}")));
        }
    }
    (
        Events {
            rx,
            latest,
            frame_pending,
            control: control.clone(),
        },
        control,
    )
}

pub fn start(config_dir: PathBuf, data_dir: PathBuf) -> (Events, Arc<Control>) {
    let mut command = Command::new(std::env::current_exe().expect("current executable"));
    command.args([
        "--preview-worker",
        &config_dir.display().to_string(),
        &data_dir.display().to_string(),
    ]);
    start_command(command, Duration::from_secs(120))
}

pub fn start_test_command(argv: &[String], seconds: u32) -> (Events, Arc<Control>) {
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    start_command(command, Duration::from_secs(seconds as u64 + 15))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn px(rgb: &[u8], w: i32, x: i32, y: i32) -> [u8; 3] {
        let i = ((y * w + x) * 3) as usize;
        [rgb[i], rgb[i + 1], rgb[i + 2]]
    }
    #[test]
    fn rect_outline_is_drawn_and_clamped() {
        let (w, h) = (20, 10);
        let mut img = vec![0; (w * h * 3) as usize];
        draw_rect(&mut img, w, h, [2.0, 2.0, 30.0, 30.0], [1, 2, 3]);
        assert_eq!(px(&img, w, 2, 2), [1, 2, 3]);
        assert_eq!(px(&img, w, 19, 9), [1, 2, 3]);
        assert_eq!(px(&img, w, 10, 7), [1, 2, 3]);
        assert_eq!(px(&img, w, 10, 6), [0, 0, 0]);
        assert_eq!(px(&img, w, 0, 0), [0, 0, 0]);
    }
    #[test]
    fn mirror_flips_rows() {
        let (w, h) = (3, 2);
        let mut img: Vec<u8> = (0..(w * h * 3) as u8).collect();
        mirror(&mut img, w, h);
        assert_eq!(&img[0..9], &[6, 7, 8, 3, 4, 5, 0, 1, 2]);
        assert_eq!(&img[9..18], &[15, 16, 17, 12, 13, 14, 9, 10, 11]);
    }

    fn fake(script: &str, runtime: Duration) -> (Events, Arc<Control>) {
        let mut command = Command::new("/bin/sh");
        command.args(["-c", script]);
        start_command(command, runtime)
    }

    fn terminal(events: &Events) -> Event {
        let until = Instant::now() + Duration::from_secs(3);
        while Instant::now() < until {
            if let Ok(event) = events.rx.try_recv() {
                if matches!(event, Event::Finished(_) | Event::Failed(_)) {
                    return event;
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        panic!("no terminal event within watchdog bound")
    }

    #[test]
    fn stalled_and_truncated_workers_terminate_without_camera_hardware() {
        let (events, _) = fake("exec sleep 30", Duration::from_millis(100));
        assert!(matches!(terminal(&events), Event::Failed(_)));
        let (events, _) = fake("printf '\\003\\377'", Duration::from_secs(1));
        assert!(matches!(terminal(&events), Event::Failed(_)));
    }

    #[test]
    fn completed_packet_wins_over_fast_process_exit() {
        let (events, _) = fake(
            "printf '\\003\\011\\000\\000\\000{\"Ok\":[]}'",
            Duration::from_secs(1),
        );
        assert!(matches!(terminal(&events), Event::Finished(Ok(values)) if values.is_empty()));
    }

    #[test]
    fn cancellation_and_receiver_drop_stop_the_child() {
        let (events, control) = fake("exec sleep 30", Duration::from_secs(30));
        control.cancel.store(true, Ordering::Release);
        assert!(matches!(terminal(&events), Event::Failed(_)));
        drop(events);
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline && control.child.lock().unwrap().is_some() {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(control.child.lock().unwrap().is_none());
        let (events, control) = fake("exec sleep 30", Duration::from_secs(30));
        drop(events);
        assert!(control.cancel.load(Ordering::Acquire));
    }

    #[test]
    fn malformed_and_oversized_packets_fail_before_allocation() {
        assert!(read_packet(&mut &b"\x01\xff\xff\xff\xff"[..]).is_err());
        assert!(read_packet(&mut &b"\x06\x01\x10\x00\x00"[..]).is_err());
        let mut bytes = Vec::new();
        write_packet(&mut bytes, Event::Sample(5, 0)).unwrap();
        assert!(read_packet(&mut bytes.as_slice()).is_err());
    }

    #[test]
    fn challenge_instructions_survive_ipc_framing() {
        let mut encoded = Vec::new();
        write_packet(&mut encoded, Event::Challenge("Turn your head LEFT".into())).unwrap();
        assert!(
            matches!(read_packet(&mut encoded.as_slice()), Ok(Event::Challenge(message)) if message == "Turn your head LEFT")
        );
    }
}
