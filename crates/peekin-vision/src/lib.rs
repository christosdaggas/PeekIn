//! Camera capture and face recognition with OpenCV (YuNet detection, SFace embeddings).
//! The movement challenge resists photos and fixed recordings but is not certified PAD (ISO/IEC 30107).

use opencv::{core, imgcodecs, imgproc, objdetect, prelude::*, videoio};
use peekin_core::cameras::{self, CameraKind};
use peekin_core::compare::{rotation_for_frame, FrameRotation};
use peekin_core::source::{DetectedFace, Face, FaceSource, FrameStats, SourceError};
use peekin_core::{PeekinConfig, PeekinPaths};
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;

/// Access is gated by the recognition threshold, not by this one.
const DETECT_THRESHOLD: f32 = 0.6;
const NMS_THRESHOLD: f32 = 0.3;
const TOP_K: i32 = 5000;
/// FOURCC for MJPG (`force_mjpeg`).
const MJPEG_FOURCC: f64 = 1_196_444_237.0;

#[derive(Debug, Error)]
pub enum OpenError {
    #[error("face models missing: {0} (run fetch-models.sh)")]
    MissingModels(String),
    #[error("PeekIn could not find a camera: {0}")]
    NoDevice(String),
    /// The configured node is not approved, or (automatic selection) none is.
    #[error("{0}")]
    NotInfrared(String),
    #[error("cannot open camera {0}: {1}")]
    Camera(String, String),
    #[error("cannot load face models: {0}")]
    Models(String),
    #[error("camera {0} rejected required capture property {1}")]
    Capability(String, String),
}

impl From<opencv::Error> for OpenError {
    fn from(e: opencv::Error) -> Self {
        OpenError::Models(e.to_string())
    }
}

fn cv(e: opencv::Error) -> SourceError {
    SourceError(format!("OpenCV error: {e}"))
}

fn model_path(p: &Path) -> Result<&str, OpenError> {
    if !p.is_file() {
        return Err(OpenError::MissingModels(p.display().to_string()));
    }
    p.to_str()
        .ok_or_else(|| OpenError::MissingModels(format!("non-UTF-8 path {}", p.display())))
}

pub struct OpenCvFaceSource {
    device: std::path::PathBuf,
    cam: videoio::VideoCapture,
    detector: core::Ptr<objdetect::FaceDetectorYN>,
    recognizer: core::Ptr<objdetect::FaceRecognizerSF>,
    clahe: core::Ptr<imgproc::CLAHE>,
    frame: core::Mat,
    gray: core::Mat,
    equalized: core::Mat,
    analysis_input: core::Mat,
    detector_input: core::Mat,
    detected: core::Mat,
    prepared_frame: Option<u64>,
    detected_frame: Option<u64>,
    keep_image: bool,
    rotate_mode: i64,
    locked_rotation: Option<FrameRotation>,
    current_rotation: FrameRotation,
    exposure: i64,
    max_height: f64,
    dark_threshold: f64,
    frames: u64,
    opened: Instant,
    warnings: Vec<String>,
    timings: StageTimings,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct StageTimings {
    pub models: Duration,
    pub camera: Duration,
    pub first_frame: Option<Duration>,
    pub first_usable: Option<Duration>,
    pub detection: Duration,
    pub recognition: Duration,
    pub detections: u64,
    pub recognitions: u64,
}

impl OpenCvFaceSource {
    pub fn open(config: &PeekinConfig, paths: &PeekinPaths) -> Result<Self, OpenError> {
        configure_opencv();
        let device_path =
            cameras::resolve_for(&config.device_path(), config.ir_only()).map_err(|e| match e {
                cameras::ResolveError::NoInfrared => OpenError::NotInfrared(e.to_string()),
                other => OpenError::NoDevice(other.to_string()),
            })?;
        let device = device_path.display().to_string();
        if config.ir_only() && cameras::kind_of(&device_path) != Some(CameraKind::VerifiedInfrared)
        {
            return Err(OpenError::NotInfrared(format!(
                "{device} is not an approved infrared camera, and ir_only = true allows only those"
            )));
        }
        let models_started = Instant::now();
        let detector_model = paths.face_detector_model_path();
        let recognizer_model = paths.face_recognizer_model_path();
        let detector = objdetect::FaceDetectorYN::create(
            model_path(&detector_model)?,
            "",
            core::Size::new(640, 480),
            DETECT_THRESHOLD,
            NMS_THRESHOLD,
            TOP_K,
            0,
            0,
        )?;
        let recognizer =
            objdetect::FaceRecognizerSF::create(model_path(&recognizer_model)?, "", 0, 0)?;
        let models_time = models_started.elapsed();
        let mut warnings = Vec::new();
        let plugin = config.recording_plugin();
        if plugin != "opencv" {
            warnings.push(format!(
                "recording_plugin = {plugin} is not supported, using opencv"
            ));
        }

        let camera_err = |e: opencv::Error| OpenError::Camera(device.clone(), e.to_string());
        let camera_started = Instant::now();
        let mut cam =
            videoio::VideoCapture::from_file(&device, videoio::CAP_V4L2).map_err(camera_err)?;
        if !cam.is_opened().map_err(camera_err)? {
            return Err(OpenError::Camera(
                device.clone(),
                "device did not open".into(),
            ));
        }
        let fps = config.device_fps();
        let mut set = |property, value: f64, name: &str| -> Result<(), OpenError> {
            if !cam.set(property, value).map_err(camera_err)? {
                if matches!(name, "frame_width" | "frame_height") {
                    warnings.push(format!("camera cannot set {name}; using its negotiated size with bounded detector input"));
                    return Ok(());
                }
                return Err(OpenError::Capability(device.clone(), name.into()));
            }
            Ok(())
        };
        if fps > 0 {
            set(videoio::CAP_PROP_FPS, fps as f64, "device_fps")?;
        }
        if config.force_mjpeg() {
            set(videoio::CAP_PROP_FOURCC, MJPEG_FOURCC, "force_mjpeg")?;
        }
        let (w, h) = (config.frame_width(), config.frame_height());
        if w != -1 {
            set(videoio::CAP_PROP_FRAME_WIDTH, w as f64, "frame_width")?;
        }
        if h != -1 {
            set(videoio::CAP_PROP_FRAME_HEIGHT, h as f64, "frame_height")?;
        }
        let negotiated = (
            cam.get(videoio::CAP_PROP_FRAME_WIDTH).map_err(camera_err)?,
            cam.get(videoio::CAP_PROP_FRAME_HEIGHT)
                .map_err(camera_err)?,
        );
        if !negotiated.0.is_finite()
            || !negotiated.1.is_finite()
            || negotiated.0 <= 0.0
            || negotiated.1 <= 0.0
            || negotiated.0 > 8192.0
            || negotiated.1 > 8192.0
        {
            return Err(OpenError::Capability(
                device.clone(),
                "negotiated frame size".into(),
            ));
        }
        if (w > 0 && (negotiated.0 - w as f64).abs() > 2.0)
            || (h > 0 && (negotiated.1 - h as f64).abs() > 2.0)
        {
            warnings.push(format!(
                "requested {w}x{h}, negotiated {}x{}; detector input remains bounded",
                negotiated.0, negotiated.1
            ));
        }
        if fps > 0 {
            let actual = cam.get(videoio::CAP_PROP_FPS).map_err(camera_err)?;
            if !actual.is_finite() || actual <= 0.0 || (actual - fps as f64).abs() > 1.0 {
                return Err(OpenError::Capability(
                    device.clone(),
                    format!("requested {fps} FPS, negotiated {actual}"),
                ));
            }
        }

        Ok(Self {
            device: device_path,
            cam,
            detector,
            recognizer,
            clahe: imgproc::create_clahe(2.0, core::Size::new(8, 8))?,
            frame: core::Mat::default(),
            gray: core::Mat::default(),
            equalized: core::Mat::default(),
            analysis_input: core::Mat::default(),
            detector_input: core::Mat::default(),
            detected: core::Mat::default(),
            prepared_frame: None,
            detected_frame: None,
            keep_image: false,
            rotate_mode: config.rotate(),
            locked_rotation: None,
            current_rotation: FrameRotation::None,
            exposure: config.exposure(),
            max_height: config.max_height(),
            dark_threshold: config.dark_threshold(),
            frames: 0,
            opened: Instant::now(),
            warnings,
            timings: StageTimings {
                models: models_time,
                camera: camera_started.elapsed(),
                ..Default::default()
            },
        })
    }

    /// The capture node actually opened (after automatic selection).
    pub fn device(&self) -> &Path {
        &self.device
    }

    pub fn warnings(&self) -> &[String] {
        &self.warnings
    }

    pub fn set_keep_image(&mut self, keep: bool) {
        self.keep_image = keep;
    }

    /// Packed RGB (`width`, `height`, bytes); face rectangles from `analyze` refer to it.
    pub fn last_image_rgb(&self) -> Option<(i32, i32, Vec<u8>)> {
        if !self.keep_image
            || self.analysis_input.empty()
            || self.prepared_frame != Some(self.frames)
        {
            return None;
        }
        let mut rgb = core::Mat::default();
        imgproc::cvt_color_def(&self.analysis_input, &mut rgb, imgproc::COLOR_BGR2RGB).ok()?;
        let bytes = rgb.data_bytes().ok()?.to_vec();
        Some((rgb.cols(), rgb.rows(), bytes))
    }

    /// BGR copy of the last analysed image; `None` when the current frame was not analysed.
    pub fn last_image(&self) -> Option<core::Mat> {
        if self.analysis_input.empty() || self.prepared_frame != Some(self.frames) {
            return None;
        }
        self.analysis_input.try_clone().ok()
    }

    pub fn frame_size(&self) -> (f64, f64) {
        let get = |p| self.cam.get(p).unwrap_or(0.0);
        (
            get(videoio::CAP_PROP_FRAME_WIDTH),
            get(videoio::CAP_PROP_FRAME_HEIGHT),
        )
    }

    pub fn timings(&self) -> StageTimings {
        self.timings
    }

    fn prepare_input(&mut self) -> Result<(), SourceError> {
        if self.prepared_frame == Some(self.frames) {
            return Ok(());
        }
        self.current_rotation = self
            .locked_rotation
            .unwrap_or_else(|| rotation_for_frame(self.rotate_mode, self.frames));
        let code = match self.current_rotation {
            FrameRotation::None => None,
            FrameRotation::Clockwise => Some(core::ROTATE_90_CLOCKWISE),
            FrameRotation::CounterClockwise => Some(core::ROTATE_90_COUNTERCLOCKWISE),
        };
        if let Some(code) = code {
            let bgr = if self.frame.channels() == 1 {
                imgproc::cvt_color_def(&self.frame, &mut self.gray, imgproc::COLOR_GRAY2BGR)
                    .map_err(cv)?;
                &self.gray
            } else {
                &self.frame
            };
            core::rotate(bgr, &mut self.analysis_input, code).map_err(cv)?;
        } else if self.frame.channels() == 1 {
            imgproc::cvt_color_def(
                &self.frame,
                &mut self.analysis_input,
                imgproc::COLOR_GRAY2BGR,
            )
            .map_err(cv)?;
        } else {
            // Mat::clone() deep-copies; swap reusable buffers instead.
            std::mem::swap(&mut self.frame, &mut self.analysis_input);
        }
        self.prepared_frame = Some(self.frames);
        Ok(())
    }

    fn detect_matrix(&mut self) -> Result<(), SourceError> {
        if self.detected_frame == Some(self.frames) {
            return Ok(());
        }
        self.prepare_input()?;
        let input = &self.analysis_input;
        let h = input.rows();
        let scale = if self.max_height > 0.0 && h as f64 > self.max_height {
            self.max_height as f32 / h as f32
        } else {
            1.0
        };
        let detect_input = if scale < 1.0 {
            let size = core::Size::new(
                ((input.cols() as f32 * scale).round() as i32).max(1),
                ((h as f32 * scale).round() as i32).max(1),
            );
            imgproc::resize(
                input,
                &mut self.detector_input,
                size,
                0.0,
                0.0,
                imgproc::INTER_AREA,
            )
            .map_err(cv)?;
            &self.detector_input
        } else {
            input
        };
        let detected_size = detect_input.size().map_err(cv)?;
        let original_size = input.size().map_err(cv)?;
        let started = Instant::now();
        self.detector
            .set_input_size(detect_input.size().map_err(cv)?)
            .map_err(cv)?;
        self.detector
            .detect(detect_input, &mut self.detected)
            .map_err(cv)?;
        self.timings.detection += started.elapsed();
        self.timings.detections += 1;
        // Keep an orientation that found a single face so temporal matching can succeed.
        if self.rotate_mode != 0 && self.detected.rows() == 1 {
            self.locked_rotation = Some(self.current_rotation);
        }
        remap_detections(&mut self.detected, original_size, detected_size)?;
        self.detected_frame = Some(self.frames);
        Ok(())
    }

    fn analyze_internal(&mut self, quality: bool) -> Result<Vec<Face>, SourceError> {
        self.detect_matrix()?;
        let faces = &self.detected;
        let mut out = Vec::with_capacity(faces.rows().max(0) as usize);
        for row in 0..faces.rows() {
            let score = *faces.at_2d::<f32>(row, 14).map_err(cv)?;
            let mut rect = [0f32; 4];
            for (i, v) in rect.iter_mut().enumerate() {
                *v = *faces.at_2d::<f32>(row, i as i32).map_err(cv)?;
            }
            if faces.rows() != 1 {
                out.push(Face {
                    score,
                    rect,
                    embedding: Vec::new(),
                    sharpness: None,
                    pose_imbalance: None,
                    yaw: None,
                });
                continue;
            }
            let face_box = faces.row(row).map_err(cv)?;
            let mut aligned = core::Mat::default();
            let recognition_started = Instant::now();
            self.recognizer
                .align_crop(&self.analysis_input, &face_box, &mut aligned)
                .map_err(cv)?;
            let eye_right = *faces.at_2d::<f32>(row, 4).map_err(cv)?;
            let eye_left = *faces.at_2d::<f32>(row, 6).map_err(cv)?;
            let nose = *faces.at_2d::<f32>(row, 8).map_err(cv)?;
            let yaw = landmark_yaw(eye_right, eye_left, nose);
            let (sharpness, pose_imbalance) = if quality {
                let mut aligned_gray = core::Mat::default();
                imgproc::cvt_color_def(&aligned, &mut aligned_gray, imgproc::COLOR_BGR2GRAY)
                    .map_err(cv)?;
                let mut laplacian = core::Mat::default();
                imgproc::laplacian(
                    &aligned_gray,
                    &mut laplacian,
                    core::CV_64F,
                    3,
                    1.0,
                    0.0,
                    core::BORDER_DEFAULT,
                )
                .map_err(cv)?;
                let (mut mean, mut deviation) = (core::Scalar::default(), core::Scalar::default());
                core::mean_std_dev(&laplacian, &mut mean, &mut deviation, &core::no_array())
                    .map_err(cv)?;
                let value = |col| faces.at_2d::<f32>(row, col).copied().map_err(cv);
                let eye_tilt = (value(5)? - value(7)?).abs() / rect[3].max(1.0);
                let nose_offset = (value(8)? - (rect[0] + rect[2] / 2.0)).abs() / rect[2].max(1.0);
                (
                    Some((deviation[0] * deviation[0]) as f32),
                    Some(eye_tilt.max(nose_offset)),
                )
            } else {
                (None, None)
            };
            let mut feature = core::Mat::default();
            self.recognizer
                .feature(&aligned, &mut feature)
                .map_err(cv)?;
            let raw = feature.data_typed::<f32>().map_err(cv)?;
            let norm = raw
                .iter()
                .map(|x| x * x)
                .sum::<f32>()
                .sqrt()
                .max(f32::EPSILON);
            out.push(Face {
                score,
                rect,
                embedding: raw.iter().map(|x| x / norm).collect(),
                sharpness,
                pose_imbalance,
                yaw,
            });
            self.timings.recognition += recognition_started.elapsed();
            self.timings.recognitions += 1;
        }
        Ok(out)
    }
}

pub fn jpeg(image: &core::Mat) -> Result<Vec<u8>, String> {
    let mut buf = core::Vector::<u8>::new();
    let params = core::Vector::from_slice(&[imgcodecs::IMWRITE_JPEG_QUALITY, 85]);
    match imgcodecs::imencode(".jpg", image, &mut buf, &params) {
        Ok(true) => Ok(buf.to_vec()),
        Ok(false) => Err("JPEG encoding failed".into()),
        Err(e) => Err(e.to_string()),
    }
}

/// CPU-only inference and a small thread pool, for fast start-up within the worker's limits.
fn configure_opencv() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = core::set_use_opencl(false);
        let threads = std::thread::available_parallelism()
            .map_or(1, |n| n.get())
            .min(peekin_core::process::MAX_WORKER_THREADS);
        let _ = core::set_num_threads(threads as i32);
    });
}

fn remap_detections(
    faces: &mut core::Mat,
    original: core::Size,
    resized: core::Size,
) -> Result<(), SourceError> {
    if resized.width <= 0 || resized.height <= 0 {
        return Err(SourceError("invalid detector size".into()));
    }
    let (sx, sy) = (
        original.width as f32 / resized.width as f32,
        original.height as f32 / resized.height as f32,
    );
    for row in 0..faces.rows() {
        for col in 0..14 {
            *faces.at_2d_mut::<f32>(row, col).map_err(cv)? *= if col % 2 == 0 { sx } else { sy };
        }
    }
    Ok(())
}

fn landmark_yaw(eye_right: f32, eye_left: f32, nose: f32) -> Option<f32> {
    let span = (eye_left - eye_right).abs();
    (span >= 4.0)
        .then_some((nose - (eye_right + eye_left) / 2.0) / span)
        .filter(|value| value.is_finite())
}

impl FaceSource for OpenCvFaceSource {
    fn next_frame(&mut self) -> Result<FrameStats, SourceError> {
        if self.exposure != -1 {
            // Some cameras only honour manual exposure when set every frame.
            let auto_set = self
                .cam
                .set(videoio::CAP_PROP_AUTO_EXPOSURE, 1.0)
                .map_err(cv)?;
            let exposure_set = self
                .cam
                .set(videoio::CAP_PROP_EXPOSURE, self.exposure as f64)
                .map_err(cv)?;
            if !auto_set || !exposure_set {
                return Err(SourceError("camera rejected manual exposure".into()));
            }
        }
        if !self.cam.read(&mut self.frame).map_err(cv)? || self.frame.empty() {
            return Err(SourceError(
                "The camera set in device_path returned no frame".into(),
            ));
        }
        self.frames += 1;
        self.prepared_frame = None;
        self.detected_frame = None;
        if self.timings.first_frame.is_none() {
            self.timings.first_frame = Some(self.opened.elapsed());
        }

        let gray = if self.frame.channels() == 1 {
            &self.frame
        } else {
            imgproc::cvt_color_def(&self.frame, &mut self.gray, imgproc::COLOR_BGR2GRAY)
                .map_err(cv)?;
            &self.gray
        };
        self.clahe.apply(gray, &mut self.equalized).map_err(cv)?;
        let mut hist = [0f64; 8];
        for &v in self.equalized.data_bytes().map_err(cv)? {
            hist[usize::from(v >> 5)] += 1.0;
        }
        if self.timings.first_usable.is_none()
            && matches!(
                peekin_core::compare::classify_frame(&hist, self.dark_threshold),
                peekin_core::compare::FrameClass::Scan { .. }
            )
        {
            self.timings.first_usable = Some(self.opened.elapsed());
        }
        Ok(FrameStats {
            at: self.opened.elapsed(),
            hist,
        })
    }

    fn analyze(&mut self) -> Result<Vec<Face>, SourceError> {
        self.analyze_internal(false)
    }

    fn analyze_for_enrollment(&mut self) -> Result<Vec<Face>, SourceError> {
        self.analyze_internal(true)
    }

    fn detect(&mut self) -> Result<Vec<DetectedFace>, SourceError> {
        self.detect_matrix()?;
        let faces = &self.detected;
        (0..faces.rows())
            .map(|row| {
                let mut rect = [0f32; 4];
                for (i, v) in rect.iter_mut().enumerate() {
                    *v = *faces.at_2d::<f32>(row, i as i32).map_err(cv)?;
                }
                Ok(DetectedFace {
                    score: *faces.at_2d::<f32>(row, 14).map_err(cv)?,
                    rect,
                })
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_encode_as_jpeg() {
        let image =
            core::Mat::new_rows_cols_with_default(48, 64, core::CV_8UC3, core::Scalar::all(90.0))
                .unwrap();
        let bytes = jpeg(&image).unwrap();
        assert_eq!(&bytes[..3], &[0xff, 0xd8, 0xff], "JPEG start of image");
        assert_eq!(
            &bytes[bytes.len() - 2..],
            &[0xff, 0xd9],
            "JPEG end of image"
        );
    }

    #[test]
    fn signed_landmarks_distinguish_center_from_both_directions() {
        assert_eq!(landmark_yaw(10.0, 50.0, 30.0), Some(0.0));
        assert!(landmark_yaw(10.0, 50.0, 42.0).unwrap() > 0.16);
        assert!(landmark_yaw(10.0, 50.0, 18.0).unwrap() < -0.16);
        assert_eq!(landmark_yaw(30.0, 30.0, 30.0), None);
    }
    #[test]
    fn integer_resize_maps_every_landmark_and_preserves_score() {
        let original = core::Size::new(641, 481);
        let resized = core::Size::new(426, 320);
        let mut row = [0.0f32; 15];
        for (col, value) in row.iter_mut().take(14).enumerate() {
            *value = if col % 2 == 0 { 213.0 } else { 160.0 };
        }
        row[14] = 0.9;
        let mut mat = core::Mat::from_slice_2d(&[row]).unwrap();
        remap_detections(&mut mat, original, resized).unwrap();
        for col in 0..14 {
            let expected = if col % 2 == 0 { 320.5 } else { 240.5 };
            assert!((*mat.at_2d::<f32>(0, col).unwrap() - expected).abs() < 0.001);
        }
        assert_eq!(*mat.at_2d::<f32>(0, 14).unwrap(), 0.9);
        assert!(remap_detections(&mut mat, original, core::Size::new(0, 1)).is_err());
    }
}
