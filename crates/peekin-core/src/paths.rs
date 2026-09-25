//! File locations, injected so tests never touch `/etc/peekin`.

use std::path::{Path, PathBuf};
use thiserror::Error;

/// Face models used by the OpenCV backend (YuNet detector, SFace recognizer).
pub const VISION_MODELS: [&str; 2] = [
    "face_detection_yunet_2023mar.onnx",
    "face_recognition_sface_2021dec.onnx",
];

#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("invalid username {0:?}")]
pub struct InvalidUsername(pub String);

/// Usernames come from PAM and `-U`, so treat them as hostile.
pub fn validate_username(user: &str) -> Result<(), InvalidUsername> {
    let bad = user.is_empty()
        || user.len() > 256
        || user.starts_with('.')
        || user.chars().any(|c| c == '/' || c.is_control());
    if bad {
        Err(InvalidUsername(user.to_string()))
    } else {
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PeekinPaths {
    pub config_dir: PathBuf,
    pub vision_model_dir: PathBuf,
    pub user_models_dir: PathBuf,
    pub log_path: PathBuf,
    pub data_dir: PathBuf,
    /// Sealed face models (installed systems only; see [`crate::sealed`]).
    pub sealed_models_dir: Option<PathBuf>,
}

pub const SYSTEM_CONFIG_DIR: &str = "/etc/peekin";

impl PeekinPaths {
    pub fn new(
        config_dir: PathBuf,
        vision_model_dir: PathBuf,
        user_models_dir: PathBuf,
        log_path: PathBuf,
        data_dir: PathBuf,
    ) -> Self {
        Self {
            config_dir,
            vision_model_dir,
            user_models_dir,
            log_path,
            data_dir,
            sealed_models_dir: None,
        }
    }

    /// Layout for a config dir and a data dir. Under [`SYSTEM_CONFIG_DIR`] models
    /// are read decrypted from memory; other trees keep plaintext models.
    pub fn from_dirs(config_dir: PathBuf, data_dir: PathBuf) -> Self {
        let system = config_dir == Path::new(SYSTEM_CONFIG_DIR);
        Self {
            user_models_dir: if system {
                PathBuf::from(crate::sealed::RUN_MODELS_DIR)
            } else {
                config_dir.join("models")
            },
            sealed_models_dir: system.then(|| config_dir.join("models")),
            vision_model_dir: data_dir.join("models"),
            log_path: PathBuf::from("/var/log/peekin"),
            config_dir,
            data_dir,
        }
    }

    pub fn system_defaults() -> Self {
        Self::from_dirs(
            PathBuf::from("/etc/peekin"),
            PathBuf::from("/usr/share/peekin"),
        )
    }

    pub fn face_detector_model_path(&self) -> PathBuf {
        self.vision_model_dir.join(VISION_MODELS[0])
    }

    pub fn face_recognizer_model_path(&self) -> PathBuf {
        self.vision_model_dir.join(VISION_MODELS[1])
    }

    pub fn vision_models_present(&self) -> bool {
        self.face_detector_model_path().is_file() && self.face_recognizer_model_path().is_file()
    }

    pub fn user_model_path(&self, user: &str) -> Result<PathBuf, InvalidUsername> {
        validate_username(user)?;
        Ok(self.user_models_dir.join(format!("{user}.dat")))
    }

    pub fn config_file_path(&self) -> PathBuf {
        self.config_dir.join("config.ini")
    }

    pub fn snapshots_dir(&self) -> PathBuf {
        self.log_path.join("snapshots")
    }

    pub fn snapshot_path(&self, filename: &str) -> PathBuf {
        self.snapshots_dir().join(filename)
    }

    pub fn user_models_dir(&self) -> &Path {
        &self.user_models_dir
    }

    pub fn sealed_models_dir(&self) -> Option<&Path> {
        self.sealed_models_dir.as_deref()
    }

    pub fn logo_path(&self) -> PathBuf {
        self.data_dir.join("logo.png")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_installed_system_reads_sealed_models_from_memory() {
        let system = PeekinPaths::from_dirs("/etc/peekin/".into(), "/usr/share/peekin".into());
        assert_eq!(system.user_models_dir(), Path::new("/run/peekin/models"));
        assert_eq!(
            system.sealed_models_dir(),
            Some(Path::new("/etc/peekin/models"))
        );
        let dev = PeekinPaths::from_dirs("/tmp/dev/etc".into(), "/tmp/dev/data".into());
        assert_eq!(dev.user_models_dir(), Path::new("/tmp/dev/etc/models"));
        assert_eq!(dev.sealed_models_dir(), None);
    }

    #[test]
    fn default_layout() {
        let p = PeekinPaths::system_defaults();
        assert_eq!(
            p.config_file_path(),
            PathBuf::from("/etc/peekin/config.ini")
        );
        assert_eq!(
            p.user_model_path("alice").unwrap(),
            // Installed systems read the decrypted copy in memory.
            PathBuf::from("/run/peekin/models/alice.dat")
        );
        assert_eq!(
            p.face_detector_model_path(),
            PathBuf::from("/usr/share/peekin/models/face_detection_yunet_2023mar.onnx")
        );
        assert_eq!(
            p.face_recognizer_model_path(),
            PathBuf::from("/usr/share/peekin/models/face_recognition_sface_2021dec.onnx")
        );
        assert_eq!(
            p.snapshot_path("20240101T000000.jpg"),
            PathBuf::from("/var/log/peekin/snapshots/20240101T000000.jpg")
        );
    }

    #[test]
    fn traversal_and_control_characters_rejected() {
        for bad in ["", "../victim", "a/b", ".hidden", "..", "x\0y", "x\ny"] {
            assert!(validate_username(bad).is_err(), "{bad:?} accepted");
            assert!(PeekinPaths::system_defaults().user_model_path(bad).is_err());
        }
    }

    #[test]
    fn real_world_names_accepted() {
        for ok in [
            "alice",
            "christos",
            "john.doe",
            "svc-backup$",
            "user@ad.example.com",
            "DOMAIN\\user",
        ] {
            assert!(validate_username(ok).is_ok(), "{ok:?} rejected");
        }
    }
}
