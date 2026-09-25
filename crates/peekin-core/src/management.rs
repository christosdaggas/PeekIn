//! Strict, serialized management transactions used by the privileged helper.

use crate::config::{MAX_AUTH_TIMEOUT_SECS, MAX_SIMILARITY, MIN_SIMILARITY};
use crate::fsutil::atomic_write;
use crate::{set_option, PeekinConfig};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SettingsUpdate {
    pub expected_revision: String,
    pub enabled: bool,
    pub device_path: String,
    pub ir_only: bool,
    pub min_similarity: f64,
    pub timeout: i64,
    pub dark_threshold: f64,
    pub detection_notice: bool,
    pub confirm_success: bool,
    pub abort_if_ssh: bool,
    pub abort_if_lid_closed: bool,
    pub movement_challenge: bool,
    pub require_movement_without_ir: bool,
    pub personal_threshold: bool,
    pub brighten_screen: bool,
    pub save_failed_snapshots: bool,
    pub services: ServicesUpdate,
}

/// `[services]`: where face authentication may be used.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ServicesUpdate {
    pub sudo: bool,
    pub login_screen: bool,
    pub lock_screen: bool,
    pub polkit: bool,
    pub console: bool,
}

impl ServicesUpdate {
    pub fn from_config(config: &PeekinConfig) -> Self {
        use crate::config::FaceService as S;
        Self {
            sudo: config.service_enabled(S::Sudo),
            login_screen: config.service_enabled(S::LoginScreen),
            lock_screen: config.service_enabled(S::LockScreen),
            polkit: config.service_enabled(S::Polkit),
            console: config.service_enabled(S::Console),
        }
    }

    fn values(self) -> [(&'static str, bool); 5] {
        [
            ("sudo", self.sudo),
            ("login_screen", self.login_screen),
            ("lock_screen", self.lock_screen),
            ("polkit", self.polkit),
            ("console", self.console),
        ]
    }
}

#[derive(Debug, Error)]
pub enum ManagementError {
    #[error("invalid settings: {0}")]
    Invalid(String),
    #[error("settings changed since they were loaded; reload and try again")]
    Conflict,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Set(#[from] set_option::SetError),
}

pub fn revision(raw: &str) -> String {
    // Stable FNV-1a token: conflict detection, not a cryptographic signature.
    let hash = raw.bytes().fold(0xcbf29ce484222325u64, |h, b| {
        (h ^ u64::from(b)).wrapping_mul(0x100000001b3)
    });
    format!("{hash:016x}")
}

fn lock_for(path: &Path) -> Result<File, std::io::Error> {
    let name = path.file_name().unwrap_or_default().to_string_lossy();
    let lock_path = path.with_file_name(format!(".{name}.lock"));
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(lock_path)?;
    // SAFETY: flock operates on the live descriptor and is released on drop.
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(lock)
}

impl SettingsUpdate {
    pub fn validate(&self) -> Result<(), ManagementError> {
        if self.expected_revision.len() != 16
            || !self
                .expected_revision
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return Err(ManagementError::Invalid("invalid revision token".into()));
        }
        if !valid_device_path(&self.device_path) {
            return Err(ManagementError::Invalid(
                "camera must be none, /dev/videoN, or one non-traversing /dev/v4l/by-path or by-id entry"
                    .into(),
            ));
        }
        if !self.min_similarity.is_finite()
            || !(MIN_SIMILARITY..=MAX_SIMILARITY).contains(&self.min_similarity)
        {
            return Err(ManagementError::Invalid(format!(
                "min_similarity must be in [{MIN_SIMILARITY}, {MAX_SIMILARITY}]"
            )));
        }
        if !(1..=MAX_AUTH_TIMEOUT_SECS).contains(&self.timeout) {
            return Err(ManagementError::Invalid(format!(
                "timeout must be in [1, {MAX_AUTH_TIMEOUT_SECS}]"
            )));
        }
        if !self.dark_threshold.is_finite() || !(1.0..=100.0).contains(&self.dark_threshold) {
            return Err(ManagementError::Invalid(
                "dark_threshold must be in [1, 100]".into(),
            ));
        }
        Ok(())
    }
}

pub fn valid_device_path(path: &str) -> bool {
    if path == "none" {
        return true;
    }
    if let Some(index) = path.strip_prefix("/dev/video") {
        return !index.is_empty() && index.bytes().all(|b| b.is_ascii_digit());
    }
    path.strip_prefix("/dev/v4l/by-path/")
        .or_else(|| path.strip_prefix("/dev/v4l/by-id/"))
        .is_some_and(|name| {
            !name.is_empty()
                && name != "."
                && name != ".."
                && !name.contains('/')
                && !name.contains(['\n', '\r', '\0'])
        })
}

/// Validate the complete candidate before one atomic replacement. The lock
/// covers read, conflict check, transformation, validation and rename.
pub fn apply_settings(path: &Path, update: &SettingsUpdate) -> Result<String, ManagementError> {
    update.validate()?;
    let _lock = lock_for(path)?;
    let raw = std::fs::read_to_string(path)?;
    if revision(&raw) != update.expected_revision {
        return Err(ManagementError::Conflict);
    }
    let values = [
        ("disabled", (!update.enabled).to_string()),
        ("device_path", update.device_path.clone()),
        ("ir_only", update.ir_only.to_string()),
        ("min_similarity", update.min_similarity.to_string()),
        ("timeout", update.timeout.to_string()),
        ("dark_threshold", update.dark_threshold.to_string()),
        ("detection_notice", update.detection_notice.to_string()),
        ("no_confirmation", (!update.confirm_success).to_string()),
        ("abort_if_ssh", update.abort_if_ssh.to_string()),
        (
            "abort_if_lid_closed",
            update.abort_if_lid_closed.to_string(),
        ),
        ("movement_challenge", update.movement_challenge.to_string()),
        (
            "require_movement_without_ir",
            update.require_movement_without_ir.to_string(),
        ),
        ("personal_threshold", update.personal_threshold.to_string()),
        ("brighten_screen", update.brighten_screen.to_string()),
        ("save_failed", update.save_failed_snapshots.to_string()),
    ];
    let mut candidate = raw;
    for (key, value) in values {
        candidate = set_option::apply_known(&candidate, key, &value)?;
    }
    for (key, enabled) in update.services.values() {
        candidate = set_option::apply_known(&candidate, key, &enabled.to_string())?;
    }
    let parsed = PeekinConfig::parse(&candidate, path.display().to_string())
        .map_err(|e| ManagementError::Invalid(e.to_string()))?;
    parsed
        .validate()
        .map_err(|e| ManagementError::Invalid(e.join("; ")))?;
    atomic_write(path, candidate.as_bytes(), None)?;
    Ok(revision(&candidate))
}

pub fn update_option(path: &Path, name: &str, value: &str) -> Result<(), ManagementError> {
    let _lock = lock_for(path)?;
    let raw = std::fs::read_to_string(path)?;
    let candidate = set_option::apply_known(&raw, name, value)?;
    let parsed = PeekinConfig::parse(&candidate, path.display().to_string())
        .map_err(|e| ManagementError::Invalid(e.to_string()))?;
    parsed
        .validate()
        .map_err(|e| ManagementError::Invalid(e.join("; ")))?;
    atomic_write(path, candidate.as_bytes(), None)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);

    fn fixture() -> (std::path::PathBuf, String) {
        let p = std::env::temp_dir().join(format!(
            "peekin-settings-{}-{}.ini",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let raw = "# keep me\n[core]\ndisabled = false\ndetection_notice = true\nno_confirmation = false\nabort_if_ssh = true\nabort_if_lid_closed = true\n[video]\ndevice_path = /dev/v4l/by-path/cam\nir_only = false\nmin_similarity = 0.99\ntimeout = 4\ndark_threshold = 80\n";
        std::fs::write(&p, raw).unwrap();
        (p, raw.into())
    }

    fn update(raw: &str) -> SettingsUpdate {
        SettingsUpdate {
            expected_revision: revision(raw),
            enabled: true,
            device_path: "/dev/v4l/by-path/cam".into(),
            ir_only: false,
            min_similarity: 0.99,
            timeout: 5,
            dark_threshold: 80.0,
            detection_notice: true,
            confirm_success: true,
            abort_if_ssh: true,
            abort_if_lid_closed: true,
            movement_challenge: true,
            require_movement_without_ir: true,
            personal_threshold: false,
            brighten_screen: true,
            save_failed_snapshots: false,
            services: ServicesUpdate {
                sudo: true,
                login_screen: true,
                lock_screen: true,
                polkit: false,
                console: false,
            },
        }
    }

    #[test]
    fn transaction_preserves_comments_and_high_threshold() {
        let (p, raw) = fixture();
        apply_settings(&p, &update(&raw)).unwrap();
        let after = std::fs::read_to_string(&p).unwrap();
        assert!(after.contains("# keep me") && after.contains("min_similarity = 0.99"));
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn movement_challenge_is_inserted_into_older_configs_and_toggles() {
        let (p, raw) = fixture();
        assert!(!raw.contains("movement_challenge"));
        let mut u = update(&raw);
        u.movement_challenge = false;
        let revision = apply_settings(&p, &u).unwrap();
        let stored = PeekinConfig::load(&p).unwrap();
        assert!(!stored.movement_challenge());
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(after.matches("movement_challenge").count(), 1);
        let mut u = update(&after);
        u.expected_revision = revision;
        u.movement_challenge = true;
        apply_settings(&p, &u).unwrap();
        assert!(PeekinConfig::load(&p).unwrap().movement_challenge());
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn threshold_and_screen_light_are_inserted_into_older_configs() {
        let (p, raw) = fixture();
        let mut u = update(&raw);
        u.personal_threshold = true;
        u.brighten_screen = false;
        u.save_failed_snapshots = true;
        apply_settings(&p, &u).unwrap();
        let stored = PeekinConfig::load(&p).unwrap();
        assert!(stored.personal_threshold() && !stored.brighten_screen());
        assert!(stored.save_failed_snapshots());
        assert!(
            stored.invalid_values().is_empty(),
            "{:?}",
            stored.invalid_values()
        );
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn movement_without_ir_is_inserted_into_older_configs_and_toggles() {
        let (p, raw) = fixture();
        assert!(!raw.contains("require_movement_without_ir"));
        let mut u = update(&raw);
        u.require_movement_without_ir = false;
        apply_settings(&p, &u).unwrap();
        let stored = PeekinConfig::load(&p).unwrap();
        assert!(!stored.require_movement_without_ir());
        assert!(
            stored.invalid_values().is_empty(),
            "{:?}",
            stored.invalid_values()
        );
        let after = std::fs::read_to_string(&p).unwrap();
        assert_eq!(after.matches("require_movement_without_ir").count(), 1);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn services_are_written_to_their_own_section() {
        let (p, raw) = fixture();
        let mut u = update(&raw);
        u.services.login_screen = false;
        u.services.console = true;
        apply_settings(&p, &u).unwrap();
        let stored = PeekinConfig::load(&p).unwrap();
        assert_eq!(ServicesUpdate::from_config(&stored), u.services);
        let text = std::fs::read_to_string(&p).unwrap();
        assert!(text.contains("[services]\n"), "{text}");
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn stale_revision_and_invalid_candidate_do_not_write() {
        let (p, raw) = fixture();
        let mut u = update(&raw);
        u.expected_revision = "0000000000000000".into();
        assert!(matches!(
            apply_settings(&p, &u),
            Err(ManagementError::Conflict)
        ));
        let mut u = update(&raw);
        u.min_similarity = 0.1;
        assert!(matches!(
            apply_settings(&p, &u),
            Err(ManagementError::Invalid(_))
        ));
        assert_eq!(std::fs::read_to_string(&p).unwrap(), raw);
        let _ = std::fs::remove_file(p);
    }

    #[test]
    fn concurrent_writers_cannot_lose_an_update() {
        let (path, raw) = fixture();
        let mut first = update(&raw);
        first.timeout = 2;
        let mut second = update(&raw);
        second.timeout = 3;
        let barrier = std::sync::Barrier::new(2);
        let results = std::thread::scope(|scope| {
            let one = scope.spawn(|| {
                barrier.wait();
                apply_settings(&path, &first)
            });
            let two = scope.spawn(|| {
                barrier.wait();
                apply_settings(&path, &second)
            });
            [one.join().unwrap(), two.join().unwrap()]
        });
        assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| matches!(r, Err(ManagementError::Conflict)))
                .count(),
            1
        );
        let stored = PeekinConfig::load(&path).unwrap();
        assert!([2, 3].contains(&stored.video_timeout_secs()));
        assert_eq!(stored.min_similarity(), 0.99);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn camera_path_syntax_separates_unconfigured_and_rejects_traversal() {
        for good in [
            "none",
            "/dev/video0",
            "/dev/v4l/by-path/pci-0000:00-video-index0",
            "/dev/v4l/by-id/usb-046d_Logitech_BRIO_ABC-video-index2",
        ] {
            assert!(valid_device_path(good), "{good}");
        }
        for bad in [
            "/dev/video",
            "/dev/video0/../x",
            "/dev/v4l/by-path/../video0",
            "/dev/v4l/by-id/..",
            "/dev/v4l/by-id/a/b",
            "/tmp/video0",
        ] {
            assert!(!valid_device_path(bad), "{bad}");
        }
    }
}
