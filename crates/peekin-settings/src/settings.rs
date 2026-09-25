//! Settings shown in the app, applied as one `apply-settings` transaction by the helper.

use peekin_core::management::ServicesUpdate;
use peekin_core::PeekinConfig;

#[derive(Debug, Clone, PartialEq)]
pub struct Settings {
    pub revision: String,
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

impl Settings {
    pub fn from_config(c: &PeekinConfig, revision: String) -> Self {
        Self {
            revision,
            enabled: !c.disabled(),
            device_path: c.device_path(),
            ir_only: c.ir_only(),
            min_similarity: c.min_similarity(),
            timeout: c.video_timeout_secs(),
            dark_threshold: c.dark_threshold(),
            detection_notice: c.detection_notice(),
            confirm_success: !c.no_confirmation(),
            abort_if_ssh: c.abort_if_ssh(),
            abort_if_lid_closed: c.abort_if_lid_closed(),
            movement_challenge: c.movement_challenge(),
            require_movement_without_ir: c.require_movement_without_ir(),
            personal_threshold: c.personal_threshold(),
            brighten_screen: c.brighten_screen(),
            save_failed_snapshots: c.save_failed_snapshots(),
            services: ServicesUpdate::from_config(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped() -> Settings {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../data/config.ini"
        ))
        .unwrap();
        Settings::from_config(
            &PeekinConfig::parse(&raw, "<test>".into()).unwrap(),
            peekin_core::management::revision(&raw),
        )
    }

    #[test]
    fn reads_shipped_defaults() {
        let s = shipped();
        assert!(s.enabled && s.detection_notice && s.confirm_success && s.abort_if_ssh);
        assert!(s.movement_challenge && s.require_movement_without_ir);
        assert!(!s.personal_threshold && s.brighten_screen && !s.save_failed_snapshots);
        assert!(s.services.sudo && s.services.login_screen && s.services.lock_screen);
        assert!(!s.services.polkit && !s.services.console);
        assert_eq!(s.timeout, 3);
        assert_eq!(s.device_path, "none");
        assert_eq!(s.min_similarity, 0.363);
        assert_eq!(s.revision.len(), 16);
    }
}
