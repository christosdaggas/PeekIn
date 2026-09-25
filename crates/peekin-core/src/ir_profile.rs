//! Administrator attestations of physical IR capture nodes.
//!
//! An attestation pins the USB identity read from sysfs (vendor, product,
//! `bcdDevice`, interface, V4L2 index, driver, optional serial), never the card
//! name. USB descriptors are firmware data, so a cloned device can still pass;
//! this is not liveness detection.

use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

const PROFILES: &str = "/etc/peekin/ir-profiles.json";

/// Attested fields of an interface `modalias`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UsbModalias {
    vid: String,
    pid: String,
    bcd_device: String,
    interface_class: String,
    interface_number: u32,
}

/// Parse `usb:v…p…d…ic…in…`; anything else fails closed.
fn parse_modalias(modalias: &str) -> Option<UsbModalias> {
    let rest = modalias.strip_prefix("usb:")?;
    let bytes = rest.as_bytes();
    let mut i = 0;
    let mut vid = None;
    let mut pid = None;
    let mut bcd_device = None;
    let mut interface_class = None;
    let mut interface_number = None;
    while i < bytes.len() {
        if !bytes[i].is_ascii_lowercase() {
            return None;
        }
        let key_start = i;
        while i < bytes.len() && bytes[i].is_ascii_lowercase() {
            i += 1;
        }
        let key = &rest[key_start..i];
        let value_start = i;
        while i < bytes.len() && !bytes[i].is_ascii_lowercase() {
            i += 1;
        }
        if i == value_start {
            return None;
        }
        let value = &rest[value_start..i];
        match key {
            "v" => vid = Some(value),
            "p" => pid = Some(value),
            "d" => bcd_device = Some(value),
            "ic" => interface_class = Some(value),
            "in" => interface_number = Some(value),
            _ => {}
        }
    }
    Some(UsbModalias {
        vid: vid?.to_owned(),
        pid: pid?.to_owned(),
        bcd_device: bcd_device?.to_owned(),
        interface_class: interface_class?.to_owned(),
        interface_number: interface_number?.parse().ok()?,
    })
}

/// Live physical identity of one V4L2 capture node, read from sysfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Identity {
    /// Sysfs device path, for audit output only; matching ignores it.
    pub sysfs_device: String,
    pub vid: String,
    pub pid: String,
    pub bcd_device: String,
    pub serial: Option<String>,
    pub interface_number: u32,
    pub interface_class: String,
    /// V4L2 node index within the interface.
    pub capture_index: u32,
    pub driver: String,
}

/// Part of an attestation that must equal the live [`Identity`].
#[derive(Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestedIdentity {
    vid: String,
    pid: String,
    bcd_device: String,
    /// Pins one unit; omit to attest every unit of this model and release.
    #[serde(default)]
    serial: Option<String>,
    interface_number: u32,
    interface_class: String,
    capture_index: u32,
    driver: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    identity: AttestedIdentity,
    evidence: String,
}

fn physical_path(path: &Path) -> bool {
    path.starts_with("/sys/devices") && !path.starts_with("/sys/devices/virtual")
}

fn matches(profile: &Profile, identity: &Identity) -> bool {
    let a = &profile.identity;
    physical_path(Path::new(&identity.sysfs_device))
        && a.vid.eq_ignore_ascii_case(&identity.vid)
        && a.pid.eq_ignore_ascii_case(&identity.pid)
        && a.bcd_device.eq_ignore_ascii_case(&identity.bcd_device)
        && a.interface_class
            .eq_ignore_ascii_case(&identity.interface_class)
        && a.interface_number == identity.interface_number
        && a.capture_index == identity.capture_index
        && a.driver == identity.driver
        && a.serial
            .as_deref()
            .is_none_or(|s| identity.serial.as_deref() == Some(s))
        && profile.evidence.trim().len() >= 10
}

/// Read the physical identity of the node at `path`. `driver` (from
/// `VIDIOC_QUERYCAP`) is checked against the sysfs driver.
pub fn observed_identity(path: &Path, driver: &str) -> Option<Identity> {
    let node = fs::canonicalize(path).ok()?.file_name()?.to_owned();
    let class = Path::new("/sys/class/video4linux").join(node);
    let device = fs::canonicalize(class.join("device")).ok()?;
    if !physical_path(&device) {
        return None;
    }
    let capture_index = fs::read_to_string(class.join("index"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let modalias = device
        .ancestors()
        .take_while(|p| physical_path(p))
        .find_map(|p| fs::read_to_string(p.join("modalias")).ok())?
        .trim()
        .to_owned();
    let modalias = parse_modalias(&modalias)?;
    if let Ok(attached) = fs::read_link(device.join("driver")) {
        if attached.file_name()?.to_string_lossy() != driver {
            return None;
        }
    }
    let serial = device
        .ancestors()
        .take_while(|p| physical_path(p))
        .find(|p| p.join("busnum").exists())
        .and_then(|p| fs::read_to_string(p.join("serial")).ok())
        .map(|s| s.trim().to_owned());
    Some(Identity {
        sysfs_device: device.to_str()?.to_owned(),
        vid: modalias.vid.to_lowercase(),
        pid: modalias.pid.to_lowercase(),
        bcd_device: modalias.bcd_device.to_lowercase(),
        serial,
        interface_number: modalias.interface_number,
        interface_class: modalias.interface_class.to_lowercase(),
        capture_index,
        driver: driver.to_owned(),
    })
}

/// Attestation profile for the live node, for review before installing;
/// `evidence` must be filled in.
pub fn attestation_template(path: &Path, driver: &str) -> Option<String> {
    let identity = observed_identity(path, driver)?;
    let profile = serde_json::json!([{
        "identity": {
            "vid": identity.vid,
            "pid": identity.pid,
            "bcd_device": identity.bcd_device,
            "serial": identity.serial,
            "interface_number": identity.interface_number,
            "interface_class": identity.interface_class,
            "capture_index": identity.capture_index,
            "driver": identity.driver,
        },
        "evidence": "<replace: where the IR sensor is documented and how you verified the emitter locally>",
    }]);
    serde_json::to_string_pretty(&profile).ok()
}

/// Attestation and its directory must be root-controlled; anything missing or
/// malformed fails closed.
pub fn approved(path: &Path, driver: &str) -> bool {
    let read = || -> Option<bool> {
        let identity = observed_identity(path, driver)?;
        let dir = fs::symlink_metadata(Path::new(PROFILES).parent()?).ok()?;
        if !dir.is_dir() || dir.uid() != 0 || dir.mode() & 0o022 != 0 {
            return None;
        }
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(PROFILES)
            .ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() > 65536
        {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(65537).read_to_end(&mut bytes).ok()?;
        if bytes.len() > 65536 {
            return None;
        }
        let profiles: Vec<Profile> = serde_json::from_slice(&bytes).ok()?;
        if profiles.len() > 32 {
            return None;
        }
        Some(profiles.iter().any(|p| matches(p, &identity)))
    };
    read().unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Brio 4K IR node, GREY-only.
    fn brio_ir() -> Identity {
        Identity {
            sysfs_device: "/sys/devices/pci0000:00/0000:00:08.3/0000:c5:00.0/usb4/4-1/4-1:1.0"
                .into(),
            vid: "046d".into(),
            pid: "085e".into(),
            bcd_device: "0317".into(),
            serial: Some("95016168".into()),
            interface_number: 0,
            interface_class: "0e".into(),
            capture_index: 2,
            driver: "uvcvideo".into(),
        }
    }

    fn brio_profile(serial: Option<&str>) -> Profile {
        Profile {
            identity: AttestedIdentity {
                vid: "046d".into(),
                pid: "085e".into(),
                bcd_device: "0317".into(),
                serial: serial.map(str::to_owned),
                interface_number: 0,
                interface_class: "0e".into(),
                capture_index: 2,
                driver: "uvcvideo".into(),
            },
            evidence: "Logitech Brio 4K UVC layout: 8-bit GREY IR sensor at V4L2 index 2 of the video interface; emitter verified lit locally".into(),
        }
    }

    #[test]
    fn brio_modalias_parses_to_attested_fields() {
        let m = parse_modalias("usb:v046Dp085Ed0317dcEFdsc02dp01ic0Eisc01ip00in00").unwrap();
        assert_eq!(m.vid, "046D");
        assert_eq!(m.pid, "085E");
        assert_eq!(m.bcd_device, "0317");
        assert_eq!(m.interface_class, "0E");
        assert_eq!(m.interface_number, 0);
        assert!(parse_modalias("pci:v00001002d00001586sv0000103Csd00008D01bc03sc80i00").is_none());
        assert!(parse_modalias("usb:v046Dp085E").is_none());
        assert!(parse_modalias("usb:v046Dp085Ed0317ic0E").is_none());
        assert!(parse_modalias("usb:v046Dxp085Ed0317ic0Ein00").is_none());
    }

    #[test]
    fn exact_physical_identity_and_provenance_are_required() {
        let profile = brio_profile(Some("95016168"));
        let live = brio_ir();
        assert!(matches(&profile, &live));
        // Missing, malformed or thin provenance never attests hardware.
        for evidence in ["", "short", "  ", "leading-space evidence text"] {
            let mut p = brio_profile(Some("95016168"));
            p.evidence = evidence.into();
            assert_eq!(
                matches(&p, &live),
                p.evidence.trim().len() >= 10,
                "evidence {evidence:?}"
            );
        }
    }

    #[test]
    fn colour_sibling_of_same_interface_is_rejected() {
        let profile = brio_profile(Some("95016168"));
        let mut colour = brio_ir();
        colour.capture_index = 0;
        assert!(
            !matches(&profile, &colour),
            "the YUYV/MJPG/NV12 node at index 0 of the same interface must not pass"
        );
        let mut meta = brio_ir();
        meta.capture_index = 1;
        assert!(!matches(&profile, &meta));
    }

    #[test]
    fn virtual_or_nonsysfs_node_is_rejected() {
        let profile = brio_profile(Some("95016168"));
        let mut virtual_cam = brio_ir();
        virtual_cam.sysfs_device = "/sys/devices/virtual/video4linux/video3".into();
        assert!(!matches(&profile, &virtual_cam));
        let mut vchiq = brio_ir();
        vchiq.sysfs_device = "/sys/devices/platform/soc/fe800000.vchiq/video4linux/video0".into();
        assert!(matches(&profile, &vchiq), "platform devices are physical");
        let mut elsewhere = brio_ir();
        elsewhere.sysfs_device = "/dev/null".into();
        assert!(!matches(&profile, &elsewhere));
    }

    #[test]
    fn moved_to_another_bus_still_matches() {
        let profile = brio_profile(Some("95016168"));
        let mut moved = brio_ir();
        moved.sysfs_device = "/sys/devices/pci0000:00/0000:00:14.0/usb1/1-3/1-3:1.0".into();
        assert!(
            matches(&profile, &moved),
            "identity is bus-position-independent: VID/PID/release/interface/index/serial"
        );
    }

    #[test]
    fn lookalike_units_fail_serial_and_firmware_pins() {
        let pinned = brio_profile(Some("95016168"));
        let mut clone = brio_ir();
        clone.serial = Some("DEADBEEF".into());
        assert!(
            !matches(&pinned, &clone),
            "same model, different serial: not the attested unit"
        );
        let mut missing_serial = brio_ir();
        missing_serial.serial = None;
        assert!(!matches(&pinned, &missing_serial));
        let model_level = brio_profile(None);
        assert!(matches(&model_level, &clone));
        // Different product, release, interface class or driver: all fail.
        let mut lookalike = brio_ir();
        lookalike.pid = "085f".into();
        assert!(!matches(&model_level, &lookalike));
        let mut reflashed = brio_ir();
        reflashed.bcd_device = "0318".into();
        assert!(!matches(&model_level, &reflashed));
        let mut vendor_clone = brio_ir();
        vendor_clone.vid = "1bcf".into();
        assert!(!matches(&model_level, &vendor_clone));
        let mut other_class = brio_ir();
        other_class.interface_class = "ff".into();
        assert!(!matches(&model_level, &other_class));
        let mut other_driver = brio_ir();
        other_driver.driver = "sometime".into();
        assert!(!matches(&model_level, &other_driver));
        // Hex fields compare case-insensitively (kernel emits uppercase).
        let mut upper = brio_ir();
        upper.vid = "046D".into();
        upper.pid = "085E".into();
        upper.bcd_device = "0317".into();
        upper.interface_class = "0E".into();
        assert!(matches(&model_level, &upper));
    }

    #[test]
    fn profile_schema_is_strict() {
        // deny_unknown_fields: unknown keys are a schema error.
        for json in [
            r#"[{"identity":{"vid":"046d","pid":"085e","bcd_device":"0317","serial":null,"interface_number":0,"interface_class":"0e","capture_index":2,"driver":"uvcvideo"},"evidence":"documented layout plus local emitter check","card":"Logitech BRIO"}]"#,
            r#"[{"identity":{"vid":"046d","pid":"085e","bcd_device":"0317","sysfs_device":"/sys/devices/pci0000:00/0000:00:08.3/0000:c5:00.0/usb4/4-1/4-1:1.0","interface_number":0,"interface_class":"0e","capture_index":2,"driver":"uvcvideo"},"evidence":"documented layout plus local emitter check"}]"#,
            r#"[{"identity":{"vid":"046d","pid":"085e"},"evidence":"documented layout plus local emitter check"}]"#,
        ] {
            let parsed: Result<Vec<Profile>, _> = serde_json::from_str(json);
            assert!(parsed.is_err(), "must reject {json}");
        }
        let ok: Vec<Profile> = serde_json::from_str(
            r#"[{"identity":{"vid":"046d","pid":"085e","bcd_device":"0317","interface_number":0,"interface_class":"0e","capture_index":2,"driver":"uvcvideo"},"evidence":"documented layout plus local emitter check"}]"#,
        )
        .unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].identity.serial, None);
    }

    /// Needs a USB camera; run with `cargo test -- --ignored`.
    #[test]
    #[ignore = "requires a USB camera on the test machine"]
    fn live_usb_camera_yields_a_complete_identity() {
        let dir = match fs::read_dir("/dev/v4l/by-path") {
            Ok(dir) => dir,
            Err(_) => return,
        };
        let mut checked = 0;
        for entry in dir.flatten() {
            let target = match fs::canonicalize(entry.path()) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if let Some(identity) = observed_identity(&target, "uvcvideo") {
                checked += 1;
                assert!(!identity.vid.is_empty() && !identity.pid.is_empty());
                assert!(physical_path(Path::new(&identity.sysfs_device)));
            }
        }
        assert!(checked > 0, "expected at least one USB capture node");
    }
}
