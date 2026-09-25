//! Administrator attestations of physical IR capture nodes.
//!
//! An attestation pins the USB identity read from sysfs (vendor, product,
//! `bcdDevice`, interface, V4L2 index, driver, optional serial), never the card
//! name. USB descriptors are firmware data, so a cloned device can still pass;
//! this is not liveness detection.

use crate::cameras::{self, CameraKind};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const PROFILES: &str = "/etc/peekin/ir-profiles.json";
const MAX_PROFILES: usize = 32;
const MAX_FILE_BYTES: u64 = 65536;
const EVIDENCE_MIN: usize = 10;
const EVIDENCE_MAX: usize = 500;

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
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct AttestedIdentity {
    vid: String,
    pid: String,
    bcd_device: String,
    /// Pins one unit; omit to attest every unit of this model and release.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    serial: Option<String>,
    interface_number: u32,
    interface_class: String,
    capture_index: u32,
    driver: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Profile {
    identity: AttestedIdentity,
    evidence: String,
}

fn physical_path(path: &Path) -> bool {
    path.starts_with("/sys/devices") && !path.starts_with("/sys/devices/virtual")
}

/// Placeholders such as `<describe the check>` are never evidence.
fn evidence_ok(evidence: &str) -> bool {
    let e = evidence.trim();
    e.chars().count() >= EVIDENCE_MIN && !(e.starts_with('<') && e.ends_with('>'))
}

fn matches(profile: &Profile, identity: &Identity) -> bool {
    same_device(&profile.identity, identity) && evidence_ok(&profile.evidence)
}

fn same_device(a: &AttestedIdentity, identity: &Identity) -> bool {
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

#[derive(Debug, Error)]
pub enum AttestError {
    #[error("{0} is not a camera that can be opened")]
    NotACamera(String),
    #[error("{0} delivers colour images; only an infrared node can be attested")]
    Colour(String),
    #[error("{0} is not a physical USB camera, or its identity cannot be read")]
    NotPhysical(String),
    #[error(
        "evidence must be {EVIDENCE_MIN} to {EVIDENCE_MAX} characters without control characters, \
         and say how the infrared sensor was checked"
    )]
    Evidence,
    #[error("{0} already holds {MAX_PROFILES} attestations")]
    Full(String),
    #[error("{path} is unsafe or invalid ({reason}); fix or remove it by hand")]
    Unsafe { path: String, reason: String },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Trimmed evidence, if a person could have written it about this device.
pub fn validate_evidence(evidence: &str) -> Result<&str, AttestError> {
    let e = evidence.trim();
    let ok =
        evidence_ok(e) && e.chars().count() <= EVIDENCE_MAX && !e.chars().any(char::is_control);
    ok.then_some(e).ok_or(AttestError::Evidence)
}

/// A camera as the kernel reports it, read by the caller itself.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub name: String,
    pub kind: CameraKind,
    pub identity: Identity,
}

/// Identity of the infrared node at `camera`; colour and virtual nodes fail.
pub fn inspect(camera: &Path) -> Result<Candidate, AttestError> {
    let shown = camera.display().to_string();
    let probe = cameras::probe(camera).ok_or_else(|| AttestError::NotACamera(shown.clone()))?;
    if probe.kind == CameraKind::Colour {
        return Err(AttestError::Colour(shown));
    }
    let identity =
        observed_identity(camera, &probe.driver).ok_or(AttestError::NotPhysical(shown))?;
    Ok(Candidate {
        name: probe.name,
        kind: probe.kind,
        identity,
    })
}

fn profile_for(identity: &Identity, evidence: &str, pin_serial: bool) -> Profile {
    Profile {
        identity: AttestedIdentity {
            vid: identity.vid.clone(),
            pid: identity.pid.clone(),
            bcd_device: identity.bcd_device.clone(),
            serial: identity.serial.clone().filter(|_| pin_serial),
            interface_number: identity.interface_number,
            interface_class: identity.interface_class.clone(),
            capture_index: identity.capture_index,
            driver: identity.driver.clone(),
        },
        evidence: evidence.to_owned(),
    }
}

/// The entry [`Store::attest`] would add, for review.
pub fn profile_json(identity: &Identity, evidence: &str, pin_serial: bool) -> String {
    serde_json::to_string_pretty(&[profile_for(identity, evidence, pin_serial)])
        .expect("profiles serialise")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Attested {
    Added,
    AlreadyAttested,
}

/// The attestation file. Only `uid` may own it and its directory, and nobody
/// else may write them; readable by all, since the worker and the user's own
/// session check cameras too.
pub struct Store {
    path: PathBuf,
    uid: libc::uid_t,
    gid: libc::gid_t,
}

impl Store {
    pub fn system() -> Self {
        Store::at(PROFILES, 0, 0)
    }

    pub fn at(path: impl Into<PathBuf>, uid: libc::uid_t, gid: libc::gid_t) -> Self {
        Store {
            path: path.into(),
            uid,
            gid,
        }
    }

    fn unsafe_file(&self, reason: &str) -> AttestError {
        AttestError::Unsafe {
            path: self.path.display().to_string(),
            reason: reason.into(),
        }
    }

    /// Every entry; an absent file is empty, anything doubtful is an error.
    fn load(&self) -> Result<Vec<Profile>, AttestError> {
        let dir = self.path.parent().unwrap_or(Path::new("/"));
        let dir = fs::symlink_metadata(dir)?;
        if !dir.is_dir() || dir.uid() != self.uid || dir.mode() & 0o022 != 0 {
            return Err(self.unsafe_file("its directory is not controlled by root"));
        }
        let file = match fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(&self.path)
        {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(_) => return Err(self.unsafe_file("it cannot be opened safely")),
        };
        let metadata = file.metadata()?;
        if !metadata.is_file()
            || metadata.uid() != self.uid
            || metadata.mode() & 0o022 != 0
            || metadata.nlink() != 1
            || metadata.len() > MAX_FILE_BYTES
        {
            return Err(self.unsafe_file("wrong type, owner, mode or size"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_FILE_BYTES + 1).read_to_end(&mut bytes)?;
        let profiles: Vec<Profile> =
            serde_json::from_slice(&bytes).map_err(|_| self.unsafe_file("not valid JSON"))?;
        if bytes.len() as u64 > MAX_FILE_BYTES || profiles.len() > MAX_PROFILES {
            return Err(self.unsafe_file("too large"));
        }
        Ok(profiles)
    }

    fn approves(&self, identity: &Identity) -> bool {
        self.load()
            .is_ok_and(|profiles| profiles.iter().any(|p| matches(p, identity)))
    }

    fn save(&self, profiles: &[Profile]) -> Result<(), AttestError> {
        let mut json = serde_json::to_vec_pretty(profiles).expect("profiles serialise");
        json.push(b'\n');
        crate::fsutil::atomic_write_owned(&self.path, &json, 0o644, self.uid, self.gid)?;
        Ok(())
    }

    pub fn attest(
        &self,
        identity: &Identity,
        evidence: &str,
        pin_serial: bool,
    ) -> Result<Attested, AttestError> {
        let evidence = validate_evidence(evidence)?;
        let _lock = crate::management::lock_for(&self.path)?;
        let mut profiles = self.load()?;
        if profiles.iter().any(|p| matches(p, identity)) {
            return Ok(Attested::AlreadyAttested);
        }
        if profiles.len() >= MAX_PROFILES {
            return Err(AttestError::Full(self.path.display().to_string()));
        }
        profiles.push(profile_for(identity, evidence, pin_serial));
        self.save(&profiles)?;
        Ok(Attested::Added)
    }

    /// Remove every entry for this device, even ones without valid evidence;
    /// returns how many.
    pub fn revoke(&self, identity: &Identity) -> Result<usize, AttestError> {
        let _lock = crate::management::lock_for(&self.path)?;
        let mut profiles = self.load()?;
        let before = profiles.len();
        profiles.retain(|p| !same_device(&p.identity, identity));
        let removed = before - profiles.len();
        if removed > 0 {
            self.save(&profiles)?;
        }
        Ok(removed)
    }
}

/// Whether the node at `path` is attested; anything doubtful fails closed.
pub fn approved(path: &Path, driver: &str) -> bool {
    observed_identity(path, driver).is_some_and(|identity| Store::system().approves(&identity))
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

    const EVIDENCE: &str = "Brio 4K IR node; emitter seen lit in a dark room";

    struct TempStore {
        dir: PathBuf,
        store: Store,
    }

    impl Drop for TempStore {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    fn temp_store(name: &str) -> TempStore {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("peekin-ir-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        // SAFETY: getuid/getgid have no preconditions.
        let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
        let store = Store::at(dir.join("ir-profiles.json"), uid, gid);
        TempStore { dir, store }
    }

    #[test]
    fn evidence_must_be_written_by_a_person() {
        assert_eq!(
            validate_evidence(&format!("  {EVIDENCE} ")).unwrap(),
            EVIDENCE
        );
        for bad in [
            "",
            "too short",
            "<replace: where the IR sensor is documented and how you verified it>",
            "<describe the check here>",
            "emitter lit\nsecond line",
            &"x".repeat(EVIDENCE_MAX + 1),
        ] {
            assert!(validate_evidence(bad).is_err(), "{bad:?}");
        }
        let mut placeholder = brio_profile(Some("95016168"));
        placeholder.evidence = "<replace: where the IR sensor is documented>".into();
        assert!(!matches(&placeholder, &brio_ir()));
    }

    #[test]
    fn attest_revoke_round_trip() {
        use std::os::unix::fs::PermissionsExt;
        let t = temp_store("roundtrip");
        let brio = brio_ir();
        assert!(!t.store.approves(&brio));
        assert_eq!(
            t.store.attest(&brio, EVIDENCE, true).unwrap(),
            Attested::Added
        );
        let mode = fs::metadata(&t.store.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o644);
        assert!(t.store.approves(&brio));
        assert_eq!(
            t.store.attest(&brio, EVIDENCE, true).unwrap(),
            Attested::AlreadyAttested
        );
        let mut other_unit = brio_ir();
        other_unit.serial = Some("DEADBEEF".into());
        assert!(!t.store.approves(&other_unit), "the serial is pinned");
        assert_eq!(t.store.revoke(&brio).unwrap(), 1);
        assert!(!t.store.approves(&brio));
        assert_eq!(t.store.revoke(&brio).unwrap(), 0);
    }

    #[test]
    fn any_unit_attestation_leaves_the_serial_out() {
        let t = temp_store("anyunit");
        t.store.attest(&brio_ir(), EVIDENCE, false).unwrap();
        assert!(!fs::read_to_string(&t.store.path)
            .unwrap()
            .contains("serial"));
        let mut other_unit = brio_ir();
        other_unit.serial = Some("DEADBEEF".into());
        assert!(t.store.approves(&other_unit));
    }

    #[test]
    fn existing_entries_are_kept_and_the_limit_holds() {
        let t = temp_store("limit");
        let mut profiles = Vec::new();
        for index in 0..MAX_PROFILES as u32 {
            let mut other = brio_ir();
            other.capture_index = 10 + index;
            profiles.push(profile_for(&other, EVIDENCE, true));
        }
        t.store.save(&profiles[..1]).unwrap();
        t.store.attest(&brio_ir(), EVIDENCE, true).unwrap();
        assert_eq!(t.store.load().unwrap().len(), 2);
        t.store.save(&profiles).unwrap();
        assert!(matches!(
            t.store.attest(&brio_ir(), EVIDENCE, true),
            Err(AttestError::Full(_))
        ));
    }

    #[test]
    fn a_doubtful_file_is_never_replaced() {
        use std::os::unix::fs::PermissionsExt;
        let t = temp_store("doubtful");
        fs::write(&t.store.path, "not json").unwrap();
        assert!(matches!(
            t.store.attest(&brio_ir(), EVIDENCE, true),
            Err(AttestError::Unsafe { .. })
        ));
        assert_eq!(fs::read_to_string(&t.store.path).unwrap(), "not json");

        t.store.save(&[]).unwrap();
        fs::set_permissions(&t.store.path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(t.store.attest(&brio_ir(), EVIDENCE, true).is_err());
        assert!(!t.store.approves(&brio_ir()));

        fs::remove_file(&t.store.path).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", &t.store.path).unwrap();
        assert!(t.store.attest(&brio_ir(), EVIDENCE, true).is_err());
        fs::remove_file(&t.store.path).unwrap();

        fs::set_permissions(&t.dir, fs::Permissions::from_mode(0o775)).unwrap();
        assert!(t.store.attest(&brio_ir(), EVIDENCE, true).is_err());
    }

    #[test]
    fn revoke_also_removes_entries_without_valid_evidence() {
        let t = temp_store("revoke");
        let mut placeholder = profile_for(&brio_ir(), EVIDENCE, true);
        placeholder.evidence = "<replace: evidence>".into();
        t.store.save(&[placeholder]).unwrap();
        assert!(!t.store.approves(&brio_ir()));
        assert_eq!(t.store.revoke(&brio_ir()).unwrap(), 1);
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
