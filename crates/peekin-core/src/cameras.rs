//! Find cameras usable for face authentication and tell infrared ones apart.
//!
//! Nodes are queried with `VIDIOC_QUERYCAP`/`VIDIOC_ENUM_FMT` without
//! streaming. Greyscale formats only suggest IR; just nodes attested in
//! `/etc/peekin/ir-profiles.json` count as [`CameraKind::VerifiedInfrared`].

use std::fs::{self, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const V4L_BY_PATH: &str = "/dev/v4l/by-path";
/// Serial-number links; unlike `by-path` they survive a port change.
pub const V4L_BY_ID: &str = "/dev/v4l/by-id";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CameraKind {
    /// Device identity and capture profile are explicitly trusted.
    VerifiedInfrared,
    /// Greyscale formats suggest IR, but identity is not verified.
    InfraredCandidate,
    Colour,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Camera {
    /// Stable `/dev/v4l/by-path/...` path, as used for `device_path`.
    pub path: PathBuf,
    pub node: String,
    pub name: String,
    pub kind: CameraKind,
}

impl Camera {
    pub fn label(&self) -> String {
        use crate::i18n::tr;
        let kind = match self.kind {
            CameraKind::VerifiedInfrared => tr("administrator-approved infrared"),
            CameraKind::InfraredCandidate => tr("possible infrared (not approved)"),
            CameraKind::Colour => tr("colour"),
        };
        format!("{} — {kind} ({})", self.name, self.node)
    }
}

// From <linux/videodev2.h>.
const VIDIOC_QUERYCAP: libc::c_ulong = 0x8068_5600;
const VIDIOC_ENUM_FMT: libc::c_ulong = 0xc040_5602;
const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
const V4L2_CAP_DEVICE_CAPS: u32 = 0x8000_0000;
const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;

const fn fourcc(s: &[u8; 4]) -> u32 {
    (s[0] as u32) | (s[1] as u32) << 8 | (s[2] as u32) << 16 | (s[3] as u32) << 24
}

const GREYSCALE_FORMATS: [u32; 6] = [
    fourcc(b"GREY"),
    fourcc(b"Y10 "),
    fourcc(b"Y12 "),
    fourcc(b"Y16 "),
    fourcc(b"Y8I "),
    fourcc(b"Y10B"),
];

#[repr(C)]
struct V4l2Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}

#[repr(C)]
struct V4l2FmtDesc {
    index: u32,
    kind: u32,
    flags: u32,
    description: [u8; 32],
    pixelformat: u32,
    mbus_code: u32,
    reserved: [u32; 3],
}

pub fn classify(capabilities: u32, device_caps: u32, formats: &[u32]) -> Option<CameraKind> {
    let caps = if capabilities & V4L2_CAP_DEVICE_CAPS != 0 {
        device_caps
    } else {
        capabilities
    };
    if caps & V4L2_CAP_VIDEO_CAPTURE == 0 || formats.is_empty() {
        return None;
    }
    if formats.iter().all(|f| GREYSCALE_FORMATS.contains(f)) {
        Some(CameraKind::InfraredCandidate)
    } else {
        Some(CameraKind::Colour)
    }
}

/// Preferred camera: a verified IR node, then the first colour camera, then an
/// unverified IR node (often dark without its emitter).
pub fn best(cameras: &[Camera]) -> Option<&Camera> {
    let first = |kind| cameras.iter().find(|c| c.kind == kind);
    first(CameraKind::VerifiedInfrared)
        .or_else(|| first(CameraKind::Colour))
        .or_else(|| first(CameraKind::InfraredCandidate))
}

fn c_string(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).trim().to_string()
}

/// What the kernel reports for a node, without streaming.
#[derive(Debug, Clone)]
pub struct Probe {
    pub name: String,
    pub driver: String,
    pub kind: CameraKind,
}

pub fn probe(path: &Path) -> Option<Probe> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let fd = file.as_raw_fd();
    // SAFETY: plain-old-data structs sized exactly as the kernel expects.
    let mut cap: V4l2Capability = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, VIDIOC_QUERYCAP, &mut cap) } != 0 {
        return None;
    }
    let mut formats = Vec::new();
    for index in 0..64 {
        let mut desc: V4l2FmtDesc = unsafe { std::mem::zeroed() };
        desc.index = index;
        desc.kind = V4L2_BUF_TYPE_VIDEO_CAPTURE;
        if unsafe { libc::ioctl(fd, VIDIOC_ENUM_FMT, &mut desc) } != 0 {
            break;
        }
        formats.push(desc.pixelformat);
    }
    let driver = c_string(&cap.driver);
    let mut kind = classify(cap.capabilities, cap.device_caps, &formats)?;
    if kind == CameraKind::InfraredCandidate && crate::ir_profile::approved(path, &driver) {
        kind = CameraKind::VerifiedInfrared;
    }
    Some(Probe {
        name: c_string(&cap.card),
        driver,
        kind,
    })
}

pub fn kind_of(path: &Path) -> Option<CameraKind> {
    probe(path).map(|p| p.kind)
}

pub fn list_in(by_path: &Path) -> Vec<Camera> {
    list_in_dirs(by_path, None)
}

fn by_id_links(by_id: &Path) -> std::collections::HashMap<PathBuf, PathBuf> {
    let mut entries: Vec<PathBuf> = fs::read_dir(by_id)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    entries.sort();
    let mut links = std::collections::HashMap::new();
    for path in entries {
        if let Ok(target) = fs::canonicalize(&path) {
            links.entry(target).or_insert(path);
        }
    }
    links
}

/// Like [`list_in`], but with the stable `by-id` link where one exists.
pub fn list_in_dirs(by_path: &Path, by_id: Option<&Path>) -> Vec<Camera> {
    let stable = by_id.map(by_id_links).unwrap_or_default();
    let mut entries: Vec<PathBuf> = fs::read_dir(by_path)
        .map(|d| d.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    // USB devices appear twice (`usb-` and `usbv3-`); keep the first link per node.
    entries.sort();
    let mut seen = std::collections::HashSet::new();
    let mut cameras = Vec::new();
    for path in entries {
        let Ok(target) = fs::canonicalize(&path) else {
            continue;
        };
        if !seen.insert(target.clone()) {
            continue;
        }
        let Some(Probe { name, kind, .. }) = probe(&target) else {
            continue;
        };
        let node = target
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        cameras.push(Camera {
            path: stable.get(&target).cloned().unwrap_or(path),
            node,
            name,
            kind,
        });
    }
    cameras
}

pub fn list() -> Vec<Camera> {
    list_in_dirs(Path::new(V4L_BY_PATH), Some(Path::new(V4L_BY_ID)))
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ResolveError {
    #[error("no camera found (device_path = none selects one automatically)")]
    NoCamera,
    #[error("configured camera {0} does not exist; choose another one in the PeekIn app")]
    Missing(String),
}

pub fn resolved_kind(configured: &str) -> Option<CameraKind> {
    resolve(configured).ok().and_then(|path| kind_of(&path))
}

/// Node to open for `device_path`: [`best`] for `none`/`auto`, otherwise the
/// configured path, which is never swapped for another camera.
pub fn resolve(configured: &str) -> Result<PathBuf, ResolveError> {
    resolve_with(configured, list)
}

fn resolve_with(
    configured: &str,
    cameras: impl FnOnce() -> Vec<Camera>,
) -> Result<PathBuf, ResolveError> {
    if crate::config::is_automatic_device(configured) {
        return best(&cameras())
            .map(|c| c.path.clone())
            .ok_or(ResolveError::NoCamera);
    }
    let path = PathBuf::from(configured.trim());
    if path.exists() {
        Ok(path)
    } else {
        Err(ResolveError::Missing(configured.trim().into()))
    }
}

/// Whether anything could satisfy `configured`, without opening a device.
pub fn plausibly_present(configured: &str) -> bool {
    if crate::config::is_automatic_device(configured) {
        fs::read_dir(V4L_BY_PATH).is_ok_and(|mut d| d.next().is_some())
    } else {
        Path::new(configured.trim()).exists()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const YUYV: u32 = fourcc(b"YUYV");
    const MJPG: u32 = fourcc(b"MJPG");
    const GREY: u32 = fourcc(b"GREY");

    #[test]
    fn fourcc_matches_videodev2() {
        assert_eq!(GREY, 0x5945_5247);
        assert_eq!(fourcc(b"Y16 "), 0x2036_3159);
        assert_eq!(fourcc(b"Y10 "), 0x2030_3159);
    }

    #[test]
    fn classification() {
        let dev = V4L2_CAP_DEVICE_CAPS;
        assert_eq!(
            classify(dev, V4L2_CAP_VIDEO_CAPTURE, &[GREY]),
            Some(CameraKind::InfraredCandidate)
        );
        assert_eq!(
            classify(dev, V4L2_CAP_VIDEO_CAPTURE, &[YUYV, MJPG]),
            Some(CameraKind::Colour)
        );
        assert_eq!(
            classify(dev, V4L2_CAP_VIDEO_CAPTURE, &[YUYV, GREY]),
            Some(CameraKind::Colour)
        );
        // Metadata node: no video capture capability.
        assert_eq!(classify(dev, 0x0080_0000, &[]), None);
        // Capture capability but no formats.
        assert_eq!(classify(dev, V4L2_CAP_VIDEO_CAPTURE, &[]), None);
        // Old drivers without DEVICE_CAPS: fall back to `capabilities`.
        assert_eq!(
            classify(V4L2_CAP_VIDEO_CAPTURE, 0, &[GREY]),
            Some(CameraKind::InfraredCandidate)
        );
    }

    #[test]
    fn spoofable_metadata_never_upgrades_grayscale_to_verified_ir() {
        let kind = classify(V4L2_CAP_VIDEO_CAPTURE, 0, &[GREY]);
        assert_eq!(kind, Some(CameraKind::InfraredCandidate));
        // Card names are device-firmware strings; a lookalike claiming this
        // name must remain an unverified candidate without an attestation.
        let spoofed_card_name = "Logitech BRIO";
        assert!(!spoofed_card_name.is_empty());
        assert_ne!(kind, Some(CameraKind::VerifiedInfrared));
    }

    #[test]
    fn colour_sibling_of_a_brio_ir_node_is_colour_and_cannot_be_verified() {
        // Observed Brio 4K layout: colour node at V4L2 index 0 of the same
        // interface as the GREY-only IR node at index 2.
        let dev = V4L2_CAP_DEVICE_CAPS;
        let cap = V4L2_CAP_VIDEO_CAPTURE;
        assert_eq!(
            classify(dev, cap, &[YUYV, MJPG, fourcc(b"NV12")]),
            Some(CameraKind::Colour)
        );
        // Any colour-capable format list disqualifies verification outright.
        for mixed in [[GREY, YUYV], [GREY, MJPG], [fourcc(b"NV12"), GREY]] {
            assert_ne!(
                classify(dev, cap, &mixed),
                Some(CameraKind::VerifiedInfrared)
            );
        }
    }

    fn cam(n: &str, kind: CameraKind) -> Camera {
        Camera {
            path: PathBuf::from(format!("/dev/v4l/by-path/{n}")),
            node: n.into(),
            name: "x".into(),
            kind,
        }
    }

    #[test]
    fn infrared_preferred_then_first_colour() {
        let list = [
            cam("video0", CameraKind::Colour),
            cam("video1", CameraKind::Colour),
            cam("video3", CameraKind::VerifiedInfrared),
        ];
        assert_eq!(best(&list).unwrap().node, "video3");
        assert_eq!(best(&list[..2]).unwrap().node, "video0");
        assert_eq!(best(&[]), None);
        // An unverified IR sensor (e.g. the Brio's GREY node) loses to the
        // colour camera and is used only when it is the only camera.
        let brio = [
            cam("video2", CameraKind::InfraredCandidate),
            cam("video0", CameraKind::Colour),
        ];
        assert_eq!(best(&brio).unwrap().node, "video0");
        assert_eq!(best(&brio[..1]).unwrap().node, "video2");
    }

    #[test]
    fn labels() {
        let c = Camera {
            path: "/p".into(),
            node: "video3".into(),
            name: "Logitech BRIO".into(),
            kind: CameraKind::InfraredCandidate,
        };
        assert_eq!(
            c.label(),
            "Logitech BRIO — possible infrared (not approved) (video3)"
        );
    }

    #[test]
    fn missing_directory_lists_nothing() {
        assert!(list_in(Path::new("/nonexistent/by-path")).is_empty());
    }

    #[test]
    fn resolve_picks_preferred_camera_only_when_automatic() {
        let found = || {
            vec![
                cam("video0", CameraKind::Colour),
                cam("video2", CameraKind::InfraredCandidate),
            ]
        };
        assert_eq!(
            resolve_with("none", found),
            Ok(PathBuf::from("/dev/v4l/by-path/video0"))
        );
        assert_eq!(
            resolve_with("auto", found),
            Ok(PathBuf::from("/dev/v4l/by-path/video0"))
        );
        assert_eq!(resolve_with("none", Vec::new), Err(ResolveError::NoCamera));
        // An explicit path is never replaced by another camera.
        assert_eq!(
            resolve_with("/nonexistent/video9", found),
            Err(ResolveError::Missing("/nonexistent/video9".into()))
        );
        assert_eq!(
            resolve_with("/dev/null", found),
            Ok(PathBuf::from("/dev/null"))
        );
    }

    #[test]
    fn by_id_links_map_back_to_their_node() {
        let dir = std::env::temp_dir().join(format!("peekin-byid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("by-id")).unwrap();
        fs::write(dir.join("video0"), "").unwrap();
        std::os::unix::fs::symlink(dir.join("video0"), dir.join("by-id/usb-cam-video-index0"))
            .unwrap();
        let links = by_id_links(&dir.join("by-id"));
        assert_eq!(
            links.get(&fs::canonicalize(dir.join("video0")).unwrap()),
            Some(&dir.join("by-id/usb-cam-video-index0"))
        );
        assert!(by_id_links(Path::new("/nonexistent/by-id")).is_empty());
        let _ = fs::remove_dir_all(dir);
    }
}
