//! Whether the laptop lid is closed (`[core] abort_if_lid_closed`).
//!
//! Two sources: the ACPI button driver's state files, which many recent
//! laptops no longer provide, and the lid switch of an input device, which is
//! what logind reads. Either one reporting the lid closed counts.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const ACPI_DIR: &str = "/proc/acpi/button/lid";
pub const INPUT_CLASS_DIR: &str = "/sys/class/input";
pub const DEV_INPUT_DIR: &str = "/dev/input";

/// Where the lid state is read from; injected so tests never touch the system.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub acpi: PathBuf,
    pub input_class: PathBuf,
    pub dev_input: PathBuf,
}

impl Paths {
    pub fn system() -> Self {
        Self {
            acpi: PathBuf::from(ACPI_DIR),
            input_class: PathBuf::from(INPUT_CLASS_DIR),
            dev_input: PathBuf::from(DEV_INPUT_DIR),
        }
    }

    /// Every source under `root` (tests and fixtures).
    pub fn under(root: &Path) -> Self {
        Self {
            acpi: root.join("acpi"),
            input_class: root.join("input"),
            dev_input: root.join("dev-input"),
        }
    }
}

/// `Some(closed)` when the ACPI driver reports at least one lid.
pub fn acpi_state(dir: &Path) -> Option<bool> {
    let entries = fs::read_dir(dir).ok()?;
    let mut seen = None;
    for entry in entries.flatten() {
        if let Ok(body) = fs::read_to_string(entry.path().join("state")) {
            let closed = body.contains("closed");
            seen = Some(seen.unwrap_or(false) || closed);
        }
    }
    seen
}

/// `capabilities/sw` holds hexadecimal words, the lowest bits last; bit 0 of
/// the last word is `SW_LID`.
fn has_lid_switch(capabilities: &str) -> bool {
    capabilities
        .split_whitespace()
        .last()
        .and_then(|word| u64::from_str_radix(word, 16).ok())
        .is_some_and(|bits| bits & 1 == 1)
}

/// `eventN` names of the input devices with a lid switch, in name order.
pub fn lid_switches(input_class: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(input_class)
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|entry| {
                    let name = entry.file_name().into_string().ok()?;
                    if !name.starts_with("event") {
                        return None;
                    }
                    let capabilities =
                        fs::read_to_string(entry.path().join("device/capabilities/sw")).ok()?;
                    has_lid_switch(&capabilities).then_some(name)
                })
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

/// `EVIOCGSW(8)`: read the switch states into 8 bytes
/// (`_IOC(_IOC_READ, 'E', 0x1b, 8)` from `<linux/input.h>`).
const EVIOCGSW: libc::c_ulong = 0x8008_451b;

/// Current state of the lid switch of `<dev_input>/<name>`; `None` when the
/// device cannot be opened or asked (no permission, unplugged).
pub fn switch_closed(dev_input: &Path, name: &str) -> Option<bool> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(dev_input.join(name))
        .ok()?;
    let mut state = [0u8; 8];
    // SAFETY: EVIOCGSW(8) writes at most 8 bytes into the live buffer.
    let rc = unsafe { libc::ioctl(file.as_raw_fd(), EVIOCGSW, state.as_mut_ptr()) };
    (rc >= 0).then(|| state[0] & 1 == 1)
}

/// Whether any source reports the lid closed; an unreadable source counts as
/// open, so face login is never skipped for a lid nobody can see.
pub fn closed(paths: &Paths) -> bool {
    acpi_state(&paths.acpi) == Some(true)
        || lid_switches(&paths.input_class)
            .iter()
            .any(|name| switch_closed(&paths.dev_input, name) == Some(true))
}

/// The sources the lid state can be read from, for diagnostics; empty when
/// this machine reports no lid at all.
pub fn sources(paths: &Paths) -> Vec<String> {
    let mut out = Vec::new();
    if acpi_state(&paths.acpi).is_some() {
        out.push(paths.acpi.display().to_string());
    }
    for name in lid_switches(&paths.input_class) {
        let node = paths.dev_input.join(&name);
        out.push(match switch_closed(&paths.dev_input, &name) {
            Some(_) => node.display().to_string(),
            None => format!("{} (cannot be read)", node.display()),
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (PathBuf, Paths) {
        let root = std::env::temp_dir().join(format!("peekin-lid-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths::under(&root);
        fs::create_dir_all(&paths.acpi).unwrap();
        fs::create_dir_all(&paths.input_class).unwrap();
        (root, paths)
    }

    fn input_device(paths: &Paths, name: &str, sw: &str) {
        let device = paths.input_class.join(name).join("device/capabilities");
        fs::create_dir_all(&device).unwrap();
        fs::write(device.join("sw"), format!("{sw}\n")).unwrap();
    }

    #[test]
    fn acpi_state_is_read_when_present() {
        let (root, paths) = fixture("acpi");
        assert_eq!(acpi_state(&paths.acpi), None, "no lid at all");
        assert!(!closed(&paths));
        assert!(sources(&paths).is_empty());
        fs::create_dir_all(paths.acpi.join("LID0")).unwrap();
        fs::write(paths.acpi.join("LID0/state"), "state:      open\n").unwrap();
        assert_eq!(acpi_state(&paths.acpi), Some(false));
        assert!(!closed(&paths));
        fs::write(paths.acpi.join("LID0/state"), "state:      closed\n").unwrap();
        assert_eq!(acpi_state(&paths.acpi), Some(true));
        assert!(closed(&paths));
        assert_eq!(sources(&paths), [paths.acpi.display().to_string()]);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn lid_switches_come_from_the_switch_capabilities() {
        let (root, paths) = fixture("switches");
        // A lid switch (bit 0), a keyboard with no switches, a tablet-mode
        // switch only (bit 1), and a lid switch on a device with several words.
        input_device(&paths, "event3", "1");
        input_device(&paths, "event0", "0");
        input_device(&paths, "event5", "2");
        input_device(&paths, "event12", "4 1");
        fs::create_dir_all(paths.input_class.join("mouse0")).unwrap();
        assert_eq!(lid_switches(&paths.input_class), ["event12", "event3"]);
        assert!(lid_switches(Path::new("/nonexistent/input")).is_empty());
        assert!(has_lid_switch("3") && !has_lid_switch("2") && !has_lid_switch("x"));
        // No device node to read: not closed, but listed as unreadable.
        assert!(!closed(&paths));
        assert_eq!(switch_closed(&paths.dev_input, "event3"), None);
        assert_eq!(
            sources(&paths),
            [
                format!(
                    "{} (cannot be read)",
                    paths.dev_input.join("event12").display()
                ),
                format!(
                    "{} (cannot be read)",
                    paths.dev_input.join("event3").display()
                ),
            ]
        );
        let _ = fs::remove_dir_all(root);
    }
}
