//! Raise the built-in screen's backlight during a scan in a dark room. Needs
//! root, so it runs in the PAM module; external monitors are left alone.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub const BACKLIGHT_DIR: &str = "/sys/class/backlight";

/// A raised backlight, restored by [`Boost::restore`] or on drop.
#[derive(Debug)]
pub struct Boost {
    brightness: PathBuf,
    previous: u64,
    raised_to: u64,
    restored: bool,
}

fn read_u64(path: &Path) -> io::Result<u64> {
    fs::read_to_string(path)?.trim().parse().map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{}: {e}", path.display()),
        )
    })
}

/// Firmware, then platform, then raw: the order systemd and GNOME use.
fn pick(dir: &Path) -> io::Result<Option<PathBuf>> {
    let mut best: Option<(u8, PathBuf)> = None;
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        let rank = match fs::read_to_string(path.join("type"))
            .as_deref()
            .map(str::trim)
        {
            Ok("firmware") => 0,
            Ok("platform") => 1,
            Ok("raw") => 2,
            _ => continue,
        };
        if best.as_ref().is_none_or(|(r, p)| (rank, &path) < (*r, p)) {
            best = Some((rank, path));
        }
    }
    Ok(best.map(|(_, path)| path))
}

/// Set full brightness; `None` without a backlight or when already full.
pub fn raise(dir: &Path) -> io::Result<Option<Boost>> {
    let Some(device) = pick(dir)? else {
        return Ok(None);
    };
    let max = read_u64(&device.join("max_brightness"))?;
    let brightness = device.join("brightness");
    let previous = read_u64(&brightness)?;
    if previous >= max {
        return Ok(None);
    }
    fs::write(&brightness, max.to_string())?;
    Ok(Some(Boost {
        brightness,
        previous,
        raised_to: max,
        restored: false,
    }))
}

impl Boost {
    /// Restore the previous brightness unless it was changed meanwhile.
    pub fn restore(&mut self) -> io::Result<()> {
        if self.restored {
            return Ok(());
        }
        self.restored = true;
        if read_u64(&self.brightness)? != self.raised_to {
            return Ok(());
        }
        fs::write(&self.brightness, self.previous.to_string())
    }
}

impl Drop for Boost {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake(name: &str, devices: &[(&str, &str, u64, u64)]) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("peekin-bl-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        for (device, kind, brightness, max) in devices {
            let d = dir.join(device);
            fs::create_dir_all(&d).unwrap();
            fs::write(d.join("type"), format!("{kind}\n")).unwrap();
            fs::write(d.join("brightness"), format!("{brightness}\n")).unwrap();
            fs::write(d.join("max_brightness"), format!("{max}\n")).unwrap();
        }
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn level(dir: &Path, device: &str) -> u64 {
        read_u64(&dir.join(device).join("brightness")).unwrap()
    }

    #[test]
    fn raises_the_preferred_backlight_and_restores_it() {
        let dir = fake(
            "raise",
            &[
                ("acpi_video0", "firmware", 30, 100),
                ("amdgpu_bl1", "raw", 200, 400),
            ],
        );
        let mut boost = raise(&dir).unwrap().unwrap();
        assert_eq!(level(&dir, "acpi_video0"), 100);
        assert_eq!(
            level(&dir, "amdgpu_bl1"),
            200,
            "only one backlight is touched"
        );
        boost.restore().unwrap();
        assert_eq!(level(&dir, "acpi_video0"), 30);
        drop(boost);
        assert_eq!(level(&dir, "acpi_video0"), 30);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn drop_restores_and_a_manual_change_is_kept() {
        let dir = fake("drop", &[("amdgpu_bl1", "raw", 100, 400)]);
        drop(raise(&dir).unwrap().unwrap());
        assert_eq!(level(&dir, "amdgpu_bl1"), 100);
        let mut boost = raise(&dir).unwrap().unwrap();
        fs::write(dir.join("amdgpu_bl1/brightness"), "250").unwrap();
        boost.restore().unwrap();
        assert_eq!(level(&dir, "amdgpu_bl1"), 250, "the user's own change wins");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn nothing_to_do_without_a_backlight_or_at_full_brightness() {
        let empty = fake("empty", &[]);
        assert!(raise(&empty).unwrap().is_none());
        let full = fake("full", &[("intel_backlight", "raw", 400, 400)]);
        assert!(raise(&full).unwrap().is_none());
        assert!(raise(Path::new("/nonexistent/backlight")).is_err());
        let _ = fs::remove_dir_all(empty);
        let _ = fs::remove_dir_all(full);
    }
}
