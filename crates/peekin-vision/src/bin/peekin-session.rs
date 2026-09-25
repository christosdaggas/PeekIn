//! `peekin-session [--dry-run [--away SECS]] [--check-camera]`: per-user helper (systemd user service).
//! After an unlock it reports face attempts rejected while away; with `lock_when_away` it locks
//! the screen when there is no input and no face. It only locks; unlocking always goes through PAM.

use peekin_core::activity;
use peekin_core::compare::{classify_frame, FrameClass};
use peekin_core::i18n::{tr, trn};
use peekin_core::session::{Action, AwayCamera, CameraChoice, Presence, Seen, SessionSettings};
use peekin_core::source::FaceSource;
use peekin_core::{PeekinConfig, PeekinPaths};
use peekin_vision::OpenCvFaceSource;
use std::ffi::CStr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const TICK: Duration = Duration::from_secs(3);
const CHECK_TIME: Duration = Duration::from_millis(1500);

/// The method arguments follow `--`, or a negative number (e.g. timeout -1) would parse as an option.
fn gdbus_args(dest: &str, path: &str, method: &str, args: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = [
        "call",
        "--session",
        "--dest",
        dest,
        "--object-path",
        path,
        "--method",
        method,
        "--",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    out.extend(args.iter().map(|s| s.to_string()));
    out
}

/// The reply text, or None on any failure.
fn gdbus(dest: &str, path: &str, method: &str, args: &[&str]) -> Option<String> {
    let out = Command::new("gdbus")
        .args(gdbus_args(dest, path, method, args))
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// Time since the last input (GNOME's idle monitor).
fn idle_time() -> Option<Duration> {
    let reply = gdbus(
        "org.gnome.Mutter.IdleMonitor",
        "/org/gnome/Mutter/IdleMonitor/Core",
        "org.gnome.Mutter.IdleMonitor.GetIdletime",
        &[],
    )?;
    let ms: u64 = reply
        .trim_start_matches("(uint64 ")
        .trim_end_matches(",)")
        .parse()
        .ok()?;
    Some(Duration::from_millis(ms))
}

fn screen_locked() -> Option<bool> {
    let reply = gdbus(
        "org.gnome.ScreenSaver",
        "/org/gnome/ScreenSaver",
        "org.gnome.ScreenSaver.GetActive",
        &[],
    )?;
    Some(reply == "(true,)")
}

/// E.g. a video player asks the desktop not to go idle.
fn idle_inhibited() -> bool {
    gdbus(
        "org.gnome.SessionManager",
        "/org/gnome/SessionManager",
        "org.gnome.SessionManager.IsInhibited",
        &["8"],
    )
    .is_some_and(|reply| reply == "(true,)")
}

fn lock_screen() -> bool {
    gdbus(
        "org.gnome.ScreenSaver",
        "/org/gnome/ScreenSaver",
        "org.gnome.ScreenSaver.Lock",
        &[],
    )
    .is_some()
}

fn gvariant_string(text: &str) -> String {
    format!("\"{}\"", text.replace('\\', "\\\\").replace('"', "\\\""))
}

fn notify(summary: &str, body: &str) -> bool {
    gdbus(
        "org.freedesktop.Notifications",
        "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications.Notify",
        &[
            "\"PeekIn\"",
            "0",
            "\"com.chrisdaggas.peekin\"",
            &gvariant_string(summary),
            &gvariant_string(body),
            "[]",
            "{\"desktop-entry\": <\"com.chrisdaggas.peekin\">}",
            "-1",
        ],
    )
    .is_some()
}

fn user_name() -> Option<String> {
    // SAFETY: getpwuid returns static storage or null; copied immediately.
    let pwd = unsafe { libc::getpwuid(libc::getuid()) };
    if pwd.is_null() {
        return None;
    }
    Some(
        unsafe { CStr::from_ptr((*pwd).pw_name) }
            .to_string_lossy()
            .into_owned(),
    )
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

/// `$XDG_STATE_HOME/peekin/notified`: the newest history entry already reported.
fn notified_path() -> Option<PathBuf> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".local/state")))?;
    Some(base.join("peekin/notified"))
}

/// Reports failed attempts not yet told about; the first run only records the position.
fn notify_failed_attempts(user: &str, settings: &SessionSettings, dry_run: bool) {
    let Some(state) = notified_path() else { return };
    let Ok(entries) = activity::read(Path::new(activity::ACTIVITY_DIR), user) else {
        return;
    };
    let newest = entries.iter().map(|e| e.time).max().unwrap_or(0);
    let since = match std::fs::read_to_string(&state)
        .ok()
        .and_then(|s| s.trim().parse().ok())
    {
        Some(since) => since,
        None => {
            remember(&state, newest.max(unix_now()));
            return;
        }
    };
    let failed = activity::failed_since(&entries, since);
    if failed > 0 && settings.notify_failed_attempts {
        let summary = trn(
            "{n} failed face attempt while you were away",
            "{n} failed face attempts while you were away",
            failed as u64,
        );
        let body = tr("Open PeekIn to see when and where (Face models, Activity).");
        if dry_run {
            println!("notify: {summary}");
        } else if !notify(&summary, &body) {
            eprintln!("cannot show the notification about failed attempts");
        }
    }
    if newest > since {
        remember(&state, newest);
    }
}

fn remember(state: &Path, time: u64) {
    if let Some(dir) = state.parent() {
        let _ = std::fs::create_dir_all(dir);
    }
    if let Err(error) = std::fs::write(state, format!("{time}\n")) {
        eprintln!("cannot write {}: {error}", state.display());
    }
}

fn saved_settings() -> SessionSettings {
    SessionSettings::path()
        .as_deref()
        .map(SessionSettings::load)
        .unwrap_or_default()
}

/// Open only while there is no input.
struct Camera {
    source: Option<OpenCvFaceSource>,
    dark_threshold: f64,
    paths: PeekinPaths,
    choice: CameraChoice,
}

impl Camera {
    fn check(&mut self) -> Seen {
        if self.source.is_none() {
            let paths = &self.paths;
            let config = match PeekinConfig::load(&paths.config_file_path()) {
                Ok(config) => config,
                Err(error) => {
                    eprintln!("{error}");
                    return Seen::Unknown;
                }
            };
            self.dark_threshold = config.dark_threshold();
            let config = match self.choice.resolve(&peekin_core::cameras::list()) {
                AwayCamera::LoginCamera => config,
                AwayCamera::Device(device) => config.with_camera(&device.to_string_lossy()),
                AwayCamera::NoneConnected => {
                    eprintln!("no camera of the chosen kind is connected, assuming you are there");
                    return Seen::Unknown;
                }
            };
            match OpenCvFaceSource::open(&config, paths) {
                Ok(source) => self.source = Some(source),
                Err(error) => {
                    eprintln!("camera unavailable, assuming you are there: {error}");
                    return Seen::Unknown;
                }
            }
        }
        let source = self.source.as_mut().expect("opened above");
        let started = Instant::now();
        let mut usable = false;
        while started.elapsed() < CHECK_TIME {
            let stats = match source.next_frame() {
                Ok(stats) => stats,
                Err(error) => {
                    // Busy (e.g. a video call) or unplugged: release it.
                    eprintln!("camera read failed, assuming you are there: {}", error.0);
                    self.source = None;
                    return Seen::Unknown;
                }
            };
            if !matches!(
                classify_frame(&stats.hist, self.dark_threshold),
                FrameClass::Scan { .. }
            ) {
                continue;
            }
            usable = true;
            match source.detect() {
                Ok(faces) if !faces.is_empty() => return Seen::Face,
                Ok(_) => {}
                Err(error) => {
                    eprintln!("face detection failed: {}", error.0);
                    return Seen::Unknown;
                }
            }
        }
        if usable {
            Seen::NoFace
        } else {
            Seen::Unknown // too dark to tell
        }
    }

    fn close(&mut self) {
        self.source = None;
    }
}

fn main() {
    // SAFETY: at start-up, before any other thread; "" selects the environment's locale.
    unsafe { libc::setlocale(libc::LC_ALL, c"".as_ptr()) };
    let mut args = std::env::args().skip(1);
    let (mut dry_run, mut away_override) = (false, None);
    let (mut config_dir, mut data_dir) = (None, None);
    let mut check_once = false;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--dry-run" => dry_run = true,
            "--check-camera" => check_once = true,
            "--away" => away_override = args.next().and_then(|v| v.parse::<u64>().ok()),
            "--config-dir" => config_dir = args.next().map(PathBuf::from),
            "--data-dir" => data_dir = args.next().map(PathBuf::from),
            _ => {
                eprintln!(
                    "usage: peekin-session [--dry-run [--away SECS] | --check-camera] \
                     [--config-dir DIR --data-dir DIR]"
                );
                std::process::exit(2);
            }
        }
    }
    let testing = away_override.is_some() || config_dir.is_some() || data_dir.is_some();
    if testing && !dry_run && !check_once {
        eprintln!("--away, --config-dir and --data-dir are only for --dry-run and --check-camera");
        std::process::exit(2);
    }
    let paths = PeekinPaths::from_dirs(
        config_dir.unwrap_or_else(|| "/etc/peekin".into()),
        data_dir.unwrap_or_else(|| "/usr/share/peekin".into()),
    );
    if check_once {
        let mut camera = Camera {
            source: None,
            dark_threshold: 60.0,
            paths,
            choice: saved_settings().camera,
        };
        let started = Instant::now();
        let seen = camera.check();
        println!("{seen:?} ({} ms)", started.elapsed().as_millis());
        std::process::exit(if seen == Seen::Unknown { 1 } else { 0 });
    }
    let Some(user) = user_name() else {
        eprintln!("cannot resolve the current user");
        std::process::exit(1);
    };
    if let Some((config, state)) = peekin_core::session::xdg_bases() {
        if let Err(error) = peekin_core::session::migrate_legacy_files(&config, &state) {
            eprintln!("cannot take over the linux-hello session settings: {error}");
        }
    }
    let settings_path = SessionSettings::path();
    let started = Instant::now();
    let mut presence = Presence::default();
    let mut camera = Camera {
        source: None,
        dark_threshold: 60.0,
        paths,
        choice: CameraChoice::default(),
    };
    let mut seen = None;
    let mut was_locked = true; // so the first unlocked tick checks the history
    loop {
        let mut settings = settings_path
            .as_deref()
            .map(SessionSettings::load)
            .unwrap_or_default();
        if dry_run {
            settings.lock_when_away = true;
        }
        if camera.choice != settings.camera {
            // Another camera chosen in the app: use it from the next check.
            camera.close();
            camera.choice = settings.camera.clone();
        }
        let locked = screen_locked().unwrap_or(false);
        if was_locked && !locked {
            notify_failed_attempts(&user, &settings, dry_run);
        }
        was_locked = locked;
        if locked || !settings.lock_when_away {
            camera.close();
            presence = Presence::default();
            seen = None;
            std::thread::sleep(TICK);
            continue;
        }
        let away = Duration::from_secs(away_override.unwrap_or(u64::from(settings.away_secs)));
        let idle = idle_time().unwrap_or_default();
        let inhibited = idle_inhibited();
        let action = presence.tick(started.elapsed(), idle, inhibited, away, seen.take());
        if dry_run {
            println!(
                "idle {:>4}s inhibited {inhibited} -> {action:?}",
                idle.as_secs()
            );
        }
        match action {
            Action::Idle => camera.close(),
            Action::Check => {
                let result = camera.check();
                if dry_run {
                    println!("  camera: {result:?}");
                }
                seen = Some(result);
            }
            Action::Lock => {
                camera.close();
                if dry_run {
                    println!("  would lock the screen now");
                } else if !lock_screen() {
                    eprintln!("cannot lock the screen");
                }
            }
        }
        std::thread::sleep(TICK);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn method_arguments_follow_the_option_terminator() {
        let args = gdbus_args("d", "/p", "m.M", &["\"x\"", "-1"]);
        let end = args.iter().position(|a| a == "--").unwrap();
        assert_eq!(&args[end + 1..], ["\"x\"", "-1"]);
        assert!(args[..end].iter().all(|a| a != "-1"));
    }

    #[test]
    fn strings_are_quoted_for_gvariant() {
        assert_eq!(
            gvariant_string(r#"say "hi" \ bye"#),
            r#""say \"hi\" \\ bye""#
        );
    }
}
