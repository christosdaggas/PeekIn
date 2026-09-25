//! Narrow pkexec entry point for the settings app: no path, editor or arbitrary-user switches.

use anyhow::{anyhow, bail, Context, Result};
use peekin_core::management::{apply_settings, revision, SettingsUpdate};
use peekin_core::models::{self, FaceModel, ModelError, EMBEDDING_FORMAT};
use peekin_core::snapshots;
use peekin_core::{ir_profile, lockout};
use peekin_core::{PeekinConfig, PeekinPaths};
use std::ffi::CStr;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

const SERVICE_USER: &str = "peekin";
const MAX_TEST_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_TEST_PACKET_BYTES: usize = 16 * 1024 * 1024;

fn caller() -> Result<(String, libc::uid_t, libc::gid_t)> {
    if unsafe { libc::geteuid() } != 0 {
        bail!("helper must run via pkexec")
    }
    let uid: libc::uid_t = std::env::var("PKEXEC_UID")
        .context("PKEXEC_UID is required")?
        .parse()?;
    if uid == 0 {
        bail!("root is not a GUI management identity")
    }
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    if unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut result) } != 0
        || result.is_null()
    {
        bail!("cannot resolve authorized caller")
    }
    let user = unsafe { CStr::from_ptr(pwd.pw_name) }
        .to_string_lossy()
        .into_owned();
    peekin_core::paths::validate_username(&user)?;
    Ok((user, pwd.pw_uid, pwd.pw_gid))
}

fn service_identity() -> Result<(libc::uid_t, libc::gid_t, Vec<libc::gid_t>)> {
    let name = std::ffi::CString::new(SERVICE_USER)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 16 * 1024];
    let mut result = std::ptr::null_mut();
    if unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr(),
            buf.len(),
            &mut result,
        )
    } != 0
        || result.is_null()
    {
        bail!("dedicated service account {SERVICE_USER} is unavailable")
    }
    if pwd.pw_name.is_null() || pwd.pw_shell.is_null() {
        bail!("dedicated service account {SERVICE_USER} is malformed")
    }
    let resolved_name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes();
    let shell = unsafe { CStr::from_ptr(pwd.pw_shell) }.to_string_lossy();
    if resolved_name != SERVICE_USER.as_bytes()
        || !(shell.ends_with("/nologin") || shell.ends_with("/false"))
    {
        bail!("dedicated service account {SERVICE_USER} is malformed")
    }
    let mut count = 0;
    unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, std::ptr::null_mut(), &mut count) };
    if !(1..=256).contains(&count) {
        bail!("invalid service group count")
    }
    let mut groups = vec![pwd.pw_gid; count.max(1) as usize];
    if unsafe { libc::getgrouplist(name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut count) } < 0
    {
        bail!("cannot resolve service groups")
    }
    groups.truncate(count as usize);
    peekin_core::process::validate_service_identity(pwd.pw_uid, pwd.pw_gid, &groups)?;
    Ok((pwd.pw_uid, pwd.pw_gid, groups))
}

fn relay_packets(mut input: impl Read, mut emit: impl FnMut(&[u8]) -> Result<()>) -> Result<()> {
    let mut relayed = 0u64;
    loop {
        let mut header = [0u8; 5];
        match input.read(&mut header[..1]) {
            Ok(0) => return Ok(()),
            Ok(1) => {}
            Ok(_) => unreachable!(),
            Err(error) => return Err(error.into()),
        }
        input
            .read_exact(&mut header[1..])
            .context("malformed worker packet header")?;
        let len = u32::from_le_bytes(header[1..5].try_into().unwrap()) as usize;
        if len > MAX_TEST_PACKET_BYTES {
            bail!("worker packet exceeds limit")
        }
        relayed = relayed
            .checked_add(5 + len as u64)
            .ok_or_else(|| anyhow!("worker output size overflow"))?;
        if relayed > MAX_TEST_OUTPUT_BYTES {
            bail!("worker output exceeds total limit")
        }
        let mut body = vec![0; len];
        input
            .read_exact(&mut body)
            .context("malformed worker packet body")?;
        emit(&header)?;
        emit(&body)?;
    }
}

fn write_all_poll(
    output: &impl AsRawFd,
    mut bytes: &[u8],
    deadline: Instant,
    cancelled: &AtomicBool,
) -> Result<()> {
    while !bytes.is_empty() {
        if cancelled.load(Ordering::Acquire) {
            bail!("test relay cancelled")
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            bail!("test relay exceeded runtime limit")
        }
        let mut descriptor = libc::pollfd {
            fd: output.as_raw_fd(),
            events: libc::POLLOUT,
            revents: 0,
        };
        let timeout = remaining.min(Duration::from_millis(50)).as_millis() as i32;
        let ready = unsafe { libc::poll(&mut descriptor, 1, timeout.max(1)) };
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error.into());
        }
        if ready == 0 {
            continue;
        }
        if descriptor.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
            bail!("test output reader disconnected")
        }
        let written =
            unsafe { libc::write(output.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if written < 0 {
            let error = std::io::Error::last_os_error();
            if matches!(
                error.kind(),
                std::io::ErrorKind::Interrupted | std::io::ErrorKind::WouldBlock
            ) {
                continue;
            }
            return Err(error.into());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

fn wait_for_relay(receiver: &Receiver<Result<()>>, deadline: Instant) -> Result<()> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    match receiver.recv_timeout(remaining) {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => bail!("test relay exceeded runtime limit"),
        Err(RecvTimeoutError::Disconnected) => bail!("test relay terminated unexpectedly"),
    }
}

fn caller_cancelled(input: &mut impl Read) -> Result<bool> {
    let mut byte = [0u8; 1];
    match input.read(&mut byte) {
        Ok(0) | Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn terminate_worker(child: &mut std::process::Child) {
    if let Some(stdin) = child.stdin.as_mut() {
        let _ = std::io::Write::write_all(stdin, b"X");
    }
    child.stdin.take();
    let group = child.id() as libc::pid_t;
    unsafe { libc::kill(-group, libc::SIGTERM) };
    let grace = Instant::now() + Duration::from_millis(200);
    while Instant::now() < grace && matches!(child.try_wait(), Ok(None)) {
        std::thread::sleep(Duration::from_millis(5));
    }
    if matches!(child.try_wait(), Ok(None)) {
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }
    let _ = child.wait();
}

fn test_broker(user: &str, seconds: u32) -> Result<()> {
    if !(1..=30).contains(&seconds) {
        bail!("test duration must be in [1, 30]")
    }
    let (uid, gid, groups) = service_identity()?;
    let parent_pid = unsafe { libc::getpid() };
    let mut command = Command::new("/usr/bin/peekin-settings");
    command
        .args([
            "--preview-test-worker",
            "/etc/peekin",
            "/usr/share/peekin",
            user,
            &seconds.to_string(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .envs(peekin_core::process::WORKER_ENV.iter().copied());
    unsafe {
        command.pre_exec(move || {
            if libc::setpgid(0, 0) != 0
                || libc::setgroups(groups.len(), groups.as_ptr()) != 0
                || libc::setgid(gid) != 0
                || libc::setuid(uid) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
                || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for (resource, value) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_NOFILE, 64),
                (libc::RLIMIT_AS, peekin_core::process::WORKER_ADDRESS_SPACE),
                (
                    libc::RLIMIT_CPU,
                    peekin_core::process::worker_cpu_limit(Duration::from_secs(seconds as u64)).1,
                ),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: value,
                    rlim_max: value,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    let mut child = command.spawn()?;
    let mut output = child
        .stdout
        .take()
        .ok_or_else(|| anyhow!("test worker has no output"))?;
    let relay_output = std::fs::OpenOptions::new()
        .write(true)
        .custom_flags(libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open("/proc/self/fd/1")
        .context("cannot open bounded test output")?;
    let deadline = Instant::now() + Duration::from_secs(seconds as u64 + 10);
    let relay_cancel = Arc::new(AtomicBool::new(false));
    let thread_cancel = relay_cancel.clone();
    let (relay_tx, relay_rx) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let result = relay_packets(&mut output, |bytes| {
            write_all_poll(&relay_output, bytes, deadline, &thread_cancel)
        });
        let _ = relay_tx.send(result);
    });
    let fd = std::io::stdin().as_raw_fd();
    unsafe {
        libc::fcntl(
            fd,
            libc::F_SETFL,
            libc::fcntl(fd, libc::F_GETFL) | libc::O_NONBLOCK,
        )
    };
    let mut cancelled = false;
    let mut relay_result = None;
    let mut stdin = std::io::stdin();
    loop {
        if relay_result.is_none() {
            match relay_rx.try_recv() {
                Ok(result) => {
                    if result.is_err() {
                        cancelled = true;
                        relay_cancel.store(true, Ordering::Release);
                        terminate_worker(&mut child);
                    }
                    relay_result = Some(result);
                }
                Err(mpsc::TryRecvError::Empty) => {}
                Err(mpsc::TryRecvError::Disconnected) => {
                    cancelled = true;
                    relay_cancel.store(true, Ordering::Release);
                    relay_result = Some(Err(anyhow!("test relay terminated unexpectedly")));
                    terminate_worker(&mut child);
                }
            }
        }
        if child.try_wait()?.is_some() {
            break;
        }
        match caller_cancelled(&mut stdin) {
            Ok(true) => {
                cancelled = true;
                relay_cancel.store(true, Ordering::Release);
                terminate_worker(&mut child);
                break;
            }
            Ok(false) => {}
            Err(_) => {
                cancelled = true;
                relay_cancel.store(true, Ordering::Release);
                terminate_worker(&mut child);
                break;
            }
        }
        if Instant::now() >= deadline {
            cancelled = true;
            relay_cancel.store(true, Ordering::Release);
            terminate_worker(&mut child);
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let reap_deadline = Instant::now() + Duration::from_secs(2);
    while child.try_wait()?.is_none() && Instant::now() < reap_deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    if relay_result.is_none() && !cancelled {
        relay_result = Some(wait_for_relay(&relay_rx, deadline));
    }
    if let Some(result) = relay_result {
        result?;
    }
    Ok(())
}

fn model_owner(paths: &PeekinPaths) -> Result<(libc::uid_t, libc::gid_t)> {
    let (_, gid, _) = service_identity()?;
    models::prepare_model_store(paths.user_models_dir(), 0, gid)?;
    Ok((0, gid))
}

fn input(limit: u64) -> Result<String> {
    let mut body = String::new();
    std::io::stdin().take(limit + 1).read_to_string(&mut body)?;
    if body.len() as u64 > limit {
        bail!("request too large")
    }
    Ok(body)
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, &b)| n | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            out.push(if i <= chunk.len() {
                ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char
            } else {
                '='
            });
        }
    }
    out
}

/// An unreadable state is reported as such, never as "no failures".
fn attempts(config: &PeekinConfig, user: &str) -> serde_json::Value {
    attempts_in(Path::new(lockout::STATE_DIR), config, user, lockout::now())
}

fn attempts_in(dir: &Path, config: &PeekinConfig, user: &str, now: u64) -> serde_json::Value {
    let limit = config.max_failed_attempts();
    match lockout::load(dir, user) {
        Ok(record) => {
            let current = record.current(now);
            let pause = record.pause(now, limit);
            serde_json::json!({
                "failures": current.failures,
                "no_face_scans": current.no_face,
                "limit": limit,
                "paused_until": pause.map(|p| p.until),
                "paused_by": pause.map(|p| match p.cause {
                    lockout::PauseCause::FailedFaces(_) => "failed-attempts",
                    lockout::PauseCause::NoFace(_) => "no-face",
                }),
            })
        }
        Err(error) => serde_json::json!({"error": error.to_string()}),
    }
}

fn camera_path(path: &str) -> bool {
    path != "none" && peekin_core::management::valid_device_path(path)
}

fn ready_for_write() -> Result<()> {
    println!("READY");
    std::io::stdout().flush()?;
    Ok(())
}

fn main() -> Result<()> {
    peekin_core::process::arm_parent_death()?;
    peekin_core::process::disable_dumpability()?;
    // Hard 60 s bound, also covering a stalled caller or lock wait.
    unsafe {
        libc::alarm(60);
    }
    let mut args = std::env::args().skip(1);
    let operation = args.next().ok_or_else(|| anyhow!("operation required"))?;
    let rest: Vec<String> = args.collect();
    let (user, _uid, _gid) = caller()?;
    let paths = PeekinPaths::from_dirs("/etc/peekin".into(), "/usr/share/peekin".into());
    match operation.as_str() {
        "metadata" if rest.is_empty() => {
            let raw = std::fs::read_to_string(paths.config_file_path())?;
            let config = PeekinConfig::parse(&raw, paths.config_file_path().display().to_string())?;
            let mut personal_threshold = None;
            let model_rows = match models::load_user_models(paths.user_models_dir(), &user) {
                Ok(items) => {
                    let known = models::usable_embeddings(&items);
                    personal_threshold = peekin_core::matcher::personal_threshold(&known)
                        .map(|personal| f64::from(personal).max(config.min_similarity()));
                    let usable: std::collections::HashSet<_> = models::usable_embeddings(&items)
                        .into_iter()
                        .map(|(i, _)| i)
                        .collect();
                    items.iter().enumerate().map(|(index, m)| serde_json::json!({"id":m.id,"label":m.label,"time":m.time,"usable":usable.contains(&index)})).collect::<Vec<_>>()
                }
                Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
                Err(e) => return Err(e.into()),
            };
            println!(
                "{}",
                serde_json::json!({"version":1,"user":user,"config_revision":revision(&raw),"config_errors":config.invalid_values(),"models":model_rows,"attempts":attempts(&config, &user),"personal_threshold":personal_threshold})
            );
        }
        "apply-settings" if rest.is_empty() => {
            ready_for_write()?;
            let update: SettingsUpdate = serde_json::from_str(&input(64 * 1024)?)?;
            println!("{}", apply_settings(&paths.config_file_path(), &update)?);
        }
        "enroll" if rest.len() <= 1 => {
            ready_for_write()?;
            let label = rest.first().cloned().unwrap_or_default();
            let data = models::parse_import(&input(256 * 1024)?).map_err(|e| anyhow!(e))?;
            let _lock = models::lock_user_models(paths.user_models_dir(), &user)?;
            let mut existing = match models::load_user_models(paths.user_models_dir(), &user) {
                Ok(existing) => existing,
                Err(ModelError::NotInitialised | ModelError::NoModelForUser(_)) => Vec::new(),
                Err(error) => return Err(error.into()),
            };
            let id = FaceModel::next_id(&existing);
            existing.push(FaceModel {
                id,
                label: FaceModel::sanitise_label(&if label.is_empty() {
                    format!("Model #{id}")
                } else {
                    label
                }),
                time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs() as i64,
                format: Some(EMBEDDING_FORMAT.into()),
                data,
            });
            let (uid, gid) = model_owner(&paths)?;
            peekin_core::sealed::replace_models(&paths, &user, Some(&existing), uid, gid)?;
            println!("added {id}");
        }
        "add-samples" if rest.len() == 1 && rest[0].bytes().all(|b| b.is_ascii_digit()) => {
            ready_for_write()?;
            let data = models::parse_import(&input(256 * 1024)?).map_err(|e| anyhow!(e))?;
            let _lock = models::lock_user_models(paths.user_models_dir(), &user)?;
            let mut existing = models::load_user_models(paths.user_models_dir(), &user)?;
            let count = models::append_samples(&mut existing, &rest[0], &user, data)?;
            let (uid, gid) = model_owner(&paths)?;
            peekin_core::sealed::replace_models(&paths, &user, Some(&existing), uid, gid)?;
            println!("model {} now has {count} samples", rest[0]);
        }
        "remove" if rest.len() == 1 && rest[0].bytes().all(|b| b.is_ascii_digit()) => {
            ready_for_write()?;
            if input(16)? != "remove\n" {
                bail!("remove confirmation token missing");
            }
            let _lock = models::lock_user_models(paths.user_models_dir(), &user)?;
            let existing = models::load_user_models(paths.user_models_dir(), &user)?;
            if !existing.iter().any(|m| m.id.to_string() == rest[0]) {
                return Err(ModelError::UnknownId(rest[0].clone(), user.clone()).into());
            }
            let kept: Vec<FaceModel> = existing
                .into_iter()
                .filter(|m| m.id.to_string() != rest[0])
                .collect();
            let (uid, gid) = model_owner(&paths)?;
            let new = (!kept.is_empty()).then_some(kept.as_slice());
            peekin_core::sealed::replace_models(&paths, &user, new, uid, gid)?;
            println!("removed {}", rest[0]);
        }
        "snapshots" if rest.is_empty() => {
            // Only the caller's own photos, newest first, as base64 JPEG.
            let dir = Path::new(snapshots::SNAPSHOT_DIR);
            let items = match snapshots::list(dir, &user) {
                Ok(items) => items,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(e) => return Err(e.into()),
            };
            // Written by the worker account into its own directory: read
            // only its regular files, never through a link.
            let (worker_uid, _, _) = service_identity()?;
            let mut rows = Vec::new();
            for item in items.iter().rev() {
                let bytes = snapshots::read(item, worker_uid)?;
                rows.push(serde_json::json!({"time": item.time, "jpeg": base64(&bytes)}));
            }
            println!(
                "{}",
                serde_json::json!({"version": 1, "user": user, "snapshots": rows})
            );
        }
        "clear-snapshots" if rest.is_empty() => {
            ready_for_write()?;
            if input(16)? != "clear\n" {
                bail!("clear confirmation token missing");
            }
            let removed = match snapshots::clear(Path::new(snapshots::SNAPSHOT_DIR), &user) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
                other => other?,
            };
            println!("removed {removed}");
        }
        "reset-attempts" if rest.is_empty() => {
            ready_for_write()?;
            if input(16)? != "reset\n" {
                bail!("reset confirmation token missing");
            }
            lockout::reset(Path::new(lockout::STATE_DIR), &user)?;
            println!("reset");
        }
        "attest-ir" if rest.len() == 1 && camera_path(&rest[0]) => {
            ready_for_write()?;
            let evidence = input(4096)?;
            // The identity is read here, as root, never taken from the caller.
            let candidate = ir_profile::inspect(Path::new(&rest[0]))?;
            match ir_profile::Store::system().attest(&candidate.identity, &evidence, true)? {
                ir_profile::Attested::Added => println!("attested"),
                ir_profile::Attested::AlreadyAttested => println!("already attested"),
            }
        }
        "revoke-ir" if rest.len() == 1 && camera_path(&rest[0]) => {
            ready_for_write()?;
            if input(16)? != "revoke\n" {
                bail!("revoke confirmation token missing");
            }
            let candidate = ir_profile::inspect(Path::new(&rest[0]))?;
            let removed = ir_profile::Store::system().revoke(&candidate.identity)?;
            println!("removed {removed}");
        }
        "test" if rest.len() == 1 => test_broker(&user, rest[0].parse()?)?,
        _ => bail!("unsupported helper operation or arguments"),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attempts_report_counts_and_the_cause_of_a_pause() {
        let dir =
            std::env::temp_dir().join(format!("peekin-helper-attempts-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let config =
            PeekinConfig::parse("[core]\nmax_failed_attempts = 5\n", "<t>".into()).unwrap();
        let now = 1_790_000_000;
        let state = |user| attempts_in(&dir, &config, user, now);
        assert_eq!(
            state("alice"),
            serde_json::json!({"failures":0,"no_face_scans":0,"limit":5,"paused_until":null,"paused_by":null})
        );
        lockout::record_failure(&dir, "alice", now).unwrap();
        for _ in 0..lockout::MAX_NO_FACE_SCANS {
            lockout::record_no_face(&dir, "alice", now - 60).unwrap();
        }
        let until = now - 60 + lockout::LOCKOUT.as_secs();
        assert_eq!(
            state("alice"),
            serde_json::json!({"failures":1,"no_face_scans":lockout::MAX_NO_FACE_SCANS,"limit":5,"paused_until":until,"paused_by":"no-face"})
        );
        for _ in 0..4 {
            lockout::record_failure(&dir, "alice", now).unwrap();
        }
        assert_eq!(
            state("alice")["paused_by"],
            "failed-attempts",
            "the later pause"
        );
        std::fs::write(dir.join("bob"), "garbage\n").unwrap();
        assert!(state("bob")["error"].is_string());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn only_camera_nodes_reach_attestation() {
        for ok in [
            "/dev/video2",
            "/dev/v4l/by-id/usb-Logitech_BRIO-video-index2",
        ] {
            assert!(camera_path(ok), "{ok}");
        }
        for bad in [
            "none",
            "/etc/passwd",
            "/dev/v4l/by-id/../../etc",
            "/dev/video",
            "video2",
        ] {
            assert!(!camera_path(bad), "{bad}");
        }
    }
    use std::io::Cursor;
    use std::os::fd::FromRawFd;

    fn packet(body: &[u8]) -> Vec<u8> {
        let mut packet = vec![7];
        packet.extend_from_slice(&(body.len() as u32).to_le_bytes());
        packet.extend_from_slice(body);
        packet
    }

    #[test]
    fn base64_matches_rfc_4648() {
        for (plain, encoded) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(plain.as_bytes()), encoded);
        }
        assert_eq!(base64(&[0xff, 0xfe, 0x00]), "//4A");
    }

    #[test]
    fn relay_accepts_packets_and_clean_eof() {
        let bytes = packet(b"result");
        let mut output = Vec::new();
        relay_packets(Cursor::new(&bytes), |bytes| {
            output.extend_from_slice(bytes);
            Ok(())
        })
        .unwrap();
        assert_eq!(output, bytes);
        assert!(caller_cancelled(&mut Cursor::new(Vec::<u8>::new())).unwrap());
    }

    #[test]
    fn relay_rejects_malformed_and_oversized_packets() {
        assert!(relay_packets(Cursor::new([1, 2]), |_| Ok(())).is_err());
        let mut oversized = vec![1];
        oversized.extend_from_slice(&((MAX_TEST_PACKET_BYTES + 1) as u32).to_le_bytes());
        assert!(relay_packets(Cursor::new(oversized), |_| Ok(())).is_err());
        let mut truncated = packet(b"body");
        truncated.pop();
        assert!(relay_packets(Cursor::new(truncated), |_| Ok(())).is_err());
    }

    #[test]
    fn relay_handles_large_frame_with_a_slow_pipe_reader() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let mut reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let expected = packet(&vec![9; 1024 * 1024]);
        let reader_thread = std::thread::spawn(move || {
            let mut received = Vec::new();
            let mut chunk = [0; 8192];
            loop {
                match reader.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        received.extend_from_slice(&chunk[..n]);
                        std::thread::sleep(Duration::from_millis(1));
                    }
                    Err(error) => panic!("pipe read failed: {error}"),
                }
            }
            received
        });
        let cancel = AtomicBool::new(false);
        relay_packets(Cursor::new(&expected), |bytes| {
            write_all_poll(
                &writer,
                bytes,
                Instant::now() + Duration::from_secs(2),
                &cancel,
            )
        })
        .unwrap();
        drop(writer);
        assert_eq!(reader_thread.join().unwrap(), expected);
    }

    #[test]
    fn relay_without_a_reader_is_deadline_bounded() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) }, 0);
        let _reader = unsafe { std::fs::File::from_raw_fd(fds[0]) };
        let writer = unsafe { std::fs::File::from_raw_fd(fds[1]) };
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let bytes = packet(&vec![7; 1024 * 1024]);
        let cancel = AtomicBool::new(false);
        let started = Instant::now();
        assert!(relay_packets(Cursor::new(bytes), |bytes| {
            write_all_poll(&writer, bytes, started + Duration::from_millis(40), &cancel)
        })
        .is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn relay_completion_obeys_deadline() {
        let (_sender, receiver) = mpsc::sync_channel::<Result<()>>(1);
        let started = Instant::now();
        assert!(wait_for_relay(&receiver, started + Duration::from_millis(20)).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
