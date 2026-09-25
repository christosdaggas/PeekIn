//! Runs `peekin-compare` with a hard deadline and no threads: PAM may unload the module as soon as it returns.

use crate::status::ChildEnd;
use peekin_core::compare::ChallengeMode;
use peekin_core::lowlight::LOW_LIGHT_SIGNAL;
use peekin_core::process::{worker_cpu_limit, WORKER_ADDRESS_SPACE, WORKER_ENV};
use std::io::{self, Read};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

const POLL: Duration = Duration::from_millis(20);
const KILL_GRACE: Duration = Duration::from_secs(2);
const STDERR_LIMIT: usize = 8 * 1024;
const STDOUT_LIMIT: usize = 256;
/// Reads per pipe per poll: at most 16 × 4 KiB = 64 KiB, about one pipe
/// buffer. A worker flooding its output can then never keep the loop from
/// reaching its deadline check; what is not read yet stays in the pipe (the
/// worker blocks writing) until the next poll, 20 ms later. Past the limits
/// the output is read and dropped, so the worker is never stalled for good.
const DRAIN_BUDGET: usize = 16;

#[derive(Debug, Clone, Copy)]
pub struct WorkerIdentity<'a> {
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    pub groups: &'a [libc::gid_t],
    pub user: &'a str,
}

#[derive(Debug)]
pub enum RunEnd {
    Exited(ChildEnd),
    /// `reaped` is false if even SIGKILL did not end it (e.g. stuck in the camera driver).
    TimedOut {
        reaped: bool,
    },
    SpawnFailed(io::Error),
    WaitFailed(io::Error),
}

#[derive(Debug)]
pub struct CompareRun {
    pub end: RunEnd,
    pub stderr: String,
    pub stdout: String,
}

pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGKILL => "SIGKILL",
        libc::SIGTERM => "SIGTERM",
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGABRT => "SIGABRT",
        libc::SIGBUS => "SIGBUS",
        libc::SIGILL => "SIGILL",
        libc::SIGXCPU => "SIGXCPU (CPU time limit)",
        libc::SIGFPE => "SIGFPE",
        libc::SIGINT => "SIGINT",
        _ => "unknown signal",
    }
}

fn child_end(status: ExitStatus) -> ChildEnd {
    match (status.code(), status.signal()) {
        (Some(code), _) => ChildEnd::Exited((code & 0xff) as u8),
        (None, Some(sig)) => ChildEnd::Signaled {
            signal: sig,
            name: signal_name(sig),
        },
        (None, None) => ChildEnd::Exited(u8::MAX),
    }
}

struct Drain<R> {
    pipe: Option<R>,
    buf: Vec<u8>,
    limit: usize,
}

impl<R: Read + AsRawFd> Drain<R> {
    fn new(pipe: Option<R>, limit: usize) -> Self {
        if let Some(p) = &pipe {
            // SAFETY: fcntl on a pipe fd we own.
            unsafe {
                let fd = p.as_raw_fd();
                let flags = libc::fcntl(fd, libc::F_GETFL);
                libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
            }
        }
        Self {
            pipe,
            buf: Vec::new(),
            limit,
        }
    }

    fn drain(&mut self) {
        let Some(pipe) = self.pipe.as_mut() else {
            return;
        };
        let mut chunk = [0u8; 4096];
        for _ in 0..DRAIN_BUDGET {
            match pipe.read(&mut chunk) {
                Ok(0) => {
                    self.pipe = None;
                    return;
                }
                Ok(n) => {
                    let room = self.limit.saturating_sub(self.buf.len());
                    self.buf.extend_from_slice(&chunk[..n.min(room)]);
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return,
            }
        }
    }

    fn text(self) -> String {
        String::from_utf8_lossy(&self.buf).into_owned()
    }
}

/// Worker output: diagnostics on stderr, low-light signal on stdout (reported once).
struct Output<'a> {
    stderr: Drain<std::process::ChildStderr>,
    stdout: Drain<std::process::ChildStdout>,
    on_low_light: Option<&'a mut dyn FnMut()>,
}

impl Output<'_> {
    fn drain(&mut self) {
        self.stderr.drain();
        self.stdout.drain();
        let signalled = self
            .stdout
            .buf
            .split(|&b| b == b'\n')
            .any(|line| line == LOW_LIGHT_SIGNAL.as_bytes());
        if signalled {
            if let Some(notify) = self.on_low_light.take() {
                notify();
            }
        }
    }
}

fn wait_until(
    child: &mut Child,
    output: &mut Output<'_>,
    deadline: Instant,
) -> io::Result<Option<ExitStatus>> {
    loop {
        output.drain();
        if let Some(status) = child.try_wait()? {
            output.drain();
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        std::thread::sleep(POLL);
    }
}

/// SIGKILL to the worker's process group. Only called before the worker is
/// reaped: until then its PID, which is the group ID, cannot be reused.
fn kill_group(child: &mut Child) {
    let group = child.id() as libc::pid_t;
    // SAFETY: kill has no memory preconditions; the group is the worker's own.
    if group > 0 && unsafe { libc::kill(-group, libc::SIGKILL) } != 0 {
        // The group is gone already, or never formed: end the worker itself.
        let _ = child.kill();
    }
}

/// Runs the worker with a minimal fixed environment and no stdin, killing it
/// and everything it started at `deadline`.
pub fn run_compare(
    compare: &Path,
    config_dir: &Path,
    data_dir: &Path,
    identity: WorkerIdentity<'_>,
    challenge: ChallengeMode,
    deadline: Duration,
    on_low_light: &mut dyn FnMut(),
) -> CompareRun {
    let mut command = Command::new(compare);
    command
        .arg("--config-dir")
        .arg(config_dir)
        .arg("--data-dir")
        .arg(data_dir)
        .arg("--challenge")
        .arg(challenge.arg())
        .arg("--")
        .arg(identity.user)
        .env_clear()
        .envs(WORKER_ENV.iter().copied())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let parent_euid = unsafe { libc::geteuid() };
    let parent_pid = unsafe { libc::getpid() };
    let groups = identity.groups.to_vec();
    let (cpu_soft, cpu_hard) = worker_cpu_limit(deadline);
    unsafe {
        command.pre_exec(move || {
            // Its own process group, so the deadline ends everything it
            // started, as the settings helper does for its test worker.
            if libc::setpgid(0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            if parent_euid == 0 {
                if libc::setgroups(groups.len(), groups.as_ptr()) != 0
                    || libc::setgid(identity.gid) != 0
                    || libc::setuid(identity.uid) != 0
                {
                    return Err(io::Error::last_os_error());
                }
            } else if libc::geteuid() != identity.uid || libc::getegid() != identity.gid {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "cannot drop to target account",
                ));
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(io::Error::from_raw_os_error(libc::ESRCH));
            }
            if libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            for (resource, soft, hard) in [
                (libc::RLIMIT_CORE, 0, 0),
                (libc::RLIMIT_NOFILE, 64, 64),
                (libc::RLIMIT_AS, WORKER_ADDRESS_SPACE, WORKER_ADDRESS_SPACE),
                (libc::RLIMIT_CPU, cpu_soft, cpu_hard),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: soft,
                    rlim_max: hard,
                };
                if libc::setrlimit(resource, &limit) != 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let spawned = command.spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => {
            return CompareRun {
                end: RunEnd::SpawnFailed(e),
                stderr: String::new(),
                stdout: String::new(),
            }
        }
    };
    let mut output = Output {
        stderr: Drain::new(child.stderr.take(), STDERR_LIMIT),
        stdout: Drain::new(child.stdout.take(), STDOUT_LIMIT),
        on_low_light: Some(on_low_light),
    };
    let started = Instant::now();

    let end = match wait_until(&mut child, &mut output, started + deadline) {
        Ok(Some(status)) => RunEnd::Exited(child_end(status)),
        Ok(None) => {
            kill_group(&mut child);
            match wait_until(&mut child, &mut output, Instant::now() + KILL_GRACE) {
                Ok(Some(_)) => RunEnd::TimedOut { reaped: true },
                _ => RunEnd::TimedOut { reaped: false },
            }
        }
        Err(e) => RunEnd::WaitFailed(e),
    };
    CompareRun {
        end,
        stderr: output.stderr.text(),
        stdout: output.stdout.text(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Written once before any test spawns: writing an executable while another thread forks gives ETXTBSY.
    fn script(name: &str) -> std::path::PathBuf {
        static DIR: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();
        let dir = DIR.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("peekin-run-{}", std::process::id()));
            std::fs::create_dir_all(&dir).unwrap();
            for (name, body) in [
                (
                    "args.sh",
                    "echo \"$@\" >&2; echo \"PATH=$PATH HOME=${HOME:-unset} OCL=$OPENCV_OPENCL_RUNTIME ARENAS=$MALLOC_ARENA_MAX\" >&2; exit 11",
                ),
                ("hang.sh", "exec sleep 30"),
                (
                    "noisy.sh",
                    "head -c 200000 /dev/zero | tr '\\0' x >&2; exit 0",
                ),
                ("segv.sh", "kill -SEGV $$"),
                (
                    "lowlight.sh",
                    "echo low-light; echo low-light; echo not-low-light; exit 0",
                ),
                ("quiet.sh", "echo low-lights; echo x-low-light; exit 0"),
                // Leaves a grandchild behind, as a stuck camera helper might.
                (
                    "family.sh",
                    "sleep 30 & echo $! > \"$0.pid\"; exec sleep 30",
                ),
            ] {
                let p = dir.join(name);
                std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
                std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            }
            dir
        });
        dir.join(name)
    }

    fn run(p: &Path, deadline_ms: u64) -> CompareRun {
        run_counting(p, deadline_ms, &mut 0)
    }

    fn run_counting(p: &Path, deadline_ms: u64, low_light: &mut u32) -> CompareRun {
        let username = username();
        let id = WorkerIdentity {
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            groups: &[],
            user: &username,
        };
        run_compare(
            p,
            Path::new("/cfg"),
            Path::new("/data"),
            id,
            ChallengeMode::parse("left,right,left").expect("test challenge"),
            Duration::from_millis(deadline_ms),
            &mut || *low_light += 1,
        )
    }

    #[test]
    fn low_light_signal_is_reported_once_and_only_as_a_whole_line() {
        let mut count = 0;
        let r = run_counting(&script("lowlight.sh"), 5_000, &mut count);
        assert!(
            matches!(r.end, RunEnd::Exited(ChildEnd::Exited(0))),
            "{r:?}"
        );
        assert_eq!(count, 1);
        let mut count = 0;
        run_counting(&script("quiet.sh"), 5_000, &mut count);
        assert_eq!(count, 0);
    }

    fn username() -> String {
        std::env::var("USER").unwrap_or_else(|_| "nobody".into())
    }

    #[test]
    fn passes_arguments_and_collects_exit_code_and_stderr() {
        let p = script("args.sh");
        let r = run(&p, 5000);
        assert!(
            matches!(r.end, RunEnd::Exited(ChildEnd::Exited(11))),
            "{r:?}"
        );
        assert!(
            r.stderr.contains(&format!(
                "--config-dir /cfg --data-dir /data --challenge left,right,left -- {}",
                username()
            )),
            "{}",
            r.stderr
        );
        assert!(
            r.stderr
                .contains("PATH=/usr/sbin:/usr/bin:/sbin:/bin HOME=unset OCL=disabled ARENAS=2"),
            "{}",
            r.stderr
        );
    }

    #[test]
    fn hung_child_is_killed_at_the_deadline() {
        let p = script("hang.sh");
        let started = Instant::now();
        let r = run(&p, 300);
        assert!(matches!(r.end, RunEnd::TimedOut { reaped: true }), "{r:?}");
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn the_whole_process_group_is_killed_at_the_deadline() {
        let p = script("family.sh");
        let r = run(&p, 300);
        assert!(matches!(r.end, RunEnd::TimedOut { reaped: true }), "{r:?}");
        let pid_file = p.with_extension("sh.pid");
        let pid: i32 = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        // Gone, or a zombie waiting for its new parent to reap it.
        let alive = || {
            std::fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
                stat.rsplit_once(')')
                    .is_some_and(|(_, rest)| !rest.trim_start().starts_with('Z'))
            })
        };
        let until = Instant::now() + Duration::from_secs(2);
        while alive() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
        let survived = alive();
        if survived {
            unsafe { libc::kill(pid, libc::SIGKILL) };
        }
        assert!(!survived, "the worker's child outlived the deadline");
    }

    #[test]
    fn huge_stderr_does_not_block_and_is_capped() {
        let p = script("noisy.sh");
        let r = run(&p, 5000);
        assert!(
            matches!(r.end, RunEnd::Exited(ChildEnd::Exited(0))),
            "{r:?}"
        );
        assert_eq!(r.stderr.len(), STDERR_LIMIT);
    }

    #[test]
    fn signal_death_is_reported() {
        let p = script("segv.sh");
        let r = run(&p, 5000);
        assert!(
            matches!(
                r.end,
                RunEnd::Exited(ChildEnd::Signaled {
                    signal: libc::SIGSEGV,
                    name: "SIGSEGV"
                })
            ),
            "{r:?}"
        );
    }

    #[test]
    fn missing_binary_is_a_spawn_failure() {
        let r = run(Path::new("/nonexistent/peekin-compare"), 1000);
        assert!(matches!(r.end, RunEnd::SpawnFailed(_)));
    }
}
