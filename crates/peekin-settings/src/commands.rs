//! Bounded management subprocess I/O, isolated from the GTK event loop.
use peekin_core::i18n::{tr, tr_args};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const OUTPUT_LIMIT: usize = 8 * 1024 * 1024;
/// How long the polkit dialog may take before the helper reports `READY`.
/// The command's own deadline starts at that acknowledgement.
pub const AUTHORIZATION_LIMIT: Duration = Duration::from_secs(300);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Termination {
    Completed,
    Cancelled,
    TimedOut,
}

#[derive(Debug, PartialEq, Eq)]
pub struct CommandResult {
    pub exit_code: i32,
    pub output: String,
    pub termination: Termination,
}

#[derive(Clone, Debug)]
pub struct CommandControl {
    cancel: Arc<AtomicBool>,
    input_committed: Arc<AtomicBool>,
    write: bool,
    ready_protocol: bool,
}

impl CommandControl {
    pub fn new(write: bool) -> Self {
        Self {
            cancel: Arc::new(AtomicBool::new(false)),
            input_committed: Arc::new(AtomicBool::new(false)),
            write,
            ready_protocol: false,
        }
    }

    /// The privileged helper reports `READY` once polkit approved the call:
    /// no write request is sent before that, and the deadline counts from it.
    pub fn with_ready_handshake(write: bool) -> Self {
        let mut control = Self::new(write);
        control.ready_protocol = true;
        control
    }

    /// False once a write may have committed: the caller must wait and reconcile instead.
    pub fn cancel(&self) -> bool {
        if self.write && self.input_committed.load(Ordering::Acquire) {
            return false;
        }
        self.cancel.store(true, Ordering::Release);
        true
    }

    pub fn cancellation_safe(&self) -> bool {
        !self.write || !self.input_committed.load(Ordering::Acquire)
    }

    pub fn is_cancelling(&self) -> bool {
        self.cancel.load(Ordering::Acquire)
    }

    pub fn mark_input_committed(&self) {
        self.input_committed.store(true, Ordering::Release);
    }
}

fn nonblocking(fd: &impl AsRawFd) -> std::io::Result<()> {
    let fd = fd.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain(stream: &mut Option<impl Read>, bytes: &mut Vec<u8>) -> std::io::Result<()> {
    if let Some(pipe) = stream.as_mut() {
        let mut block = [0; 8192];
        // A continuously noisy child must not prevent deadline checks.
        for _ in 0..16 {
            match pipe.read(&mut block) {
                Ok(0) => {
                    *stream = None;
                    break;
                }
                Ok(n) if bytes.len() + n <= OUTPUT_LIMIT => bytes.extend_from_slice(&block[..n]),
                Ok(_) => return Err(std::io::Error::other("command output exceeded limit")),
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e),
            }
        }
    }
    Ok(())
}

fn execute_blocking(
    argv: &[String],
    env: &[(&str, &str)],
    input: &[u8],
    timeout: Duration,
    control: &CommandControl,
) -> CommandResult {
    let result = |exit_code, output, termination| CommandResult {
        exit_code,
        output,
        termination,
    };
    let Some(program) = argv.first() else {
        return result(-1, "No command specified".into(), Termination::Completed);
    };
    let mut command = Command::new(program);
    command
        .args(&argv[1..])
        .envs(env.iter().copied())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setpgid(0, 0) == 0 {
                Ok(())
            } else {
                Err(std::io::Error::last_os_error())
            }
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return result(
                -1,
                tr_args(
                    "Cannot run {program}: {error}",
                    &[("program", program), ("error", &error)],
                ),
                Termination::Completed,
            )
        }
    };
    let process_group = child.id() as libc::pid_t;
    // Before the handshake the clock covers the authorization dialog only.
    let mut deadline = Instant::now()
        + if control.ready_protocol {
            AUTHORIZATION_LIMIT
        } else {
            timeout
        };
    let mut stdout = child.stdout.take();
    let mut stderr = child.stderr.take();
    let command_result = (|| -> std::io::Result<CommandResult> {
        nonblocking(stdout.as_ref().unwrap())?;
        nonblocking(stderr.as_ref().unwrap())?;
        nonblocking(child.stdin.as_ref().unwrap())?;
        let (mut out, mut err, mut written) = (Vec::new(), Vec::new(), 0);
        let mut ready = !control.ready_protocol;
        let mut status = None;
        loop {
            if control.cancel.load(Ordering::Acquire)
                && (!control.write || !control.input_committed.load(Ordering::Acquire))
            {
                return Ok(result(
                    -1,
                    tr("Operation cancelled"),
                    Termination::Cancelled,
                ));
            }
            if Instant::now() >= deadline {
                return Ok(result(
                    124,
                    if ready {
                        tr("Operation timed out. Reload to check whether the change was saved.")
                    } else {
                        tr("Authorization timed out; nothing was changed.")
                    },
                    Termination::TimedOut,
                ));
            }
            if ready && written == input.len() {
                child.stdin.take();
                control.input_committed.store(true, Ordering::Release);
            }
            if let Some(stdin) = child.stdin.as_mut().filter(|_| ready) {
                match stdin.write(&input[written..]) {
                    Ok(n) => written += n,
                    Err(e)
                        if matches!(
                            e.kind(),
                            std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted
                        ) => {}
                    Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => {
                        child.stdin.take();
                    }
                    Err(e) => return Err(e),
                }
            }
            drain(&mut stdout, &mut out)?;
            drain(&mut stderr, &mut err)?;
            if !ready {
                if out.len() >= 6 {
                    if !out.starts_with(b"READY\n") {
                        return Err(std::io::Error::other("invalid privileged helper handshake"));
                    }
                    out.drain(..6);
                    ready = true;
                    deadline = Instant::now() + timeout;
                } else if !b"READY\n".starts_with(&out) {
                    return Err(std::io::Error::other("invalid privileged helper handshake"));
                }
            }
            if status.is_none() {
                status = child.try_wait()?;
            }
            if let Some(status) = status {
                if stdout.is_none() && stderr.is_none() {
                    let code = status.code().unwrap_or(-1);
                    if code == 0 && !ready {
                        return Err(std::io::Error::other(
                            "privileged helper did not acknowledge the request",
                        ));
                    }
                    if code != 0 {
                        out.extend_from_slice(&err);
                    }
                    return Ok(result(
                        code,
                        String::from_utf8_lossy(&out).into_owned(),
                        Termination::Completed,
                    ));
                }
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    })();
    // Closing stdin and killing the process group leaves no pipe-holding descendant behind.
    child.stdin.take();
    let abnormal = !matches!(
        &command_result,
        Ok(CommandResult {
            termination: Termination::Completed,
            ..
        })
    );
    if abnormal {
        unsafe { libc::kill(-process_group, libc::SIGTERM) };
        let grace = Instant::now() + Duration::from_millis(200);
        while Instant::now() < grace && matches!(child.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(5));
        }
        unsafe { libc::kill(-process_group, libc::SIGKILL) };
        let reap_deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < reap_deadline && matches!(child.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(10));
        }
    }
    // A driver stuck in uninterruptible sleep must not wedge the GTK worker.
    let _ = child.try_wait();
    command_result.unwrap_or_else(|e| result(-1, e.to_string(), Termination::Completed))
}

pub async fn execute(
    argv: Vec<String>,
    env: Vec<(&'static str, &'static str)>,
    input: String,
    timeout: Duration,
    control: CommandControl,
) -> CommandResult {
    let (tx, rx) = async_channel::bounded(1);
    std::thread::spawn(move || {
        let result = execute_blocking(&argv, &env, input.as_bytes(), timeout, &control);
        let _ = tx.send_blocking(result);
    });
    rx.recv().await.unwrap_or_else(|_| CommandResult {
        exit_code: -1,
        output: tr("Command worker stopped unexpectedly"),
        termination: Termination::Completed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn run(script: &str, input: &[u8], timeout: Duration) -> (i32, String) {
        let result = execute_blocking(
            &["/bin/sh".into(), "-c".into(), script.into()],
            &[],
            input,
            timeout,
            &CommandControl::new(!input.is_empty()),
        );
        (result.exit_code, result.output)
    }
    #[test]
    fn large_input_does_not_deadlock_and_stderr_does_not_corrupt_json() {
        let input = vec![b'x'; 256 * 1024];
        let result = run("cat; printf warning >&2", &input, Duration::from_secs(3));
        assert_eq!(result, (0, String::from_utf8(input).unwrap()));
    }
    #[test]
    fn hung_and_noisy_commands_are_bounded() {
        let start = Instant::now();
        assert_eq!(run("exec sleep 30", &[], Duration::from_millis(100)).0, 124);
        assert!(start.elapsed() < Duration::from_secs(2));
        let (code, text) = run("exec yes flood", &[], Duration::from_secs(3));
        assert_ne!(code, 0);
        assert!(text.contains("limit"));
    }

    #[test]
    fn read_only_command_can_be_cancelled_and_process_tree_is_reaped() {
        let control = CommandControl::new(false);
        control.cancel.store(true, Ordering::Release);
        let started = Instant::now();
        let result = execute_blocking(
            &["/bin/sh".into(), "-c".into(), "sleep 30 & wait".into()],
            &[],
            &[],
            Duration::from_secs(30),
            &control,
        );
        assert_eq!(result.termination, Termination::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn write_cancel_is_rejected_after_commit_boundary() {
        let control = CommandControl::new(true);
        let worker_control = control.clone();
        let worker = std::thread::spawn(move || {
            execute_blocking(
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "cat >/dev/null; sleep .1; printf saved".into(),
                ],
                &[],
                b"request",
                Duration::from_secs(2),
                &worker_control,
            )
        });
        let deadline = Instant::now() + Duration::from_secs(1);
        while control.cancellation_safe() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(!control.cancel());
        let result = worker.join().unwrap();
        assert_eq!(result.termination, Termination::Completed);
        assert_eq!((result.exit_code, result.output.as_str()), (0, "saved"));
    }

    #[test]
    fn privileged_request_waits_for_ready_then_commits_exactly_once() {
        let control = CommandControl::with_ready_handshake(true);
        let result = execute_blocking(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf 'READY\\n'; cat >/dev/null; printf saved".into(),
            ],
            &[],
            b"request",
            Duration::from_secs(2),
            &control,
        );
        assert_eq!(result.termination, Termination::Completed);
        assert_eq!((result.exit_code, result.output.as_str()), (0, "saved"));
        assert!(!control.cancel());
    }

    #[test]
    fn privileged_request_can_be_cancelled_before_authorization_handoff() {
        let control = CommandControl::with_ready_handshake(true);
        let worker_control = control.clone();
        let started = Instant::now();
        let worker = std::thread::spawn(move || {
            execute_blocking(
                &[
                    "/bin/sh".into(),
                    "-c".into(),
                    "sleep 30; printf 'READY\\n'; cat >/dev/null".into(),
                ],
                &[],
                b"request",
                Duration::from_secs(30),
                &worker_control,
            )
        });
        std::thread::sleep(Duration::from_millis(50));
        assert!(control.cancel());
        assert_eq!(worker.join().unwrap().termination, Termination::Cancelled);
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn missing_ready_acknowledgement_never_sends_write_payload() {
        let result = execute_blocking(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "printf invalid; exit 0".into(),
            ],
            &[],
            b"request",
            Duration::from_secs(2),
            &CommandControl::with_ready_handshake(true),
        );
        assert_ne!(result.exit_code, 0);
        assert!(result.output.contains("handshake"));
    }

    /// The deadline counts from `READY`: a slow authorization dialog does not
    /// eat into the command's time, and a read can still be cancelled after it.
    #[test]
    fn the_deadline_starts_at_the_ready_acknowledgement() {
        let started = Instant::now();
        let result = execute_blocking(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "sleep 0.3; printf 'READY\\n'; sleep 0.3; printf done".into(),
            ],
            &[],
            b"",
            Duration::from_millis(450),
            &CommandControl::with_ready_handshake(false),
        );
        assert_eq!(
            (result.exit_code, result.output.as_str()),
            (0, "done"),
            "{result:?}"
        );
        assert!(started.elapsed() >= Duration::from_millis(600));
        let control = CommandControl::with_ready_handshake(false);
        assert!(control.cancel(), "a read stays cancellable");
    }
}
