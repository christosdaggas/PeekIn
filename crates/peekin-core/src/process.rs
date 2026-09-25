//! Runtime process hardening that must be applied after `exec`.

use std::io;

/// Environment for the workers. It keeps BLAS/OpenMP from starting a thread
/// (and glibc a 64 MiB arena) per CPU, which exceeds [`WORKER_ADDRESS_SPACE`]
/// on many-core machines.
pub const WORKER_ENV: &[(&str, &str)] = &[
    ("PATH", "/usr/sbin:/usr/bin:/sbin:/bin"),
    ("OPENCV_OPENCL_RUNTIME", "disabled"),
    ("OPENCV_OPENCL_DEVICE", "disabled"),
    ("OPENBLAS_NUM_THREADS", "1"),
    ("OMP_NUM_THREADS", "1"),
    ("MALLOC_ARENA_MAX", "2"),
];

/// `RLIMIT_AS` for workers; they measured about 0.4 GB.
pub const WORKER_ADDRESS_SPACE: u64 = 4 * 1024 * 1024 * 1024;

pub const MAX_WORKER_THREADS: usize = 2;

/// `RLIMIT_CPU` for a worker with wall-clock budget `wall`. A scan uses more
/// than one CPU second per second, so this only stops a runaway process.
pub fn worker_cpu_limit(wall: std::time::Duration) -> (u64, u64) {
    let soft = wall
        .as_secs()
        .saturating_add(1)
        .saturating_mul(MAX_WORKER_THREADS as u64 + 1)
        .saturating_add(2);
    (soft, soft.saturating_add(1))
}

/// Disable ptrace/core-dump access and verify that the kernel accepted it.
pub fn disable_dumpability() -> io::Result<()> {
    if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) } != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "process remains dumpable",
        ));
    }
    Ok(())
}

/// Arm parent-death termination again; `exec` may reset it.
pub fn arm_parent_death() -> io::Result<()> {
    let parent = unsafe { libc::getppid() };
    if parent <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "worker parent is already gone",
        ));
    }
    if unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { libc::getppid() } != parent {
        return Err(io::Error::from_raw_os_error(libc::ESRCH));
    }
    Ok(())
}

pub fn validate_service_identity(
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: &[libc::gid_t],
) -> io::Result<()> {
    let unique: std::collections::HashSet<_> = groups.iter().copied().collect();
    if uid == 0
        || gid == 0
        || groups.is_empty()
        || groups.len() > 256
        || !groups.contains(&gid)
        || groups.contains(&0)
        || unique.len() != groups.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid dedicated service identity",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runtime_guard_is_verified_in_a_subprocess() {
        const CHILD: &str = "PEEKIN_DUMPABILITY_CHILD";
        if std::env::var_os(CHILD).is_some() {
            disable_dumpability().unwrap();
            assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, 0);
            return;
        }

        let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE) };
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "process::tests::runtime_guard_is_verified_in_a_subprocess",
            ])
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
        assert_eq!(unsafe { libc::prctl(libc::PR_GET_DUMPABLE) }, before);
    }

    #[test]
    fn cpu_limit_scales_with_worker_threads() {
        let (soft, hard) = worker_cpu_limit(std::time::Duration::from_secs(15));
        assert!(soft >= 15 * (MAX_WORKER_THREADS as u64 + 1));
        assert_eq!(hard, soft + 1);
        assert!(worker_cpu_limit(std::time::Duration::ZERO).0 > 0);
    }

    #[test]
    fn service_identity_rejects_root_and_malformed_groups() {
        assert!(validate_service_identity(100, 200, &[200, 201]).is_ok());
        assert!(validate_service_identity(0, 200, &[200]).is_err());
        assert!(validate_service_identity(100, 0, &[0]).is_err());
        assert!(validate_service_identity(100, 200, &[]).is_err());
        assert!(validate_service_identity(100, 200, &[201]).is_err());
        assert!(validate_service_identity(100, 200, &[200, 200]).is_err());
    }
}
