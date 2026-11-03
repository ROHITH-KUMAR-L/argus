//! Versioned seccomp profile catalog.
//!
//! A profile's *content* never changes once published: a stricter or looser
//! variant gets a new name (`-v2`). The ratchet orders profiles by the set of
//! syscalls they deny over the x86_64 syscall universe.

use std::collections::BTreeSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProfileMode {
    /// Default allow; listed syscalls fail with EPERM. Compatibility / defense in depth.
    Denylist,
    /// Default deny; only listed syscalls are allowed.
    Allowlist,
}

#[derive(Debug, Clone, Copy)]
pub struct SyscallProfile {
    pub name: &'static str,
    pub mode: ProfileMode,
    pub syscalls: &'static [&'static str],
    pub description: &'static str,
    /// Executables the profile was validated for. `None` = any catalog
    /// executable. A policy using other executables is rejected (SEC-018).
    pub supported_executables: Option<&'static [&'static str]>,
}

/// Syscalls no supported workload needs: kernel modules, mounts, namespaces,
/// tracing/introspection of other processes, BPF, keyrings, clock and reboot,
/// and io_uring (whose submitted operations are not individually filtered by
/// seccomp). Every profile additionally gets two fixed rules (see
/// `linux-confinement::seccomp`): `clone3` -> ENOSYS (its flags cannot be
/// inspected), and `clone` with any `CLONE_NEW*` flag -> EPERM.
pub const HIGH_RISK: &[&str] = &[
    "acct",
    "add_key",
    "adjtimex",
    "bpf",
    "chroot",
    "clock_adjtime",
    "clock_settime",
    "create_module",
    "delete_module",
    "finit_module",
    "fsconfig",
    "fsmount",
    "fsopen",
    "fspick",
    "get_kernel_syms",
    "init_module",
    "ioperm",
    "io_uring_enter",
    "io_uring_register",
    "io_uring_setup",
    "iopl",
    "kexec_file_load",
    "kexec_load",
    "keyctl",
    "lookup_dcookie",
    "mount",
    "mount_setattr",
    "move_mount",
    "name_to_handle_at",
    "nfsservctl",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pidfd_getfd",
    "pivot_root",
    "process_madvise",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "query_module",
    "quotactl",
    "reboot",
    "request_key",
    "setns",
    "settimeofday",
    "swapoff",
    "swapon",
    "syslog",
    "umount2",
    "unshare",
    "uselib",
    "userfaultfd",
    "vhangup",
];

const MINIMAL_EXTRA: &[&str] = &[
    "accept",
    "accept4",
    "bind",
    "connect",
    "listen",
    "socket",
    "socketpair",
];

/// Default-deny allowlist for Python workloads, derived from an `strace` of
/// interpreter startup, pytest (tmp_path, subprocess, threads), file I/O and the
/// worker's own file-op child (`docs/confinement.md`), plus a small documented
/// margin of equivalent `*at` variants, timers, waits and signal returns.
/// High-risk families are excluded by construction (a unit test checks it).
pub const PYTHON_STRICT_V1: &[&str] = &[
    "access",
    "arch_prctl",
    "brk",
    "chdir",
    "chmod",
    "clock_getres",
    "clock_gettime",
    "clock_nanosleep",
    "clone",
    "clone3",
    "close",
    "close_range",
    "connect",
    "copy_file_range",
    "dup",
    "dup2",
    "dup3",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "epoll_wait",
    "eventfd2",
    "execve",
    "exit",
    "exit_group",
    "faccessat",
    "faccessat2",
    "fadvise64",
    "fchdir",
    "fchmod",
    "fchmodat",
    "fcntl",
    "fdatasync",
    "fgetxattr",
    "flock",
    "fstat",
    "fstatfs",
    "fsync",
    "ftruncate",
    "futex",
    "getcwd",
    "getdents64",
    "getegid",
    "geteuid",
    "getgid",
    "getgroups",
    "getpgid",
    "getpgrp",
    "getpid",
    "getppid",
    "getrandom",
    "getresgid",
    "getresuid",
    "getrusage",
    "getsid",
    "gettid",
    "gettimeofday",
    "getuid",
    "getxattr",
    "ioctl",
    "kill",
    "lgetxattr",
    "link",
    "linkat",
    "lseek",
    "madvise",
    "membarrier",
    "mkdir",
    "mkdirat",
    "mmap",
    "mprotect",
    "mremap",
    "msync",
    "munmap",
    "nanosleep",
    "newfstatat",
    "openat",
    "pipe",
    "pipe2",
    "poll",
    "ppoll",
    "pread64",
    "prlimit64",
    "pselect6",
    "pwrite64",
    "read",
    "readlink",
    "readlinkat",
    "readv",
    "rename",
    "renameat",
    "renameat2",
    "restart_syscall",
    "rmdir",
    "rseq",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sched_getaffinity",
    "sched_setaffinity",
    "sched_yield",
    "select",
    "sendfile",
    "set_robust_list",
    "set_tid_address",
    "setfsgid",
    "setfsuid",
    "setpgid",
    "sigaltstack",
    "socket",
    "statfs",
    "statx",
    "symlink",
    "symlinkat",
    "sysinfo",
    "tgkill",
    "times",
    "truncate",
    "uname",
    "unlink",
    "unlinkat",
    "utimensat",
    "vfork",
    "wait4",
    "waitid",
    "write",
    "writev",
];

static MINIMAL_RUN_V1: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
    let mut v: Vec<&'static str> = HIGH_RISK.iter().chain(MINIMAL_EXTRA).copied().collect();
    v.sort_unstable();
    v
});

/// The profile catalog. Order is irrelevant; names are unique.
pub static PROFILES: std::sync::LazyLock<Vec<SyscallProfile>> = std::sync::LazyLock::new(|| {
    vec![
        SyscallProfile {
            name: "python-build-v1",
            mode: ProfileMode::Denylist,
            syscalls: HIGH_RISK,
            description:
                "Python interpreter, pip-free test runs and subprocesses; denies high-risk families",
            supported_executables: None,
        },
        SyscallProfile {
            name: "c-build-v1",
            mode: ProfileMode::Denylist,
            syscalls: HIGH_RISK,
            description: "gcc/cc/make compile, link and run; denies high-risk families",
            supported_executables: None,
        },
        SyscallProfile {
            name: "minimal-run-v1",
            mode: ProfileMode::Denylist,
            syscalls: MINIMAL_RUN_V1.as_slice(),
            description: "High-risk families plus all socket creation/connection",
            supported_executables: None,
        },
        SyscallProfile {
            name: "python-strict-v1",
            mode: ProfileMode::Allowlist,
            syscalls: PYTHON_STRICT_V1,
            description: "Default-deny allowlist for the Python interpreter and its subprocesses",
            supported_executables: Some(&["/usr/local/bin/python3"]),
        },
    ]
});

pub fn profile(name: &str) -> Option<&'static SyscallProfile> {
    PROFILES.iter().find(|p| p.name == name)
}

impl SyscallProfile {
    /// Syscall names this profile denies, over the x86_64 universe.
    pub fn denied(&self) -> BTreeSet<&'static str> {
        let listed: BTreeSet<&'static str> = self.syscalls.iter().copied().collect();
        match self.mode {
            ProfileMode::Denylist => listed,
            ProfileMode::Allowlist => crate::syscalls_x86_64::SYSCALLS_X86_64
                .iter()
                .map(|(n, _)| *n)
                .filter(|n| !listed.contains(n))
                .collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_profile_syscall_is_known() {
        for p in PROFILES.iter() {
            for s in p.syscalls {
                assert!(
                    crate::syscall_nr(s).is_some(),
                    "{} lists unknown syscall {s}",
                    p.name
                );
            }
        }
    }

    #[test]
    fn profile_names_unique() {
        let names: BTreeSet<_> = PROFILES.iter().map(|p| p.name).collect();
        assert_eq!(names.len(), PROFILES.len());
    }

    #[test]
    fn strict_allowlist_excludes_high_risk_and_is_strictest() {
        let strict = profile("python-strict-v1").unwrap();
        for s in HIGH_RISK {
            assert!(!strict.syscalls.contains(s), "{s} must not be allowed");
        }
        let d = strict.denied();
        assert!(d.is_superset(&profile("python-build-v1").unwrap().denied()));
    }

    #[test]
    fn minimal_is_stricter_than_python() {
        let py = profile("python-build-v1").unwrap().denied();
        let min = profile("minimal-run-v1").unwrap().denied();
        assert!(min.is_superset(&py));
        assert!(min.len() > py.len());
    }
}
