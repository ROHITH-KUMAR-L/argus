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
}

/// Syscalls no supported workload needs: kernel modules, mounts, namespaces,
/// tracing/introspection of other processes, BPF, keyrings, clock and reboot.
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
    "pivot_root",
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
        },
        SyscallProfile {
            name: "c-build-v1",
            mode: ProfileMode::Denylist,
            syscalls: HIGH_RISK,
            description: "gcc/cc/make compile, link and run; denies high-risk families",
        },
        SyscallProfile {
            name: "minimal-run-v1",
            mode: ProfileMode::Denylist,
            syscalls: MINIMAL_RUN_V1.as_slice(),
            description: "High-risk families plus all socket creation/connection",
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
    fn minimal_is_stricter_than_python() {
        let py = profile("python-build-v1").unwrap().denied();
        let min = profile("minimal-run-v1").unwrap().denied();
        assert!(min.is_superset(&py));
        assert!(min.len() > py.len());
    }
}
