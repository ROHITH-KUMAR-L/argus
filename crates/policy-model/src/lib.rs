//! Typed task policy, permission set and seccomp profile catalog.
//!
//! These are plain data structures. Validation and canonicalization live in
//! `policy-validator`; subset/ratchet logic lives in `privilege-ratchet`.

pub mod action;
pub mod permissions;
pub mod policy;
pub mod profiles;
pub mod syscalls_x86_64;

pub use action::*;
pub use permissions::{Access, PermissionSet};
pub use policy::*;
pub use profiles::{profile, ProfileMode, SyscallProfile, PROFILES};

/// Look up an x86_64 syscall number by name.
pub fn syscall_nr(name: &str) -> Option<u32> {
    syscalls_x86_64::SYSCALLS_X86_64
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, nr)| *nr)
}
