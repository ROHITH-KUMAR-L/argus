//! Normalized permission set used for ratchet comparisons.
//!
//! Every class is represented so that "more permission" is a superset:
//! filesystem grants (path -> access bits), tools, executables, shell, the set
//! of *allowed* syscalls (complement of denied), TCP ports, and numeric ceilings.

use crate::policy::Limits;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Filesystem access bits granted to a hierarchy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Access(pub u8);

impl Access {
    pub const READ: u8 = 0b001;
    pub const WRITE: u8 = 0b010;
    pub const EXECUTE: u8 = 0b100;
    pub const READ_ONLY: Access = Access(Self::READ | Self::EXECUTE);
    pub const READ_WRITE: Access = Access(Self::READ | Self::WRITE | Self::EXECUTE);

    pub fn contains(self, other: Access) -> bool {
        self.0 & other.0 == other.0
    }
    pub fn union(self, other: Access) -> Access {
        Access(self.0 | other.0)
    }
    pub fn names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if self.0 & Self::READ != 0 {
            v.push("read");
        }
        if self.0 & Self::WRITE != 0 {
            v.push("write");
        }
        if self.0 & Self::EXECUTE != 0 {
            v.push("execute");
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PermissionSet {
    /// Normalized absolute path -> access granted to that hierarchy. No entry is
    /// redundant (covered by an ancestor with a superset of access).
    pub fs: BTreeMap<String, Access>,
    pub tools: BTreeSet<String>,
    pub executables: BTreeSet<String>,
    pub shell: bool,
    /// Syscall names that are denied. More denied = narrower.
    pub denied_syscalls: BTreeSet<String>,
    /// `None` = no network. `Some(ports)` = Landlock TCP grants.
    pub tcp_ports: Option<BTreeSet<u16>>,
    pub limits: Limits,
}
