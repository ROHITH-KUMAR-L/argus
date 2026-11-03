//! `new ⊆ old` over normalized permission sets, with an explicit delta.
//!
//! Semantics per class (a transition is accepted only if *every* class holds):
//!
//! * **Filesystem**: Landlock rights accumulate over a hierarchy, so the
//!   effective access at a path is the union of every grant on that path or an
//!   ancestor. Each new grant `(p, a)` must satisfy `a ⊆ coverage_old(p)`. All
//!   descendants of `p` have old coverage `⊇ coverage_old(p)`, so checking `p`
//!   suffices.
//! * **Tools / executables**: set inclusion.
//! * **Shell**: `allow` may become `deny`, never the reverse.
//! * **Syscalls**: the new denied set must be a superset of the old one.
//! * **Network**: `none ⊂ tcp_ports(S)`, and `tcp_ports(T) ⊆ tcp_ports(S)` iff `T ⊆ S`.
//! * **Limits**: every ceiling must be `<=` the old ceiling.

use policy_model::{Access, PermissionSet};
use policy_validator::paths::is_within;
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DeltaItem {
    FsAccessAdded {
        path: String,
        requested: Vec<&'static str>,
        previously: Vec<&'static str>,
    },
    ToolAdded {
        tool: String,
    },
    ExecutableAdded {
        executable: String,
    },
    ShellEnabled,
    SyscallUndenied {
        syscall: String,
    },
    NetworkEnabled,
    PortAdded {
        port: u16,
    },
    LimitIncreased {
        limit: &'static str,
        from: u64,
        to: u64,
    },
}

/// Effective filesystem access at `path` under `fs`.
pub fn coverage(fs: &BTreeMap<String, Access>, path: &str) -> Access {
    fs.iter()
        .filter(|(g, _)| is_within(path, g))
        .fold(Access(0), |acc, (_, a)| acc.union(*a))
}

/// Every permission `new` holds that `old` does not. Empty means `new ⊆ old`.
pub fn expansion_delta(new: &PermissionSet, old: &PermissionSet) -> Vec<DeltaItem> {
    let mut d = Vec::new();

    for (path, access) in &new.fs {
        let have = coverage(&old.fs, path);
        if !have.contains(*access) {
            d.push(DeltaItem::FsAccessAdded {
                path: path.clone(),
                requested: access.names(),
                previously: have.names(),
            });
        }
    }
    for t in new.tools.difference(&old.tools) {
        d.push(DeltaItem::ToolAdded { tool: t.clone() });
    }
    for x in new.executables.difference(&old.executables) {
        d.push(DeltaItem::ExecutableAdded {
            executable: x.clone(),
        });
    }
    if new.shell && !old.shell {
        d.push(DeltaItem::ShellEnabled);
    }
    for s in old.denied_syscalls.difference(&new.denied_syscalls) {
        d.push(DeltaItem::SyscallUndenied { syscall: s.clone() });
    }
    match (&old.tcp_ports, &new.tcp_ports) {
        (_, None) => {}
        (None, Some(_)) => d.push(DeltaItem::NetworkEnabled),
        (Some(o), Some(n)) => {
            for p in n.difference(o) {
                d.push(DeltaItem::PortAdded { port: *p });
            }
        }
    }
    for ((name, n), (_, o)) in new.limits.fields().iter().zip(old.limits.fields().iter()) {
        if n > o {
            d.push(DeltaItem::LimitIncreased {
                limit: name,
                from: *o,
                to: *n,
            });
        }
    }
    d
}

pub fn is_subset(new: &PermissionSet, old: &PermissionSet) -> bool {
    expansion_delta(new, old).is_empty()
}
