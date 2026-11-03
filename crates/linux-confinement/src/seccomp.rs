//! Policy → seccomp-BPF (x86_64), compiled with `seccompiler`.
//!
//! Three filters are stacked (installed in the order 2, 3, 1: the profile
//! filter last). The kernel evaluates all of them and applies the most
//! restrictive result:
//! 1. the **profile**: a denylist (listed → EPERM, rest allowed) or an
//!    allowlist (listed allowed, rest → EPERM), with the policy's extra
//!    denials removed or added;
//! 2. **namespace guard**: `clone` with any `CLONE_NEW*` flag → EPERM;
//! 3. **clone3 guard**: `clone3` → ENOSYS. Its flags live in a struct seccomp
//!    cannot read, and glibc falls back to `clone` (guarded by filter 2).
//!
//! seccompiler programs validate the architecture and kill the process on a
//! mismatch. Filters are installed after Landlock (which needs its own
//! syscalls) and immediately before `execve`.

use policy_model::{profile, syscall_nr, Policy, ProfileMode};
use seccompiler::{
    BpfProgram, SeccompAction, SeccompCmpArgLen, SeccompCmpOp, SeccompCondition, SeccompFilter,
    SeccompRule, TargetArch,
};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

const CLONE_NS_FLAGS: &[u64] = &[
    libc::CLONE_NEWNS as u64,
    libc::CLONE_NEWUTS as u64,
    libc::CLONE_NEWIPC as u64,
    libc::CLONE_NEWUSER as u64,
    libc::CLONE_NEWPID as u64,
    libc::CLONE_NEWNET as u64,
    libc::CLONE_NEWCGROUP as u64,
    0x0000_0080, // CLONE_NEWTIME
];

#[derive(Debug, Clone, Serialize)]
pub struct SeccompPlan {
    pub profile: String,
    pub mode: &'static str,
    /// Syscalls answered with EPERM by the profile filter (denylist), or the
    /// number allowed (allowlist).
    pub listed: usize,
    pub extra_denied: Vec<String>,
    pub instructions: usize,
    #[serde(skip)]
    pub programs: Vec<BpfProgram>,
}

fn compile(
    rules: BTreeMap<i64, Vec<SeccompRule>>,
    mismatch: SeccompAction,
    matched: SeccompAction,
) -> Result<BpfProgram, String> {
    let f = SeccompFilter::new(rules, mismatch, matched, TargetArch::x86_64)
        .map_err(|e| e.to_string())?;
    BpfProgram::try_from(f).map_err(|e| e.to_string())
}

fn nr(name: &str) -> Result<i64, String> {
    syscall_nr(name)
        .map(i64::from)
        .ok_or_else(|| format!("unknown syscall {name}"))
}

pub fn plan(policy: &Policy) -> Result<SeccompPlan, String> {
    let prof = profile(&policy.syscalls.profile)
        .ok_or_else(|| format!("unknown seccomp profile {:?}", policy.syscalls.profile))?;
    if let Some(supported) = prof.supported_executables {
        for x in &policy.commands.allowed_executables {
            if !supported.contains(&x.as_str()) {
                return Err(format!("profile {} is not validated for {x}", prof.name));
            }
        }
    }
    let extra: BTreeSet<&str> = policy
        .syscalls
        .deny_high_risk
        .iter()
        .map(String::as_str)
        .collect();
    let eperm = SeccompAction::Errno(libc::EPERM as u32);

    let (main, listed, mode) = match prof.mode {
        ProfileMode::Denylist => {
            let names: BTreeSet<&str> = prof
                .syscalls
                .iter()
                .copied()
                .chain(extra.iter().copied())
                .collect();
            let rules = names
                .iter()
                .map(|n| Ok((nr(n)?, vec![])))
                .collect::<Result<_, String>>()?;
            (
                compile(rules, SeccompAction::Allow, eperm.clone())?,
                names.len(),
                "denylist",
            )
        }
        ProfileMode::Allowlist => {
            let names: BTreeSet<&str> = prof
                .syscalls
                .iter()
                .copied()
                .filter(|n| !extra.contains(n))
                .collect();
            let rules = names
                .iter()
                .map(|n| Ok((nr(n)?, vec![])))
                .collect::<Result<_, String>>()?;
            (
                compile(rules, eperm.clone(), SeccompAction::Allow)?,
                names.len(),
                "allowlist",
            )
        }
    };

    let mut ns_rules = Vec::new();
    for flag in CLONE_NS_FLAGS {
        let cond = SeccompCondition::new(
            0,
            SeccompCmpArgLen::Qword,
            SeccompCmpOp::MaskedEq(*flag),
            *flag,
        )
        .map_err(|e| e.to_string())?;
        ns_rules.push(SeccompRule::new(vec![cond]).map_err(|e| e.to_string())?);
    }
    let ns_guard = compile(
        BTreeMap::from([(nr("clone")?, ns_rules)]),
        SeccompAction::Allow,
        eperm,
    )?;
    let clone3_guard = compile(
        BTreeMap::from([(nr("clone3")?, vec![])]),
        SeccompAction::Allow,
        SeccompAction::Errno(libc::ENOSYS as u32),
    )?;

    // Install order matters: the profile filter goes LAST, because an
    // allowlist profile does not permit the `seccomp` syscall needed to add
    // further filters (which also means the task cannot stack its own).
    let programs = vec![ns_guard, clone3_guard, main];
    Ok(SeccompPlan {
        profile: prof.name.to_string(),
        mode,
        listed,
        extra_denied: extra.iter().map(|s| s.to_string()).collect(),
        instructions: programs.iter().map(Vec::len).sum(),
        programs,
    })
}

/// Install the planned filters on the calling (single-threaded, pre-exec)
/// process. `seccompiler::apply_filter` sets `no_new_privs` first.
pub fn install(plan: &SeccompPlan) -> Result<(), String> {
    for p in &plan.programs {
        seccompiler::apply_filter(p).map_err(|e| format!("seccomp install: {e}"))?;
    }
    Ok(())
}
