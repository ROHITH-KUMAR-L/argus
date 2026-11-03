//! Kernel confinement: Landlock, seccomp-BPF and `no_new_privs`.
//!
//! Two steps, so the parent can report exactly what the child enforces:
//! 1. [`plan`] (in the parent, before fork) turns a validated policy into a
//!    concrete [`Plan`] for the running kernel, or fails.
//! 2. [`install`] (in the forked child, before `execve`) applies the plan and
//!    fails if anything required could not be enforced. The worker turns that
//!    failure into `confinement_failed` and nothing runs.

pub mod landlock_rules;
pub mod seccomp;
mod sys;

pub use sys::landlock_abi;

use policy_model::Policy;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub landlock: landlock_rules::LandlockPlan,
    pub seccomp: seccomp::SeccompPlan,
    pub no_new_privs: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfinementError {
    #[error("landlock: {0}")]
    Landlock(String),
    #[error("seccomp: {0}")]
    Seccomp(String),
}

pub fn plan(policy: &Policy) -> Result<Plan, ConfinementError> {
    let ll = landlock_rules::plan(policy, landlock_abi()).map_err(ConfinementError::Landlock)?;
    let sc = seccomp::plan(policy).map_err(ConfinementError::Seccomp)?;
    Ok(Plan {
        landlock: ll,
        seccomp: sc,
        no_new_privs: true,
    })
}

/// Install everything in `plan` on the calling (single-threaded, pre-exec) process.
pub fn install(plan: &Plan) -> std::io::Result<()> {
    // Order: Landlock first (an allowlist filter might not permit the
    // Landlock syscalls), then seccomp, then the caller execs.
    landlock_rules::install(&plan.landlock).map_err(std::io::Error::other)?;
    seccomp::install(&plan.seccomp).map_err(std::io::Error::other)?;
    Ok(())
}
