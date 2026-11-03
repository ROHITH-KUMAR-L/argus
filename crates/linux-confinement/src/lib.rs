//! Kernel confinement: Landlock (Phase 6), seccomp-BPF (Phase 7), `no_new_privs`.
//!
//! Two steps, so the parent can report exactly what the child enforces:
//! 1. [`plan`] (in the parent, before fork) turns a validated policy into a
//!    concrete [`Plan`] for the running kernel, or fails.
//! 2. [`install`] (in the forked child, before `execve`) applies the plan and
//!    fails if anything required could not be enforced. The worker turns that
//!    failure into `confinement_failed` and nothing runs.

pub mod landlock_rules;
mod sys;

pub use sys::landlock_abi;

use policy_model::Policy;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub landlock: landlock_rules::LandlockPlan,
    /// Phase 7: seccomp profile name (not yet installed).
    pub seccomp_profile: String,
    pub no_new_privs: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfinementError {
    #[error("landlock: {0}")]
    Landlock(String),
}

pub fn plan(policy: &Policy) -> Result<Plan, ConfinementError> {
    let ll = landlock_rules::plan(policy, landlock_abi()).map_err(ConfinementError::Landlock)?;
    Ok(Plan {
        landlock: ll,
        seccomp_profile: policy.syscalls.profile.clone(),
        no_new_privs: true,
    })
}

/// Install everything in `plan` on the calling (single-threaded, pre-exec) process.
pub fn install(plan: &Plan) -> std::io::Result<()> {
    landlock_rules::install(&plan.landlock).map_err(std::io::Error::other)?;
    Ok(())
}
