//! Kernel confinement: Landlock, seccomp-BPF, `no_new_privs`.
//!
//! Usage is two-step so the parent can report exactly what the child enforces:
//! 1. [`plan`] (in the parent, before fork) turns a validated policy into a
//!    concrete [`Plan`] for the running kernel, or fails.
//! 2. [`install`] (in the forked child, before `execve`) applies the plan and
//!    fails if anything required could not be enforced.
//!
//! **Phase 4 status:** not implemented. Both functions fail closed, so no
//! `confinement: kernel` request can run until Phases 6–7 land.

use policy_model::Policy;
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    pub landlock_abi: u32,
    pub seccomp_profile: String,
    pub no_new_privs: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfinementError {
    #[error("kernel confinement is not implemented in this build")]
    NotImplemented,
}

pub fn plan(_policy: &Policy) -> Result<Plan, ConfinementError> {
    Err(ConfinementError::NotImplemented)
}

pub fn install(_plan: &Plan) -> std::io::Result<()> {
    Err(std::io::Error::other(ConfinementError::NotImplemented))
}
