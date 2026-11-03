//! Deterministic monotonic privilege ratchet.
//!
//! Invariant: within an execution epoch, every committed policy satisfies
//! `permissions(next) ⊆ permissions(current)`. Expansion is possible only
//! through an explicit, single-use approval that closes the epoch and opens a
//! new one.

pub mod engine;
pub mod subset;

pub use engine::{Arm, Decision, Engine, Op, RatchetError, TaskState, TransitionRecord};
pub use subset::{coverage, expansion_delta, is_subset, DeltaItem};
