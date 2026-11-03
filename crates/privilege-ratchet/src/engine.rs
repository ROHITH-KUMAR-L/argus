//! Deterministic ratchet engine.
//!
//! All state changes go through [`Engine::apply`] with an explicit `now`, so a
//! persisted op log replays to exactly the same state. Action evaluation
//! ([`Engine::evaluate_action`]) is read-only.

use crate::subset::{coverage, expansion_delta, DeltaItem};
use policy_model::{
    valid_id, Access, Action, Confinement, Operation, WorkerRequest, MAX_ARGV, MAX_ARG_BYTES,
    MAX_CONTENT_BYTES, WORKER_REQUEST_VERSION,
};
use policy_validator::{
    paths, validate_str, DeploymentConfig, Issue, Validated, ValidationContext,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;

pub const DEFAULT_EXPANSION_TTL_SECS: u64 = 900;
pub const DEFAULT_READ_BYTES: u64 = 64 * 1024;
pub const MAX_READ_BYTES: u64 = 1024 * 1024;
pub const MAX_REASON_LEN: usize = 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Arm {
    B0,
    B1,
    P1,
}

impl Arm {
    pub fn as_str(self) -> &'static str {
        match self {
            Arm::B0 => "B0",
            Arm::B1 => "B1",
            Arm::P1 => "P1",
        }
    }
}

impl std::str::FromStr for Arm {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "B0" => Ok(Arm::B0),
            "B1" => Ok(Arm::B1),
            "P1" => Ok(Arm::P1),
            _ => Err(format!("unknown arm {s:?}")),
        }
    }
}

/// State-changing operations. These are exactly what the daemon persists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Op {
    OpenTask {
        task_id: String,
        policy: String,
    },
    ApplyNarrowing {
        task_id: String,
        epoch_id: String,
        expected_policy_hash: String,
        proposed_policy: String,
        reason: String,
    },
    RequestExpansion {
        task_id: String,
        epoch_id: String,
        policy_hash: String,
        proposed_policy: String,
        reason: String,
    },
    DecideExpansion {
        task_id: String,
        expansion_id: String,
        approver: String,
        approve: bool,
    },
    CloseEpoch {
        task_id: String,
        epoch_id: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RatchetError {
    UnknownTask,
    TaskExists,
    EpochClosed,
    StaleEpoch,
    StalePolicyHash,
    PolicyInvalid(Vec<Issue>),
    TaskMismatch(String),
    ExpansionDenied(Vec<DeltaItem>),
    NotAnExpansion,
    UnknownExpansion,
    ExpansionExpired,
    ArmStaticPolicy,
    Malformed(String),
}

impl RatchetError {
    pub fn code(&self) -> &'static str {
        match self {
            RatchetError::UnknownTask => "UNKNOWN_TASK",
            RatchetError::TaskExists => "TASK_EXISTS",
            RatchetError::EpochClosed => "EPOCH_CLOSED",
            RatchetError::StaleEpoch => "STALE_EPOCH",
            RatchetError::StalePolicyHash => "STALE_POLICY_HASH",
            RatchetError::PolicyInvalid(_) => "POLICY_VALIDATION_FAILED",
            RatchetError::TaskMismatch(_) => "MALFORMED_REQUEST",
            RatchetError::ExpansionDenied(_) => "PRIVILEGE_EXPANSION_DENIED",
            RatchetError::NotAnExpansion => "MALFORMED_REQUEST",
            RatchetError::UnknownExpansion => "UNKNOWN_EXPANSION",
            RatchetError::ExpansionExpired => "UNKNOWN_EXPANSION",
            RatchetError::ArmStaticPolicy => "ARM_STATIC_POLICY",
            RatchetError::Malformed(_) => "MALFORMED_REQUEST",
        }
    }

    pub fn message(&self) -> String {
        match self {
            RatchetError::UnknownTask => "no such task".into(),
            RatchetError::TaskExists => "task already open".into(),
            RatchetError::EpochClosed => "the epoch is closed".into(),
            RatchetError::StaleEpoch => "epoch_id is not the current epoch".into(),
            RatchetError::StalePolicyHash => {
                "policy hash is not the current effective policy".into()
            }
            RatchetError::PolicyInvalid(_) => "proposed policy failed validation".into(),
            RatchetError::TaskMismatch(m) => m.clone(),
            RatchetError::ExpansionDenied(_) => {
                "in-epoch privilege expansion denied; request approval for a new epoch".into()
            }
            RatchetError::NotAnExpansion => {
                "proposed policy adds no permission; use apply_narrowing".into()
            }
            RatchetError::UnknownExpansion => "no pending expansion with that id".into(),
            RatchetError::ExpansionExpired => "the expansion request has expired".into(),
            RatchetError::ArmStaticPolicy => {
                "this experiment arm uses a static policy; transitions are not applied".into()
            }
            RatchetError::Malformed(m) => m.clone(),
        }
    }

    pub fn detail(&self) -> Option<Value> {
        match self {
            RatchetError::PolicyInvalid(issues) => Some(json!({ "issues": issues })),
            RatchetError::ExpansionDenied(delta) => Some(json!({ "delta": delta })),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TransitionRecord {
    pub seq: u64,
    pub at: u64,
    pub kind: &'static str,
    pub epoch: u64,
    pub from_hash: String,
    pub to_hash: String,
    pub reason: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub delta: Vec<DeltaItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approver: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expansion_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PendingExpansion {
    pub id: String,
    pub epoch_id: String,
    pub base_hash: String,
    pub proposed: Validated,
    pub delta: Vec<DeltaItem>,
    pub reason: String,
    pub created_at: u64,
}

#[derive(Debug, Clone)]
pub struct TaskState {
    pub task_id: String,
    pub epoch: u64,
    pub epoch_id: String,
    pub closed: bool,
    pub current: Validated,
    pub transitions: Vec<TransitionRecord>,
    pub pending: BTreeMap<String, PendingExpansion>,
    pub expansion_counter: u64,
}

impl TaskState {
    fn record(
        &mut self,
        at: u64,
        kind: &'static str,
        from: &str,
        to: &str,
        reason: &str,
        delta: Vec<DeltaItem>,
    ) -> &mut TransitionRecord {
        let seq = self.transitions.len() as u64 + 1;
        self.transitions.push(TransitionRecord {
            seq,
            at,
            kind,
            epoch: self.epoch,
            from_hash: from.into(),
            to_hash: to.into(),
            reason: reason.into(),
            delta,
            approver: None,
            expansion_id: None,
        });
        self.transitions.last_mut().expect("just pushed")
    }

    pub fn summary(&self) -> Value {
        json!({
            "task_id": self.task_id,
            "epoch": self.epoch,
            "epoch_id": self.epoch_id,
            "closed": self.closed,
            "policy_hash": self.current.policy_hash,
            "pending_expansions": self.pending.keys().collect::<Vec<_>>(),
            "transitions": self.transitions,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Decision {
    pub decision: &'static str,
    pub reason_code: &'static str,
    pub evidence: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatch: Option<WorkerRequest>,
}

pub struct Engine {
    pub arm: Arm,
    pub deployment: DeploymentConfig,
    pub landlock_abi: Option<u32>,
    pub expansion_ttl: u64,
    tasks: BTreeMap<String, TaskState>,
}

fn epoch_id(task_id: &str, epoch: u64) -> String {
    format!("{task_id}:e{epoch}")
}

fn bounded(reason: &str) -> Result<String, RatchetError> {
    if reason.chars().count() > MAX_REASON_LEN {
        return Err(RatchetError::Malformed("reason too long".into()));
    }
    Ok(reason.to_string())
}

impl Engine {
    pub fn new(arm: Arm, deployment: DeploymentConfig, landlock_abi: Option<u32>) -> Self {
        Self {
            arm,
            deployment,
            landlock_abi,
            expansion_ttl: DEFAULT_EXPANSION_TTL_SECS,
            tasks: BTreeMap::new(),
        }
    }

    pub fn task(&self, task_id: &str) -> Option<&TaskState> {
        self.tasks.get(task_id)
    }

    fn validate(&self, text: &str) -> Result<Validated, RatchetError> {
        let ctx = ValidationContext {
            deployment: &self.deployment,
            landlock_abi: self.landlock_abi,
        };
        validate_str(text, &ctx).map_err(RatchetError::PolicyInvalid)
    }

    /// Check that `(epoch_id, hash)` names the open current epoch/policy of `task`.
    fn check_current(t: &TaskState, epoch_id: &str, hash: &str) -> Result<(), RatchetError> {
        if t.closed {
            return Err(RatchetError::EpochClosed);
        }
        if t.epoch_id != epoch_id {
            return Err(RatchetError::StaleEpoch);
        }
        if t.current.policy_hash != hash {
            return Err(RatchetError::StalePolicyHash);
        }
        Ok(())
    }

    /// Apply one state-changing op. Rejections that concern a known task are
    /// recorded in its transition history (so they are auditable and replay).
    pub fn apply(&mut self, op: &Op, now: u64) -> Result<Value, RatchetError> {
        match op {
            Op::OpenTask { task_id, policy } => self.open_task(task_id, policy, now),
            Op::ApplyNarrowing {
                task_id,
                epoch_id,
                expected_policy_hash,
                proposed_policy,
                reason,
            } => self.apply_narrowing(
                task_id,
                epoch_id,
                expected_policy_hash,
                proposed_policy,
                reason,
                now,
            ),
            Op::RequestExpansion {
                task_id,
                epoch_id,
                policy_hash,
                proposed_policy,
                reason,
            } => {
                self.request_expansion(task_id, epoch_id, policy_hash, proposed_policy, reason, now)
            }
            Op::DecideExpansion {
                task_id,
                expansion_id,
                approver,
                approve,
            } => self.decide_expansion(task_id, expansion_id, approver, *approve, now),
            Op::CloseEpoch {
                task_id,
                epoch_id,
                reason,
            } => self.close_epoch(task_id, epoch_id, reason, now),
        }
    }

    fn open_task(&mut self, task_id: &str, policy: &str, now: u64) -> Result<Value, RatchetError> {
        if self.tasks.contains_key(task_id) {
            return Err(RatchetError::TaskExists);
        }
        let v = self.validate(policy)?;
        if v.policy.task_id != task_id {
            return Err(RatchetError::TaskMismatch(
                "policy.task_id does not match task_id".into(),
            ));
        }
        let mut t = TaskState {
            task_id: task_id.into(),
            epoch: 1,
            epoch_id: epoch_id(task_id, 1),
            closed: false,
            current: v,
            transitions: Vec::new(),
            pending: BTreeMap::new(),
            expansion_counter: 0,
        };
        let h = t.current.policy_hash.clone();
        t.record(now, "TASK_OPENED", "", &h, "initial policy P0", vec![]);
        let out = json!({
            "task_id": task_id,
            "epoch": 1,
            "epoch_id": t.epoch_id,
            "policy_hash": h,
            "normalized_policy": t.current.policy,
            "warnings": t.current.warnings,
        });
        self.tasks.insert(task_id.into(), t);
        Ok(out)
    }

    /// Run `f` against task `task_id`; on error, record a rejection transition.
    fn with_task<F>(
        &mut self,
        task_id: &str,
        now: u64,
        kind_on_err: &'static str,
        f: F,
    ) -> Result<Value, RatchetError>
    where
        F: FnOnce(&mut TaskState, &Self) -> Result<Value, RatchetError>,
    {
        let mut t = self
            .tasks
            .remove(task_id)
            .ok_or(RatchetError::UnknownTask)?;
        let res = f(&mut t, self);
        if let Err(e) = &res {
            let h = t.current.policy_hash.clone();
            let delta = match e {
                RatchetError::ExpansionDenied(d) => d.clone(),
                _ => vec![],
            };
            let kind = match e {
                RatchetError::ExpansionDenied(_) => "PRIVILEGE_EXPANSION_DENIED",
                _ => kind_on_err,
            };
            t.record(now, kind, &h, &h, e.code(), delta);
        }
        self.tasks.insert(task_id.into(), t);
        res
    }

    fn apply_narrowing(
        &mut self,
        task_id: &str,
        eid: &str,
        expected: &str,
        proposed: &str,
        reason: &str,
        now: u64,
    ) -> Result<Value, RatchetError> {
        let arm = self.arm;
        self.with_task(task_id, now, "TRANSITION_REJECTED", |t, eng| {
            Self::check_current(t, eid, expected)?;
            let reason = bounded(reason)?;
            if arm != Arm::P1 {
                return Err(RatchetError::ArmStaticPolicy);
            }
            let v = eng.validate(proposed)?;
            if v.policy.task_id != t.task_id || v.policy.workspace != t.current.policy.workspace {
                return Err(RatchetError::TaskMismatch(
                    "proposed policy changes task_id or workspace".into(),
                ));
            }
            let delta = expansion_delta(&v.permissions, &t.current.permissions);
            if !delta.is_empty() {
                // RAT-014: a mixed transition is rejected as a whole.
                return Err(RatchetError::ExpansionDenied(delta));
            }
            let from = t.current.policy_hash.clone();
            let to = v.policy_hash.clone();
            if v.permissions == t.current.permissions {
                t.record(now, "POLICY_UNCHANGED", &from, &from, &reason, vec![]);
                return Ok(json!({"accepted": true, "changed": false, "policy_hash": from}));
            }
            t.current = v;
            // Pending expansions were computed against the old policy.
            t.pending.clear();
            let seq = t
                .record(now, "POLICY_NARROWED", &from, &to, &reason, vec![])
                .seq;
            Ok(json!({"accepted": true, "changed": true, "policy_hash": to, "transition_seq": seq}))
        })
    }

    fn request_expansion(
        &mut self,
        task_id: &str,
        eid: &str,
        hash: &str,
        proposed: &str,
        reason: &str,
        now: u64,
    ) -> Result<Value, RatchetError> {
        let arm = self.arm;
        self.with_task(task_id, now, "EXPANSION_REQUEST_REJECTED", |t, eng| {
            Self::check_current(t, eid, hash)?;
            let reason = bounded(reason)?;
            if arm != Arm::P1 {
                return Err(RatchetError::ArmStaticPolicy);
            }
            let v = eng.validate(proposed)?;
            if v.policy.task_id != t.task_id || v.policy.workspace != t.current.policy.workspace {
                return Err(RatchetError::TaskMismatch(
                    "proposed policy changes task_id or workspace".into(),
                ));
            }
            let delta = expansion_delta(&v.permissions, &t.current.permissions);
            if delta.is_empty() {
                return Err(RatchetError::NotAnExpansion);
            }
            t.expansion_counter += 1;
            let id = format!("{}:x{}", t.epoch_id, t.expansion_counter);
            let from = t.current.policy_hash.clone();
            let to = v.policy_hash.clone();
            let rec = t.record(now, "EXPANSION_REQUESTED", &from, &to, &reason, delta.clone());
            rec.expansion_id = Some(id.clone());
            t.pending.insert(
                id.clone(),
                PendingExpansion {
                    id: id.clone(),
                    epoch_id: t.epoch_id.clone(),
                    base_hash: from,
                    proposed: v,
                    delta: delta.clone(),
                    reason,
                    created_at: now,
                },
            );
            Ok(json!({"expansion_id": id, "status": "APPROVAL_PENDING", "delta": delta, "expires_at": now + eng.expansion_ttl}))
        })
    }

    fn decide_expansion(
        &mut self,
        task_id: &str,
        xid: &str,
        approver: &str,
        approve: bool,
        now: u64,
    ) -> Result<Value, RatchetError> {
        let ttl = self.expansion_ttl;
        self.with_task(task_id, now, "APPROVAL_REJECTED", |t, _| {
            if approver.is_empty() || approver.len() > 128 {
                return Err(RatchetError::Malformed("approver must be 1-128 characters".into()));
            }
            if t.closed {
                return Err(RatchetError::EpochClosed);
            }
            // Single use: the pending entry is removed whatever the outcome.
            let p = t.pending.remove(xid).ok_or(RatchetError::UnknownExpansion)?;
            if p.epoch_id != t.epoch_id {
                return Err(RatchetError::StaleEpoch);
            }
            if p.base_hash != t.current.policy_hash {
                return Err(RatchetError::StalePolicyHash);
            }
            if now.saturating_sub(p.created_at) > ttl {
                return Err(RatchetError::ExpansionExpired);
            }
            let from = t.current.policy_hash.clone();
            if !approve {
                let rec = t.record(now, "EXPANSION_DENIED_BY_APPROVER", &from, &from, &p.reason, p.delta.clone());
                rec.approver = Some(approver.into());
                rec.expansion_id = Some(p.id.clone());
                return Ok(json!({"status": "DENIED", "epoch_id": t.epoch_id, "policy_hash": from}));
            }
            // Approved: close the old epoch, start a new one with the new policy.
            let to = p.proposed.policy_hash.clone();
            let old_epoch = t.epoch;
            let rec = t.record(now, "EPOCH_CLOSED", &from, &from, "superseded by approved expansion", vec![]);
            rec.expansion_id = Some(p.id.clone());
            t.epoch = old_epoch + 1;
            t.epoch_id = epoch_id(&t.task_id, t.epoch);
            t.current = p.proposed;
            t.pending.clear();
            let rec = t.record(now, "EXPANSION_APPROVED_NEW_EPOCH", &from, &to, &p.reason, p.delta);
            rec.approver = Some(approver.into());
            rec.expansion_id = Some(p.id);
            Ok(json!({"status": "APPROVED", "epoch": t.epoch, "epoch_id": t.epoch_id, "policy_hash": to}))
        })
    }

    fn close_epoch(
        &mut self,
        task_id: &str,
        eid: &str,
        reason: &str,
        now: u64,
    ) -> Result<Value, RatchetError> {
        self.with_task(task_id, now, "TRANSITION_REJECTED", |t, _| {
            let reason = bounded(reason)?;
            if t.closed {
                return Err(RatchetError::EpochClosed);
            }
            if t.epoch_id != eid {
                return Err(RatchetError::StaleEpoch);
            }
            t.closed = true;
            t.pending.clear();
            let h = t.current.policy_hash.clone();
            t.record(now, "EPOCH_CLOSED", &h, &h, &reason, vec![]);
            Ok(json!({"closed": true}))
        })
    }

    /// Decide one proposed action against the *current* effective policy.
    /// Errors (unknown task, stale epoch/hash) must be treated as DENY.
    pub fn evaluate_action(
        &self,
        task_id: &str,
        eid: &str,
        hash: &str,
        run_id: &str,
        action_id: &str,
        action: &Action,
    ) -> Result<Decision, RatchetError> {
        let t = self.tasks.get(task_id).ok_or(RatchetError::UnknownTask)?;
        Self::check_current(t, eid, hash)?;
        if !valid_id(run_id) || !valid_id(action_id) {
            return Ok(deny(
                "INVALID_ID",
                json!({"detail": "run_id/action_id must match [A-Za-z0-9._:-]{1,64}"}),
            ));
        }
        let gated = self.arm != Arm::B0;
        let op = match self.resolve(t, action, gated) {
            Ok(Resolved::Op(op)) => op,
            Ok(Resolved::Approval(evidence)) => {
                return Ok(Decision {
                    decision: "APPROVAL_REQUIRED",
                    reason_code: "PERMISSION_REQUEST",
                    evidence,
                    dispatch: None,
                })
            }
            Err((code, evidence)) => return Ok(deny(code, evidence)),
        };
        let p = &t.current;
        Ok(Decision {
            decision: "ALLOW",
            reason_code: if gated {
                "WITHIN_POLICY"
            } else {
                "ARM_B0_UNGATED"
            },
            evidence: json!({"tool": action.tool_name(), "policy_hash": p.policy_hash, "epoch": t.epoch}),
            dispatch: Some(WorkerRequest {
                request_version: WORKER_REQUEST_VERSION.into(),
                run_id: run_id.into(),
                task_id: t.task_id.clone(),
                epoch: t.epoch,
                epoch_id: t.epoch_id.clone(),
                action_id: action_id.into(),
                arm: self.arm.as_str().into(),
                confinement: if gated {
                    Confinement::Kernel
                } else {
                    Confinement::None
                },
                policy_hash: p.policy_hash.clone(),
                canonical_policy: p.canonical_json.clone(),
                operation: op,
            }),
        })
    }

    fn resolve(
        &self,
        t: &TaskState,
        action: &Action,
        gated: bool,
    ) -> Result<Resolved, (&'static str, Value)> {
        let p = &t.current;
        let perms = &p.permissions;
        let ws = &p.policy.workspace;
        let tool = action.tool_name();
        if gated && !perms.tools.contains(tool) {
            return Err(("TOOL_NOT_PERMITTED", json!({"tool": tool})));
        }
        let wall = p.policy.limits.wall_time_seconds;

        // Resolve a planner path. Gated arms: relative to the workspace only.
        let path_of = |raw: &str, need: Access| -> Result<String, (&'static str, Value)> {
            let abs = if raw.is_empty() {
                ws.clone()
            } else if !gated && raw.starts_with('/') {
                paths::check_absolute(raw)
                    .map_err(|e| {
                        (
                            "PATH_INVALID",
                            json!({"path": raw, "detail": e.to_string()}),
                        )
                    })?
                    .to_string()
            } else {
                paths::resolve_relative(ws, raw).map_err(|e| {
                    (
                        "PATH_OUTSIDE_WORKSPACE",
                        json!({"path": raw, "detail": e.to_string()}),
                    )
                })?
            };
            if gated {
                let have = coverage(&perms.fs, &abs);
                if !have.contains(need) {
                    return Err((
                        "PATH_NOT_PERMITTED",
                        json!({"path": abs, "required": need.names(), "granted": have.names()}),
                    ));
                }
            }
            Ok(abs)
        };
        let content_cap = (MAX_CONTENT_BYTES as u64).min(p.policy.limits.file_size_bytes);
        let check_len = |len: usize| -> Result<(), (&'static str, Value)> {
            if len as u64 > content_cap {
                Err((
                    "CONTENT_TOO_LARGE",
                    json!({"bytes": len, "max": content_cap}),
                ))
            } else {
                Ok(())
            }
        };
        let check_exec = |argv: &[String]| -> Result<(), (&'static str, Value)> {
            if argv.is_empty() || argv.len() > MAX_ARGV {
                return Err((
                    "ARGV_INVALID",
                    json!({"detail": "argv must have 1..=256 entries"}),
                ));
            }
            if argv
                .iter()
                .any(|a| a.len() > MAX_ARG_BYTES || a.contains('\0'))
            {
                return Err((
                    "ARGV_INVALID",
                    json!({"detail": "argument too long or contains NUL"}),
                ));
            }
            if paths::check_absolute(&argv[0]).is_err() {
                return Err((
                    "ARGV_INVALID",
                    json!({"detail": "argv[0] must be a canonical absolute path"}),
                ));
            }
            if gated && !perms.executables.contains(&argv[0]) {
                return Err(("EXECUTABLE_NOT_PERMITTED", json!({"executable": argv[0]})));
            }
            Ok(())
        };

        let op = match action {
            Action::ListFiles { path } => Operation::ListFiles {
                path: path_of(path, Access(Access::READ))?,
            },
            Action::ReadFile {
                path,
                offset,
                length,
            } => {
                let length = length.unwrap_or(DEFAULT_READ_BYTES);
                if length == 0 || length > MAX_READ_BYTES {
                    return Err((
                        "READ_LENGTH_INVALID",
                        json!({"length": length, "max": MAX_READ_BYTES}),
                    ));
                }
                Operation::ReadFile {
                    path: path_of(path, Access(Access::READ))?,
                    offset: *offset,
                    length,
                }
            }
            Action::WriteFile { path, content } => {
                check_len(content.len())?;
                Operation::WriteFile {
                    path: path_of(path, Access(Access::WRITE))?,
                    content: content.clone(),
                }
            }
            Action::ApplyPatch { path, patch } => {
                check_len(patch.len())?;
                Operation::ApplyPatch {
                    path: path_of(path, Access(Access::READ | Access::WRITE))?,
                    patch: patch.clone(),
                }
            }
            Action::RunCommand {
                executable,
                argv,
                cwd,
                timeout_seconds,
            } => {
                if argv.first() != Some(executable) {
                    return Err((
                        "ARGV_INVALID",
                        json!({"detail": "argv[0] must equal executable"}),
                    ));
                }
                check_exec(argv)?;
                let timeout = timeout_seconds.unwrap_or(wall);
                if timeout == 0 || timeout > wall {
                    return Err((
                        "TIMEOUT_EXCEEDS_LIMIT",
                        json!({"timeout_seconds": timeout, "max": wall}),
                    ));
                }
                Operation::Exec {
                    argv: argv.clone(),
                    cwd: path_of(cwd.as_deref().unwrap_or(""), Access(Access::READ))?,
                    timeout_seconds: timeout,
                }
            }
            Action::RunTests { target } => {
                let argv = self
                    .deployment
                    .test_targets
                    .get(target)
                    .ok_or(("UNKNOWN_TEST_TARGET", json!({"target": target})))?;
                check_exec(argv)?;
                Operation::Exec {
                    argv: argv.clone(),
                    cwd: path_of("", Access(Access::READ))?,
                    timeout_seconds: wall,
                }
            }
            Action::RequestPermission {
                reason,
                add_read_only,
                add_read_write,
                add_executables,
                add_tools,
            } => {
                if self.arm != Arm::P1 {
                    return Err((
                        "ARM_STATIC_POLICY",
                        json!({"detail": "no approval path in this arm"}),
                    ));
                }
                if reason.chars().count() > MAX_REASON_LEN {
                    return Err(("REASON_TOO_LONG", json!({})));
                }
                return Ok(Resolved::Approval(json!({
                    "reason": reason,
                    "add_read_only": add_read_only,
                    "add_read_write": add_read_write,
                    "add_executables": add_executables,
                    "add_tools": add_tools,
                    "policy_hash": p.policy_hash,
                    "epoch": t.epoch,
                })));
            }
        };
        Ok(Resolved::Op(op))
    }
}

enum Resolved {
    Op(Operation),
    Approval(Value),
}

fn deny(code: &'static str, evidence: Value) -> Decision {
    Decision {
        decision: "DENY",
        reason_code: code,
        evidence,
        dispatch: None,
    }
}
