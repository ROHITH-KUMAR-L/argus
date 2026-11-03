#![allow(clippy::result_large_err)] // Response is returned by value on a cold path.
//! Request dispatch for the decision and approval sockets.

use crate::store::Store;
use policy_model::Action;
use policy_validator::{validate_str, ValidationContext};
use privilege_ratchet::{Engine, Op, RatchetError};
use protocol::{valid_request_id, ErrorCode, Request, Response, PROTOCOL_VERSION};
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocketKind {
    Decision,
    Approval,
}

pub struct State {
    pub engine: Engine,
    pub store: Store,
    pub seen_request_ids: HashSet<String>,
    /// Set after any failed append; all further state changes are refused.
    pub store_poisoned: bool,
    pub deployment_hash: String,
}

pub const MAX_SEEN_REQUEST_IDS: usize = 1_000_000;

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn code_of(s: &str) -> ErrorCode {
    serde_json::from_value(Value::String(s.into())).unwrap_or(ErrorCode::Internal)
}

fn ratchet_err(id: &str, e: &RatchetError) -> Response {
    Response::err_detail(id, code_of(e.code()), e.message(), e.detail())
}

fn params<T: for<'de> Deserialize<'de>>(id: &str, v: &Value) -> Result<T, Response> {
    serde_json::from_value(v.clone()).map_err(|e| {
        Response::err(
            id,
            ErrorCode::MalformedRequest,
            format!("invalid params: {e}"),
        )
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ValidateP {
    policy_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenP {
    task_id: String,
    policy_json: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EvalP {
    task_id: String,
    epoch_id: String,
    policy_hash: String,
    run_id: String,
    action_id: String,
    action: Value,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NarrowP {
    task_id: String,
    epoch_id: String,
    expected_policy_hash: String,
    proposed_policy_json: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ExpandP {
    task_id: String,
    epoch_id: String,
    policy_hash: String,
    proposed_policy_json: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveP {
    task_id: String,
    expansion_id: String,
    approver: String,
    decision: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CloseP {
    task_id: String,
    epoch_id: String,
    reason: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TaskP {
    task_id: String,
}

/// Handle one raw frame. Never panics on untrusted input.
pub fn handle_frame(state: &mut State, kind: SocketKind, frame: &[u8]) -> Response {
    let req: Request = match serde_json::from_slice(frame) {
        Ok(r) => r,
        Err(e) => {
            return Response::err(
                "",
                ErrorCode::MalformedRequest,
                format!("invalid request: {e}"),
            )
        }
    };
    let id = req.request_id.clone();
    if req.protocol_version != PROTOCOL_VERSION {
        return Response::err(
            &id,
            ErrorCode::UnsupportedProtocolVersion,
            "protocol_version must be \"1\"",
        );
    }
    if !valid_request_id(&id) {
        return Response::err(&id, ErrorCode::MalformedRequest, "invalid request_id");
    }
    if state.seen_request_ids.contains(&id) {
        return Response::err(&id, ErrorCode::ReplayedRequest, "request_id already used");
    }
    if state.seen_request_ids.len() >= MAX_SEEN_REQUEST_IDS {
        return Response::err(
            &id,
            ErrorCode::Internal,
            "request-id table full; restart the daemon",
        );
    }
    state.seen_request_ids.insert(id.clone());

    let allowed = match kind {
        SocketKind::Decision => matches!(
            req.method.as_str(),
            "health"
                | "validate_policy"
                | "open_task"
                | "evaluate_action"
                | "apply_narrowing"
                | "request_expansion"
                | "close_epoch"
                | "get_state"
        ),
        SocketKind::Approval => matches!(
            req.method.as_str(),
            "health" | "get_state" | "approve_expansion"
        ),
    };
    let known = matches!(
        req.method.as_str(),
        "health"
            | "validate_policy"
            | "open_task"
            | "evaluate_action"
            | "apply_narrowing"
            | "request_expansion"
            | "approve_expansion"
            | "close_epoch"
            | "get_state"
    );
    if !known {
        return Response::err(
            &id,
            ErrorCode::UnknownMethod,
            format!("unknown method {:?}", req.method),
        );
    }
    if !allowed {
        return Response::err(
            &id,
            ErrorCode::MethodNotPermittedOnSocket,
            format!("{} is not available on this socket", req.method),
        );
    }

    match dispatch(state, &id, &req.method, &req.params) {
        Ok(v) => Response::ok(&id, v),
        Err(r) => r,
    }
}

fn mutate(state: &mut State, id: &str, op: Op) -> Result<Value, Response> {
    if state.store_poisoned {
        return Err(Response::err(
            id,
            ErrorCode::StateStoreUnavailable,
            "state store failed earlier; refusing changes",
        ));
    }
    let now = now_secs();
    if let Err(e) = state.store.append(&op, now) {
        state.store_poisoned = true;
        return Err(Response::err(
            id,
            ErrorCode::StateStoreUnavailable,
            format!("cannot persist: {e}"),
        ));
    }
    state
        .engine
        .apply(&op, now)
        .map_err(|e| ratchet_err(id, &e))
}

fn dispatch(state: &mut State, id: &str, method: &str, p: &Value) -> Result<Value, Response> {
    match method {
        "health" => {
            if !p.is_null() {
                params::<Empty>(id, p)?;
            }
            Ok(json!({
                "daemon_version": env!("CARGO_PKG_VERSION"),
                "protocol_version": PROTOCOL_VERSION,
                "arm": state.engine.arm.as_str(),
                "landlock_abi": state.engine.landlock_abi,
                "deployment_hash": state.deployment_hash,
                "state_store": if state.store_poisoned { "unavailable" } else { "ok" },
            }))
        }
        "validate_policy" => {
            let a: ValidateP = params(id, p)?;
            let ctx = ValidationContext {
                deployment: &state.engine.deployment,
                landlock_abi: state.engine.landlock_abi,
            };
            match validate_str(&a.policy_json, &ctx) {
                Ok(v) => Ok(
                    json!({"normalized_policy": v.policy, "policy_hash": v.policy_hash, "warnings": v.warnings}),
                ),
                Err(issues) => Err(Response::err_detail(
                    id,
                    ErrorCode::PolicyValidationFailed,
                    "policy failed validation",
                    Some(json!({"issues": issues})),
                )),
            }
        }
        "open_task" => {
            let a: OpenP = params(id, p)?;
            mutate(
                state,
                id,
                Op::OpenTask {
                    task_id: a.task_id,
                    policy: a.policy_json,
                },
            )
        }
        "apply_narrowing" => {
            let a: NarrowP = params(id, p)?;
            mutate(
                state,
                id,
                Op::ApplyNarrowing {
                    task_id: a.task_id,
                    epoch_id: a.epoch_id,
                    expected_policy_hash: a.expected_policy_hash,
                    proposed_policy: a.proposed_policy_json,
                    reason: a.reason,
                },
            )
        }
        "request_expansion" => {
            let a: ExpandP = params(id, p)?;
            mutate(
                state,
                id,
                Op::RequestExpansion {
                    task_id: a.task_id,
                    epoch_id: a.epoch_id,
                    policy_hash: a.policy_hash,
                    proposed_policy: a.proposed_policy_json,
                    reason: a.reason,
                },
            )
        }
        "approve_expansion" => {
            let a: ApproveP = params(id, p)?;
            let approve = match a.decision.as_str() {
                "approve" => true,
                "deny" => false,
                _ => {
                    return Err(Response::err(
                        id,
                        ErrorCode::MalformedRequest,
                        "decision must be \"approve\" or \"deny\"",
                    ))
                }
            };
            mutate(
                state,
                id,
                Op::DecideExpansion {
                    task_id: a.task_id,
                    expansion_id: a.expansion_id,
                    approver: a.approver,
                    approve,
                },
            )
        }
        "close_epoch" => {
            let a: CloseP = params(id, p)?;
            mutate(
                state,
                id,
                Op::CloseEpoch {
                    task_id: a.task_id,
                    epoch_id: a.epoch_id,
                    reason: a.reason,
                },
            )
        }
        "evaluate_action" => {
            let a: EvalP = params(id, p)?;
            let action: Action = serde_json::from_value(a.action).map_err(|e| {
                Response::err(
                    id,
                    ErrorCode::MalformedRequest,
                    format!("invalid action: {e}"),
                )
            })?;
            let d = state
                .engine
                .evaluate_action(
                    &a.task_id,
                    &a.epoch_id,
                    &a.policy_hash,
                    &a.run_id,
                    &a.action_id,
                    &action,
                )
                .map_err(|e| ratchet_err(id, &e))?;
            Ok(serde_json::to_value(d).expect("decision serializes"))
        }
        "get_state" => {
            let a: TaskP = params(id, p)?;
            state
                .engine
                .task(&a.task_id)
                .map(|t| t.summary())
                .ok_or_else(|| Response::err(id, ErrorCode::UnknownTask, "no such task"))
        }
        _ => Err(Response::err(
            id,
            ErrorCode::UnknownMethod,
            "unknown method",
        )),
    }
}
