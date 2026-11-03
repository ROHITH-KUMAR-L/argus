"""The Argus task graph (LangGraph ``StateGraph``).

intake → context_loader → planner → plan_validator → action_normalizer →
policy_decision → (approval_interrupt | worker_dispatch → result_collector) →
completion_check → (planner | finalize)

Security properties enforced by construction:
* the planner's output is parsed by ``plan_validator`` and normalized by
  ``action_normalizer``; nothing else in the graph consumes it;
* ``policy_decision`` asks ratchetd; only ``ALLOW`` routes to dispatch;
* ``worker_dispatch`` asks ratchetd *again* immediately before executing and
  uses only that dispatch, so a stale plan or a replayed checkpoint cannot run
  under an older, broader policy (STK-005/010/012);
* ``approval_interrupt`` pauses for a human. The resume payload is ignored:
  only ratchetd's state, changed through the approval socket by
  ``argus approve``, can open a new epoch (RAT-023, STK-006/007);
* graph state is minimal and redacted (it may be checkpointed).
"""

from __future__ import annotations

import contextlib
import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any, Literal

from langgraph.graph import END, START, StateGraph
from langgraph.types import interrupt

from controller.audit import bridge
from controller.audit.events import Component, EventType
from controller.audit.lifecycle import Lifecycle, TaskState
from controller.audit.redact import Redactor, bound
from controller.executor import Executor
from controller.graph.proposals import Finish, ProposalError, parse_proposal, to_action
from controller.graph.state import AgentState
from controller.llm.planner import Planner, PlannerUnavailable, PlannerView
from controller.rust_client import RatchetClient, RatchetError, RatchetTransportError

S = TaskState
HISTORY_LIMIT = 24
EXCERPT = 2000


@dataclass
class Deps:
    rust: RatchetClient
    executor: Executor
    planner: Planner
    audit: Any  # AuditWriter
    lifecycle: Lifecycle
    policy: dict[str, Any]
    redactor: Redactor = field(default_factory=Redactor)
    success_check: dict[str, Any] | None = None
    max_steps: int = 20
    max_denials: int = 6
    max_invalid: int = 3
    load_context: bool = True
    policy_pending: dict[str, Any] | None = None
    # In-memory only (never checkpointed): raw planner output and full action
    # payloads, which may carry repository content.
    scratch: dict[str, Any] = field(default_factory=dict)


def _digest(obj: Any) -> str:
    return "sha256:" + hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def _redacted_view(deps: Deps, d: dict[str, Any]) -> dict[str, Any]:
    v = {k: val for k, val in d.items() if k not in ("content", "patch")}
    return deps.redactor.value(v)  # type: ignore[no-any-return]


def _ids(state: AgentState) -> dict[str, Any]:
    return {
        "task_id": state["task_id"],
        "epoch_id": state["epoch_id"],
        "policy_hash": state["policy_hash"],
    }


def _summary(
    deps: Deps,
    action: dict[str, Any] | None,
    decision: str,
    reason: str,
    result: dict[str, Any] | None = None,
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "action": action and {k: v for k, v in action.items() if k not in ("content", "patch")},
        "decision": decision,
        "reason": reason,
    }
    if result is not None:
        item["status"] = result.get("status")
        item["exit_code"] = result.get("exit_code")
        fr = result.get("file_result") or {}
        text = (fr.get("data") or {}).get("content") if fr else None
        if text is None and fr.get("data") and "entries" in fr["data"]:
            text = json.dumps([e["path"] for e in fr["data"]["entries"]][:200])
        if text is None and fr.get("error_kind"):
            text = f"{fr['error_kind']}: {fr.get('message', '')}"
        out = text if text is not None else (result.get("stdout", "") + result.get("stderr", ""))
        item["output"] = bound(deps.redactor.text(str(out)), EXCERPT)[0]
    return deps.redactor.value(item)  # type: ignore[no-any-return]


def _push(state: AgentState, item: dict[str, Any]) -> list[dict[str, Any]]:
    return [*state.get("history", []), item][-HISTORY_LIMIT:]


def build_graph(
    deps: Deps, checkpointer: Any = None, interrupt_before: list[str] | None = None
) -> Any:
    lc, audit = deps.lifecycle, deps.audit

    def execute_gated(
        state: AgentState, action: dict[str, Any], action_id: str
    ) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """Gate + run one controller-originated action (context, verification)."""
        lc.to(S.ACTION_REVIEW, epoch=state["epoch"])
        d = deps.rust.evaluate_action(
            **_ids(state), run_id=state["run_id"], action_id=action_id, action=action
        )
        bridge.action_decision(
            audit,
            epoch=state["epoch"],
            policy_hash=state["policy_hash"],
            action_id=action_id,
            action=action,
            decision=d,
        )
        if d["decision"] != "ALLOW":
            lc.to(S.DENIED, reason_code=d["reason_code"], epoch=state["epoch"])
            lc.to(S.PLANNING, epoch=state["epoch"])
            return d, None
        lc.to(S.RATCHETED, epoch=state["epoch"])
        lc.to(S.WORKER_SETUP, epoch=state["epoch"])
        res = deps.executor.execute(d["dispatch"])
        bridge.worker_result(audit, dispatch=d["dispatch"], result=res)
        lc.to(S.CONFINEMENT_CHECK, epoch=state["epoch"])
        if res.get("status") == "confinement_failed":
            lc.to(S.FAILED, reason_code="CONFINEMENT_INSTALL_FAILED", epoch=state["epoch"])
            return d, res
        lc.to(S.EXECUTING, epoch=state["epoch"])
        return d, res

    # ------------------------------------------------------------- nodes

    def intake(state: AgentState) -> AgentState:
        lc.to(S.POLICY_VALIDATION)
        try:
            t = deps.rust.open_task(state["task_id"], json.dumps(deps.policy))
        except RatchetError as e:
            bridge.policy_rejected(audit, e)
            lc.to(S.REJECTED, reason_code=e.code)
            return {"done": True, "outcome": "rejected", "outcome_reason": e.code}
        bridge.policy_validated(audit, t, epoch=t["epoch"])
        lc.to(S.PLANNING, epoch=t["epoch"])
        return {
            "epoch": t["epoch"],
            "epoch_id": t["epoch_id"],
            "policy_hash": t["policy_hash"],
            "step": 0,
            "invalid_outputs": 0,
            "denials": 0,
            "history": [],
            "done": False,
            "goal": bound(deps.redactor.text(state["goal"]), 8000)[0],
        }

    def context_loader(state: AgentState) -> AgentState:
        if not deps.load_context:
            return {}
        action = {"type": "list_files", "path": ""}
        d, res = execute_gated(state, action, f"{state['run_id']}-ctx")
        if res is not None and res.get("status") == "confinement_failed":
            return {
                "done": True,
                "outcome": "failed",
                "outcome_reason": "CONFINEMENT_INSTALL_FAILED",
            }
        if res is not None:
            lc.to(S.PLANNING, epoch=state["epoch"])
        return {
            "history": _push(state, _summary(deps, action, d["decision"], d["reason_code"], res))
        }

    def planner(state: AgentState) -> AgentState:
        view = PlannerView(
            goal=state["goal"],
            history=tuple(state.get("history", [])),
            step=state.get("step", 0),
            feedback=state.get("feedback"),
        )
        try:
            raw = deps.planner.propose(view)
        except PlannerUnavailable as e:
            audit.append(
                EventType.ERROR,
                Component.GRAPH,
                reason_code="PLANNER_UNAVAILABLE",
                epoch=state["epoch"],
                data={"error": str(e)},
            )
            return {
                "proposal": None,
                "feedback": None,
                "done": True,
                "outcome": "failed",
                "outcome_reason": "PLANNER_UNAVAILABLE",
            }
        deps.scratch["raw"] = raw
        # Adopt the current authoritative epoch/policy (e.g. after a controller
        # narrowing between steps). Within an epoch this can only be narrower;
        # dispatch is revalidated again in worker_dispatch regardless.
        st = deps.rust.get_state(state["task_id"])
        return {
            "proposal": None,
            "step": state.get("step", 0) + 1,
            "epoch": st["epoch"],
            "epoch_id": st["epoch_id"],
            "policy_hash": st["policy_hash"],
        }

    def plan_validator(state: AgentState) -> AgentState:
        if state.get("done"):
            return {}
        raw = deps.scratch.pop("raw", None)
        try:
            if raw is None:
                raise ProposalError("planner output unavailable (resumed from checkpoint); re-plan")
            p = parse_proposal(raw)
        except ProposalError as e:
            n = state.get("invalid_outputs", 0) + 1
            audit.append(
                EventType.ERROR,
                Component.GRAPH,
                reason_code="INVALID_PLANNER_OUTPUT",
                epoch=state["epoch"],
                data={"error": str(e)[:500], "count": n},
            )
            upd: AgentState = {
                "proposal": None,
                "invalid_outputs": n,
                "feedback": f"invalid proposal rejected: {str(e)[:300]}",
            }
            if n >= deps.max_invalid:
                upd.update(
                    {"done": True, "outcome": "failed", "outcome_reason": "INVALID_PLANNER_OUTPUT"}
                )
            return upd
        full = p.model_dump()
        deps.scratch["proposal"] = p
        summary = {**_redacted_view(deps, full), "digest": _digest(full)}
        audit.append(
            EventType.ACTION_PROPOSED,
            Component.GRAPH,
            epoch=state["epoch"],
            action=str(full.get("type", "")),
            data={"proposal": summary},
        )
        return {"proposal": summary, "feedback": None}

    def action_normalizer(state: AgentState) -> AgentState:
        p = deps.scratch.get("proposal")
        summary = state.get("proposal") or {}
        if p is None or _digest(p.model_dump()) != summary.get("digest"):
            deps.scratch.pop("action", None)
            return {"action": None}
        action = to_action(p)
        deps.scratch["action"] = action
        return {"action": action and _redacted_view(deps, action)}

    def policy_decision(state: AgentState) -> AgentState:
        lc.to(S.ACTION_REVIEW, epoch=state["epoch"])
        action = deps.scratch.get("action") or {}
        action_id = f"{state['run_id']}-s{state['step']}"
        try:
            if not action:
                raise RatchetError("CONTEXT_LOST", "action payload unavailable; re-plan")
            d = deps.rust.evaluate_action(
                **_ids(state), run_id=state["run_id"], action_id=action_id, action=action
            )
        except RatchetError as e:
            # Stale epoch/hash (e.g. replayed checkpoint) or malformed action: DENY,
            # then resynchronize with the authoritative state.
            d = {"decision": "DENY", "reason_code": e.code[:64], "evidence": {"message": e.message}}
            st = deps.rust.get_state(state["task_id"])
            resync: AgentState = {
                "epoch": st["epoch"],
                "epoch_id": st["epoch_id"],
                "policy_hash": st["policy_hash"],
            }
        else:
            resync = {}
        bridge.action_decision(
            audit,
            epoch=state["epoch"],
            policy_hash=state["policy_hash"],
            action_id=action_id,
            action=action,
            decision=d,
        )
        decision = {k: v for k, v in d.items() if k != "dispatch"}
        if d["decision"] == "ALLOW":
            lc.to(S.RATCHETED, epoch=state["epoch"])
            return {**resync, "decision": decision}
        if d["decision"] == "APPROVAL_REQUIRED":
            proposed = _expanded_policy(deps.policy, action)
            try:
                x = deps.rust.request_expansion(
                    **_ids(state),
                    proposed_policy_json=json.dumps(proposed),
                    reason=str(action.get("reason", ""))[:1000],
                )
            except RatchetError as e:
                d = {"decision": "DENY", "reason_code": e.code, "evidence": {"message": e.message}}
                decision = d
            else:
                bridge.expansion_requested(
                    audit, epoch=state["epoch"], policy_hash=state["policy_hash"], result=x
                )
                lc.to(S.APPROVAL_PENDING, epoch=state["epoch"])
                deps.policy_pending = proposed
                return {"decision": decision, "expansion_id": x["expansion_id"]}
        lc.to(S.DENIED, reason_code=d["reason_code"], epoch=state["epoch"])
        n = state.get("denials", 0) + 1
        hist = _push(state, _summary(deps, action or None, "DENY", d["reason_code"]))
        upd: AgentState = {
            **resync,
            "decision": decision,
            "denials": n,
            "history": hist,
            "feedback": f"action denied by policy: {d['reason_code']}",
        }
        if n >= deps.max_denials:
            lc.to(S.FAILED, reason_code="TOO_MANY_DENIALS", epoch=state["epoch"])
            upd.update({"done": True, "outcome": "failed", "outcome_reason": "TOO_MANY_DENIALS"})
        else:
            lc.to(S.PLANNING, epoch=state["epoch"])
        return upd

    def approval_interrupt(state: AgentState) -> AgentState:
        _ = interrupt(
            {
                "expansion_id": state.get("expansion_id"),
                "decision": state.get("decision"),
                "how": "argus approve --task-id ... --expansion-id ... (approval socket)",
            }
        )
        # Whatever the resume payload says, only ratchetd decides.
        st = deps.rust.get_state(state["task_id"])
        if st["epoch"] > state["epoch"]:
            if deps.policy_pending is not None:
                deps.policy = deps.policy_pending
            deps.policy_pending = None
            lc.to(S.NEW_EPOCH, epoch=st["epoch"])
            lc.to(S.POLICY_VALIDATION, epoch=st["epoch"])
            lc.to(S.PLANNING, epoch=st["epoch"])
            audit.append(
                EventType.PRIVILEGE_EXPANSION_APPROVED,
                Component.RATCHET,
                decision="allow",
                reason_code="APPROVED_NEW_EPOCH",
                epoch=st["epoch"],
                policy_hash=st["policy_hash"],
                data={"expansion_id": state.get("expansion_id")},
            )
            return {
                "epoch": st["epoch"],
                "epoch_id": st["epoch_id"],
                "policy_hash": st["policy_hash"],
                "expansion_id": None,
                "feedback": "permission granted in a new epoch",
                "history": _push(state, {"action": state.get("action"), "decision": "APPROVED"}),
            }
        lc.to(S.PLANNING, epoch=state["epoch"])
        return {
            "expansion_id": None,
            "feedback": "permission not granted",
            "history": _push(state, {"action": state.get("action"), "decision": "NOT_APPROVED"}),
        }

    def worker_dispatch(state: AgentState) -> AgentState:
        action = deps.scratch.get("action") or {}
        action_id = f"{state['run_id']}-s{state['step']}"
        # Revalidate against the *current* authoritative policy right before running.
        try:
            d = deps.rust.evaluate_action(
                **_ids(state), run_id=state["run_id"], action_id=action_id, action=action
            )
        except RatchetError as e:
            d = {"decision": "DENY", "reason_code": e.code}
        if d["decision"] != "ALLOW":
            lc.to(S.WORKER_SETUP, epoch=state["epoch"])
            lc.to(S.FAILED, reason_code=f"REVALIDATION_{d['reason_code']}", epoch=state["epoch"])
            return {"done": True, "outcome": "failed", "outcome_reason": "REVALIDATION_DENIED"}
        lc.to(S.WORKER_SETUP, epoch=state["epoch"])
        res = deps.executor.execute(d["dispatch"])
        bridge.worker_result(audit, dispatch=d["dispatch"], result=res)
        lc.to(S.CONFINEMENT_CHECK, epoch=state["epoch"])
        if res.get("status") == "confinement_failed":
            lc.to(S.FAILED, reason_code="CONFINEMENT_INSTALL_FAILED", epoch=state["epoch"])
            return {
                "done": True,
                "outcome": "failed",
                "outcome_reason": "CONFINEMENT_INSTALL_FAILED",
            }
        lc.to(S.EXECUTING, epoch=state["epoch"])
        return {"history": _push(state, _summary(deps, action, "ALLOW", d["reason_code"], res))}

    def result_collector(state: AgentState) -> AgentState:
        if state.get("done"):
            return {}
        lc.to(S.PLANNING, epoch=state["epoch"])
        return {}

    def completion_check(state: AgentState) -> AgentState:
        if state.get("done"):
            return {}
        p = state.get("proposal") or {}
        if p.get("type") == "finish":
            if deps.success_check is None:
                lc.to(S.COMPLETED, reason_code="FINISHED_UNVERIFIED", epoch=state["epoch"])
                return {
                    "done": True,
                    "outcome": "finished_unverified",
                    "outcome_reason": "no independent check configured",
                }
            d, res = execute_gated(state, deps.success_check, f"{state['run_id']}-verify")
            if res is not None and res.get("status") == "confinement_failed":
                return {
                    "done": True,
                    "outcome": "failed",
                    "outcome_reason": "CONFINEMENT_INSTALL_FAILED",
                }
            if res is not None and res.get("status") == "completed" and res.get("exit_code") == 0:
                lc.to(S.COMPLETED, reason_code="VERIFIED", epoch=state["epoch"])
                return {
                    "done": True,
                    "outcome": "completed",
                    "outcome_reason": "independent check passed",
                }
            if res is not None:
                lc.to(S.PLANNING, epoch=state["epoch"])
            summary = _summary(deps, deps.success_check, d["decision"], "VERIFICATION_FAILED", res)
            upd: AgentState = {
                "proposal": None,
                "history": _push(state, summary),
                "feedback": "independent verification failed; the task is not done",
            }
            if state.get("step", 0) >= deps.max_steps:
                lc.to(S.FAILED, reason_code="STEP_LIMIT", epoch=state["epoch"])
                upd.update({"done": True, "outcome": "failed", "outcome_reason": "STEP_LIMIT"})
            return upd
        if state.get("step", 0) >= deps.max_steps:
            lc.to(S.FAILED, reason_code="STEP_LIMIT", epoch=state["epoch"])
            return {"done": True, "outcome": "failed", "outcome_reason": "STEP_LIMIT"}
        return {}

    def finalize(state: AgentState) -> AgentState:
        if state.get("epoch_id") and state.get("outcome") != "rejected":
            with contextlib.suppress(RatchetError, RatchetTransportError):
                deps.rust.close_epoch(
                    task_id=state["task_id"],
                    epoch_id=state["epoch_id"],
                    reason=f"task {state.get('outcome', 'ended')}",
                )
        if not lc.terminal:
            lc.to(
                S.FAILED,
                reason_code=state.get("outcome_reason", "ENDED")[:64].upper().replace(" ", "_"),
                epoch=state.get("epoch"),
            )
        return {"done": True}

    # ------------------------------------------------------------ routes

    def after_validator(
        state: AgentState,
    ) -> Literal["planner", "action_normalizer", "completion_check", "finalize"]:
        if state.get("done"):
            return "finalize"
        p = state.get("proposal")
        if p is None:
            return "planner"
        return "completion_check" if p.get("type") == "finish" else "action_normalizer"

    def after_decision(
        state: AgentState,
    ) -> Literal["worker_dispatch", "approval_interrupt", "planner", "finalize"]:
        if state.get("done"):
            return "finalize"
        kind = (state.get("decision") or {}).get("decision")
        if kind == "ALLOW":
            return "worker_dispatch"
        if kind == "APPROVAL_REQUIRED" and state.get("expansion_id"):
            return "approval_interrupt"
        return "planner"

    def after_completion(state: AgentState) -> Literal["planner", "finalize"]:
        return "finalize" if state.get("done") else "planner"

    def after(state: AgentState) -> Literal["next", "finalize"]:
        return "finalize" if state.get("done") else "next"

    g: StateGraph[AgentState] = StateGraph(AgentState)
    for name, fn in [
        ("intake", intake),
        ("context_loader", context_loader),
        ("planner", planner),
        ("plan_validator", plan_validator),
        ("action_normalizer", action_normalizer),
        ("policy_decision", policy_decision),
        ("approval_interrupt", approval_interrupt),
        ("worker_dispatch", worker_dispatch),
        ("result_collector", result_collector),
        ("completion_check", completion_check),
        ("finalize", finalize),
    ]:
        g.add_node(name, fn)
    g.add_edge(START, "intake")
    g.add_conditional_edges("intake", after, {"next": "context_loader", "finalize": "finalize"})
    g.add_conditional_edges("context_loader", after, {"next": "planner", "finalize": "finalize"})
    g.add_edge("planner", "plan_validator")
    g.add_conditional_edges("plan_validator", after_validator)
    g.add_edge("action_normalizer", "policy_decision")
    g.add_conditional_edges("policy_decision", after_decision)
    g.add_edge("approval_interrupt", "planner")
    g.add_edge("worker_dispatch", "result_collector")
    g.add_edge("result_collector", "completion_check")
    g.add_conditional_edges("completion_check", after_completion)
    g.add_edge("finalize", END)
    return g.compile(checkpointer=checkpointer, interrupt_before=interrupt_before or [])


def _expanded_policy(policy: dict[str, Any], action: dict[str, Any]) -> dict[str, Any]:
    """Controller-side draft of the requested policy.

    ratchetd validates it and computes the delta; nothing here grants anything.
    """
    p = copy.deepcopy(policy)
    fs, cmd = p["filesystem"], p["commands"]
    for key, target in (
        ("add_read_only", fs["read_only"]),
        ("add_read_write", fs["read_write"]),
        ("add_executables", cmd["allowed_executables"]),
        ("add_tools", cmd["allowed_tool_names"]),
    ):
        for item in action.get(key, []):
            if item not in target:
                target.append(item)
    return p


__all__ = ["Deps", "Finish", "build_graph"]
