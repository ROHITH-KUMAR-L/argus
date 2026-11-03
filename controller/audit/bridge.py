"""Map ratchetd results/errors onto audit events (used by the graph nodes)."""

from __future__ import annotations

from typing import Any

from controller.audit.events import Component, EventType
from controller.audit.writer import AuditWriter
from controller.rust_client import RatchetError


def policy_validated(audit: AuditWriter, result: dict[str, Any], epoch: int | None = None) -> None:
    audit.append(
        EventType.POLICY_VALIDATED,
        Component.RATCHET,
        policy_hash=result["policy_hash"],
        policy_version="1.0",
        epoch=epoch,
        data={"warnings": result.get("warnings", [])},
    )


def policy_rejected(audit: AuditWriter, err: RatchetError) -> None:
    issues = (err.detail or {}).get("issues", [])
    audit.append(
        EventType.POLICY_VALIDATION_FAILED,
        Component.RATCHET,
        decision="deny",
        enforcement_layer="policy_gate",
        reason_code=err.code,
        data={"issues": issues[:32]},
    )


def narrowing(
    audit: AuditWriter, *, epoch: int, from_hash: str, outcome: dict[str, Any] | RatchetError
) -> None:
    if isinstance(outcome, RatchetError):
        delta = (outcome.detail or {}).get("delta", [])
        etype = (
            EventType.PRIVILEGE_EXPANSION_DENIED
            if outcome.code == "PRIVILEGE_EXPANSION_DENIED"
            else EventType.POLICY_TRANSITION_REJECTED
        )
        audit.append(
            etype,
            Component.RATCHET,
            decision="deny",
            enforcement_layer="ratchet",
            reason_code=outcome.code,
            epoch=epoch,
            policy_hash=from_hash,
            data={"from_hash": from_hash, "delta": delta},
        )
        return
    audit.append(
        EventType.POLICY_TRANSITION_ACCEPTED,
        Component.RATCHET,
        decision="allow",
        reason_code="POLICY_NARROWED" if outcome.get("changed") else "POLICY_UNCHANGED",
        epoch=epoch,
        policy_hash=outcome["policy_hash"],
        data={"from_hash": from_hash, "to_hash": outcome["policy_hash"]},
    )


def expansion_requested(
    audit: AuditWriter, *, epoch: int, policy_hash: str, result: dict[str, Any]
) -> None:
    audit.append(
        EventType.PRIVILEGE_EXPANSION_REQUESTED,
        Component.RATCHET,
        decision="approval_required",
        reason_code="APPROVAL_PENDING",
        epoch=epoch,
        policy_hash=policy_hash,
        data={"expansion_id": result["expansion_id"], "delta": result["delta"]},
    )


def expansion_decided(
    audit: AuditWriter, *, approver: str, result: dict[str, Any], from_hash: str, epoch: int
) -> None:
    approved = result.get("status") == "APPROVED"
    audit.append(
        EventType.PRIVILEGE_EXPANSION_APPROVED
        if approved
        else EventType.PRIVILEGE_EXPANSION_DENIED,
        Component.RATCHET,
        decision="allow" if approved else "deny",
        enforcement_layer=None if approved else "ratchet",
        reason_code="APPROVED_NEW_EPOCH" if approved else "DENIED_BY_APPROVER",
        epoch=result.get("epoch", epoch),
        policy_hash=result["policy_hash"],
        data={"approver": approver, "from_hash": from_hash, "to_hash": result["policy_hash"]},
    )


def action_decision(
    audit: AuditWriter,
    *,
    epoch: int,
    policy_hash: str,
    action_id: str,
    action: dict[str, Any],
    decision: dict[str, Any],
) -> None:
    kind = decision["decision"]
    etype, d = {
        "ALLOW": (EventType.ACTION_ALLOWED, "allow"),
        "DENY": (EventType.ACTION_DENIED, "deny"),
        "APPROVAL_REQUIRED": (EventType.ACTION_APPROVAL_REQUIRED, "approval_required"),
    }[kind]
    resource = action.get("path") or action.get("executable") or action.get("target")
    audit.append(
        etype,
        Component.POLICY_GATE,
        decision=d,
        enforcement_layer="policy_gate" if kind == "DENY" else None,
        reason_code=decision["reason_code"],
        epoch=epoch,
        policy_hash=policy_hash,
        action_id=action_id,
        action=str(action.get("type", ""))[:64],
        resource=str(resource)[:4096] if resource else None,
        data={"evidence": decision.get("evidence", {})},
    )
