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


MAX_PROCESS_EVENTS = 64
EXCERPT_BYTES = 4096


def worker_result(audit: AuditWriter, *, dispatch: dict[str, Any], result: dict[str, Any]) -> None:
    """Record one worker result: confinement, process tree, limits and outcome.

    Enforcement-layer attribution: a denial reported by a kernel-confined
    worker is a ``landlock`` denial for filesystem errors; in B0 the same errno
    can only come from the outer container boundary (``docker``).
    """
    from controller.audit.redact import bound

    epoch = dispatch["epoch"]
    common = {
        "epoch": epoch,
        "policy_hash": dispatch["policy_hash"],
        "action_id": dispatch["action_id"],
    }
    conf = result.get("confinement", {})
    kernel = dispatch.get("confinement") == "kernel"
    if result.get("status") == "confinement_failed":
        audit.append(
            EventType.CONFINEMENT_INSTALL_FAILED,
            Component.LAUNCHER,
            decision="deny",
            reason_code="CONFINEMENT_INSTALL_FAILED",
            **common,
            data={"detail": conf.get("detail")},
        )
    elif kernel and conf.get("installed"):
        ll, sc = conf.get("landlock", {}), conf.get("seccomp", {})
        audit.append(
            EventType.CONFINEMENT_INSTALLED,
            Component.LAUNCHER,
            **common,
            data={
                "landlock_kernel_abi": ll.get("kernel_abi"),
                "landlock_handled_abi": ll.get("handled_abi"),
                "handled_fs": ll.get("handled_fs"),
                "rules": ll.get("rules"),
                "scoped": ll.get("scoped"),
                "seccomp_profile": sc.get("profile"),
                "seccomp_mode": sc.get("mode"),
                "seccomp_installed": conf.get("seccomp_installed"),
            },
        )
    tree = result.get("process_tree") or []
    for proc in tree[:MAX_PROCESS_EVENTS]:
        audit.append(
            EventType.PROCESS_SPAWNED,
            Component.SUPERVISOR,
            **common,
            process_id=proc["pid"],
            parent_process_id=proc["ppid"],
            data={"comm": proc["comm"], "first_seen_ms": proc["first_seen_ms"]},
        )
    if tree:
        audit.append(
            EventType.PROCESS_TERMINATED,
            Component.SUPERVISOR,
            **common,
            data={
                "observed": len(tree),
                "events_truncated": len(tree) > MAX_PROCESS_EVENTS
                or bool(result.get("process_tree_truncated")),
                "descendants_killed_at_end": result.get("descendants_killed", 0),
            },
        )
    if result.get("limit_hit"):
        layer = "docker" if result["limit_hit"] == "memory_bytes" else "rlimit"
        audit.append(
            EventType.RESOURCE_LIMIT_HIT,
            Component.SUPERVISOR,
            enforcement_layer=layer,
            reason_code=str(result["limit_hit"]).upper(),
            **common,
            data={"signal": result.get("signal")},
        )
    if result.get("status") == "timeout":
        audit.append(
            EventType.TIMEOUT, Component.SUPERVISOR, reason_code="WALL_TIME_EXCEEDED", **common
        )
    fr = result.get("file_result") or {}
    if fr.get("error_kind") == "permission_denied":
        audit.append(
            EventType.FILESYSTEM_DENIAL,
            Component.WORKER,
            decision="deny",
            enforcement_layer="landlock" if kernel else "docker",
            reason_code="PERMISSION_DENIED",
            resource=dispatch["operation"].get("path"),
            **common,
            data={"message": fr.get("message")},
        )
    stdout, _ = bound(result.get("stdout", ""), EXCERPT_BYTES)
    stderr, _ = bound(result.get("stderr", ""), EXCERPT_BYTES)
    audit.append(
        EventType.WORKER_FINISHED,
        Component.WORKER,
        reason_code=str(result.get("status", "error")).upper(),
        duration_ms=float(result.get("duration_ms") or 0),
        **common,
        data={
            "status": result.get("status"),
            "exit_code": result.get("exit_code"),
            "signal": result.get("signal"),
            "stdout_excerpt": stdout,
            "stderr_excerpt": stderr,
            "stdout_truncated": result.get("stdout_truncated"),
            "resource_usage": result.get("resource_usage"),
        },
    )
