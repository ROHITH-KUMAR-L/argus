"""Reconstruct lifecycles and aggregate metrics from raw audit events."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from controller.audit.events import Event, EventType
from controller.audit.writer import verify


@dataclass
class Reconstruction:
    run_id: str
    task_id: str
    states: list[str] = field(default_factory=list)
    terminal: str | None = None
    epochs: list[int] = field(default_factory=list)
    policy_hashes: list[str] = field(default_factory=list)
    transitions: list[dict[str, Any]] = field(default_factory=list)


def reconstruct(events: list[Event]) -> Reconstruction:
    """Rebuild the task lifecycle and policy history from an ordered event stream."""
    if not events:
        raise ValueError("no events")
    r = Reconstruction(run_id=events[0].run_id, task_id=events[0].task_id)
    for ev in events:
        if ev.event_type == EventType.TASK_STARTED:
            r.states.append(ev.data["state"])
        elif ev.event_type == EventType.TASK_STATE_CHANGED:
            if r.states and r.states[-1] != ev.data["from"]:
                raise ValueError(
                    f"seq {ev.seq}: state jumped from {r.states[-1]} to {ev.data['from']}"
                )
            r.states.append(ev.data["to"])
        elif ev.event_type in (
            EventType.TASK_COMPLETED,
            EventType.TASK_FAILED,
            EventType.TASK_CANCELLED,
            EventType.TASK_REJECTED,
        ):
            r.terminal = ev.data["state"]
        if ev.epoch is not None and (not r.epochs or r.epochs[-1] != ev.epoch):
            r.epochs.append(ev.epoch)
        if ev.policy_hash and (not r.policy_hashes or r.policy_hashes[-1] != ev.policy_hash):
            r.policy_hashes.append(ev.policy_hash)
        if ev.event_type in (
            EventType.POLICY_TRANSITION_ACCEPTED,
            EventType.POLICY_TRANSITION_REJECTED,
            EventType.PRIVILEGE_EXPANSION_DENIED,
            EventType.PRIVILEGE_EXPANSION_APPROVED,
        ):
            r.transitions.append({"seq": ev.seq, "type": ev.event_type, **ev.data})
    return r


def aggregate(events: list[Event]) -> dict[str, Any]:
    """Raw counts per event type, decision and enforcement layer (AUD-014)."""
    by_type = Counter(str(e.event_type) for e in events)
    decisions = Counter(e.decision for e in events if e.decision)
    denials_by_layer = Counter(
        e.enforcement_layer for e in events if e.decision == "deny" and e.enforcement_layer
    )
    return {
        "events": len(events),
        "by_type": dict(sorted(by_type.items())),
        "decisions": dict(sorted(decisions.items())),
        "denials_by_layer": dict(sorted(denials_by_layer.items())),
        "expansions": {
            "requested": by_type[EventType.PRIVILEGE_EXPANSION_REQUESTED],
            "denied": by_type[EventType.PRIVILEGE_EXPANSION_DENIED],
            "approved": by_type[EventType.PRIVILEGE_EXPANSION_APPROVED],
        },
        "policy_transitions": {
            "accepted": by_type[EventType.POLICY_TRANSITION_ACCEPTED],
            "rejected": by_type[EventType.POLICY_TRANSITION_REJECTED],
        },
    }


def load(path: Path) -> list[Event]:
    return verify(path)
