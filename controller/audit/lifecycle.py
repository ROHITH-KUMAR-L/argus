"""Task lifecycle state machine (workflow.md §4)."""

from __future__ import annotations

from enum import StrEnum

from controller.audit.events import Component, EventType
from controller.audit.writer import AuditWriter


class TaskState(StrEnum):
    RECEIVED = "RECEIVED"
    POLICY_VALIDATION = "POLICY_VALIDATION"
    REJECTED = "REJECTED"
    PLANNING = "PLANNING"
    ACTION_REVIEW = "ACTION_REVIEW"
    DENIED = "DENIED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    NEW_EPOCH = "NEW_EPOCH"
    RATCHETED = "RATCHETED"
    WORKER_SETUP = "WORKER_SETUP"
    CONFINEMENT_CHECK = "CONFINEMENT_CHECK"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


S = TaskState
TRANSITIONS: dict[TaskState, frozenset[TaskState]] = {
    S.RECEIVED: frozenset({S.POLICY_VALIDATION, S.CANCELLED}),
    S.POLICY_VALIDATION: frozenset({S.REJECTED, S.PLANNING}),
    S.PLANNING: frozenset({S.ACTION_REVIEW, S.COMPLETED, S.FAILED, S.CANCELLED}),
    S.ACTION_REVIEW: frozenset({S.DENIED, S.APPROVAL_PENDING, S.RATCHETED, S.FAILED, S.CANCELLED}),
    S.DENIED: frozenset({S.PLANNING, S.FAILED, S.CANCELLED}),
    S.APPROVAL_PENDING: frozenset({S.PLANNING, S.NEW_EPOCH, S.CANCELLED}),
    S.NEW_EPOCH: frozenset({S.POLICY_VALIDATION}),
    S.RATCHETED: frozenset({S.WORKER_SETUP}),
    S.WORKER_SETUP: frozenset({S.CONFINEMENT_CHECK, S.FAILED}),
    S.CONFINEMENT_CHECK: frozenset({S.FAILED, S.EXECUTING}),
    S.EXECUTING: frozenset({S.ACTION_REVIEW, S.PLANNING, S.COMPLETED, S.FAILED, S.CANCELLED}),
    S.COMPLETED: frozenset(),
    S.FAILED: frozenset(),
    S.CANCELLED: frozenset(),
    S.REJECTED: frozenset(),
}
TERMINAL = frozenset({S.COMPLETED, S.FAILED, S.CANCELLED, S.REJECTED})
_TERMINAL_EVENT = {
    S.COMPLETED: EventType.TASK_COMPLETED,
    S.FAILED: EventType.TASK_FAILED,
    S.CANCELLED: EventType.TASK_CANCELLED,
    S.REJECTED: EventType.TASK_REJECTED,
}


class IllegalTransition(RuntimeError):
    pass


class Lifecycle:
    """Tracks task state and records every transition in the audit store."""

    def __init__(self, audit: AuditWriter) -> None:
        self.audit = audit
        self.state = S.RECEIVED
        audit.append(EventType.TASK_STARTED, Component.CONTROLLER, data={"state": self.state})

    def to(
        self, new: TaskState, *, reason_code: str | None = None, epoch: int | None = None
    ) -> None:
        if new not in TRANSITIONS[self.state]:
            raise IllegalTransition(f"{self.state} -> {new}")
        old, self.state = self.state, new
        self.audit.append(
            EventType.TASK_STATE_CHANGED,
            Component.CONTROLLER,
            reason_code=reason_code,
            epoch=epoch,
            data={"from": old, "to": new},
        )
        if new in TERMINAL:
            self.audit.append(
                _TERMINAL_EVENT[new],
                Component.CONTROLLER,
                reason_code=reason_code,
                epoch=epoch,
                data={"state": new},
            )

    @property
    def terminal(self) -> bool:
        return self.state in TERMINAL
