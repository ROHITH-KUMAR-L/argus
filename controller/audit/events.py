"""Versioned audit event model (schema ``schemas/event.schema.json``)."""

from __future__ import annotations

from enum import StrEnum
from typing import Any, Final, Literal

from pydantic import BaseModel, ConfigDict, Field

EVENT_VERSION: Final = "1.0"
ID_PATTERN = r"^[A-Za-z0-9._:-]{1,64}$"
HASH_PATTERN = r"^sha256:([0-9a-f]{64}|genesis)$"


class EventType(StrEnum):
    TASK_STARTED = "TASK_STARTED"
    TASK_STATE_CHANGED = "TASK_STATE_CHANGED"
    TASK_COMPLETED = "TASK_COMPLETED"
    TASK_FAILED = "TASK_FAILED"
    TASK_CANCELLED = "TASK_CANCELLED"
    TASK_REJECTED = "TASK_REJECTED"
    POLICY_VALIDATED = "POLICY_VALIDATED"
    POLICY_VALIDATION_FAILED = "POLICY_VALIDATION_FAILED"
    POLICY_TRANSITION_ACCEPTED = "POLICY_TRANSITION_ACCEPTED"
    POLICY_TRANSITION_REJECTED = "POLICY_TRANSITION_REJECTED"
    PRIVILEGE_EXPANSION_REQUESTED = "PRIVILEGE_EXPANSION_REQUESTED"
    PRIVILEGE_EXPANSION_DENIED = "PRIVILEGE_EXPANSION_DENIED"
    PRIVILEGE_EXPANSION_APPROVED = "PRIVILEGE_EXPANSION_APPROVED"
    ACTION_PROPOSED = "ACTION_PROPOSED"
    ACTION_ALLOWED = "ACTION_ALLOWED"
    ACTION_DENIED = "ACTION_DENIED"
    ACTION_APPROVAL_REQUIRED = "ACTION_APPROVAL_REQUIRED"
    WORKER_STARTED = "WORKER_STARTED"
    WORKER_FINISHED = "WORKER_FINISHED"
    CONFINEMENT_INSTALLED = "CONFINEMENT_INSTALLED"
    CONFINEMENT_INSTALL_FAILED = "CONFINEMENT_INSTALL_FAILED"
    COMMAND_STARTED = "COMMAND_STARTED"
    COMMAND_FINISHED = "COMMAND_FINISHED"
    PROCESS_SPAWNED = "PROCESS_SPAWNED"
    PROCESS_TERMINATED = "PROCESS_TERMINATED"
    RESOURCE_LIMIT_HIT = "RESOURCE_LIMIT_HIT"
    FILESYSTEM_DENIAL = "FILESYSTEM_DENIAL"
    SYSCALL_DENIAL = "SYSCALL_DENIAL"
    TIMEOUT = "TIMEOUT"
    CANCELLATION = "CANCELLATION"
    EXPORT_ACCEPTED = "EXPORT_ACCEPTED"
    EXPORT_REJECTED = "EXPORT_REJECTED"
    EXPERIMENT_RESULT = "EXPERIMENT_RESULT"
    ERROR = "ERROR"


class Component(StrEnum):
    CONTROLLER = "controller"
    GRAPH = "graph"
    POLICY_GATE = "policy_gate"
    RATCHET = "ratchet"
    SUPERVISOR = "supervisor"
    WORKER = "worker"
    LAUNCHER = "launcher"
    EVALUATION = "evaluation"


# Which layer produced a denial. A policy-gate denial is never a kernel denial.
EnforcementLayer = Literal[
    "policy_gate", "ratchet", "landlock", "seccomp", "docker", "rlimit", "none"
]


class Event(BaseModel):
    """One audit row. ``seq``, ``prev_hash`` and ``hash`` are set by the writer."""

    model_config = ConfigDict(extra="forbid", frozen=True, use_enum_values=True)

    event_version: Literal["1.0"] = EVENT_VERSION
    event_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    seq: int = Field(ge=0)
    timestamp_utc: str = Field(pattern=r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
    run_id: str = Field(pattern=ID_PATTERN)
    task_id: str = Field(pattern=ID_PATTERN)
    epoch: int | None = Field(default=None, ge=1)
    scenario_id: str | None = Field(default=None, pattern=ID_PATTERN)
    arm: Literal["B0", "B1", "P1"] | None = None
    component: Component
    event_type: EventType
    decision: Literal["allow", "deny", "approval_required"] | None = None
    enforcement_layer: EnforcementLayer | None = None
    reason_code: str | None = Field(default=None, pattern=r"^[A-Z0-9_]{1,64}$")
    policy_version: str | None = None
    policy_hash: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    action_id: str | None = Field(default=None, pattern=ID_PATTERN)
    action: str | None = Field(default=None, max_length=64)
    resource: str | None = Field(default=None, max_length=4096)
    process_id: int | None = Field(default=None, ge=0)
    parent_process_id: int | None = Field(default=None, ge=0)
    duration_ms: float | None = Field(default=None, ge=0)
    data: dict[str, Any] = Field(default_factory=dict)
    prev_hash: str = Field(pattern=HASH_PATTERN)
    hash: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
