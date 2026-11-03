"""LangGraph state. Minimal and redacted: it may be checkpointed (STK-011).

Never put credentials, raw secrets, full file contents or host paths here.
History entries are bounded summaries produced by ``result_collector``.
"""

from __future__ import annotations

from typing import Any, TypedDict


class AgentState(TypedDict, total=False):
    run_id: str
    task_id: str
    arm: str
    goal: str  # redacted, bounded
    epoch: int
    epoch_id: str
    policy_hash: str
    step: int
    invalid_outputs: int
    denials: int
    proposal: dict[str, Any] | None  # validated proposal (dict form)
    action: dict[str, Any] | None  # normalized ratchetd action
    decision: dict[str, Any] | None  # decision without the dispatch payload
    feedback: str | None  # bounded reason returned to the planner
    history: list[dict[str, Any]]
    expansion_id: str | None
    done: bool
    outcome: str  # completed | finished_unverified | failed | ...
    outcome_reason: str
