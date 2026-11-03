"""Deterministic scenario planner with controller-side narrowing steps."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from typing import Any

from controller.llm.planner import PlannerView
from controller.rust_client import RatchetClient, RatchetError


@dataclass
class ScenarioPlanner:
    """Replays a scenario script.

    A step ``{"__controller__": "narrow", "policy": {...}}`` is not a planner
    proposal: it is the *orchestrator* narrowing the task policy between steps
    (workflow.md step 10). It goes through ratchetd like any narrowing and its
    outcome is recorded (P1 applies it; B0/B1 report ARM_STATIC_POLICY).
    """

    script: list[Any]
    rust: RatchetClient
    task_id: str
    name: str = "scenario-mock"
    pos: int = 0
    transitions: list[dict[str, Any]] = field(default_factory=list)

    def propose(self, view: PlannerView) -> Any:
        while self.pos < len(self.script):
            step = self.script[self.pos]
            self.pos += 1
            if isinstance(step, dict) and step.get("__controller__") == "narrow":
                self._narrow(step)
                continue
            return copy.deepcopy(step)
        return {"type": "finish", "summary": "script exhausted"}

    def _narrow(self, step: dict[str, Any]) -> None:
        st = self.rust.get_state(self.task_id)
        pol = {**step["policy"], "task_id": self.task_id}
        try:
            r = self.rust.apply_narrowing(
                task_id=self.task_id,
                epoch_id=st["epoch_id"],
                expected_policy_hash=st["policy_hash"],
                proposed_policy_json=json.dumps(pol),
                reason=step.get("reason", "narrow"),
            )
            self.transitions.append(
                {"accepted": True, "changed": r.get("changed"), "policy_hash": r["policy_hash"]}
            )
        except RatchetError as e:
            self.transitions.append({"accepted": False, "code": e.code})
