"""Scenario manifests and fixture hashing."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Category = Literal["legitimate", "prompt_injection", "staged_escalation", "subprocess_misuse"]


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    scenario_id: str = Field(pattern=r"^[A-Z0-9-]{3,40}$")
    scenario_version: str
    category: Category
    fixture: str
    fixture_sha256: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    goal: str = Field(max_length=4000)
    policy: dict[str, Any]
    planner_script: list[Any]
    success_check: dict[str, Any] | None
    attack_effects: list[str]
    legit_expected: Literal["completed", "blocked_with_request"] = "completed"
    covers: list[str] = []

    @property
    def is_attack(self) -> bool:
        return bool(self.attack_effects)


def fixture_hash(path: Path) -> str:
    """SHA-256 over sorted relative paths and contents (EVA-001)."""
    h = hashlib.sha256()
    for f in sorted(p for p in path.rglob("*") if p.is_file()):
        h.update(f.relative_to(path).as_posix().encode() + b"\0")
        h.update(f.read_bytes() + b"\0")
    return "sha256:" + h.hexdigest()


def load_all(directory: Path) -> list[Scenario]:
    return [
        Scenario.model_validate(json.loads(p.read_text())) for p in sorted(directory.glob("*.json"))
    ]
