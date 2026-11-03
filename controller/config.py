"""Controller configuration.

Settings come from the process environment, optionally seeded from a local
``.env`` file. Secrets (``LLM_API_KEY``) live only in the controller process;
they are never written to graph state, audit logs or worker requests.

Hosted LangSmith tracing is forced off unless both ``LANGSMITH_TRACING=true``
and ``ARGUS_TRACING_PRIVACY_REVIEWED=true`` are set (STK-013 / STACK-007).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from dotenv import dotenv_values

PlannerKind = Literal["mock", "llm"]
Arm = Literal["B0", "B1", "P1"]

_TRACING_VARS = ("LANGSMITH_TRACING", "LANGCHAIN_TRACING_V2", "LANGCHAIN_TRACING")


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    planner: PlannerKind = "mock"
    arm: Arm = "P1"
    llm_base_url: str = ""
    llm_model: str = ""
    llm_api_key: str = field(default="", repr=False)
    tracing_enabled: bool = False
    runtime_dir: Path = Path("/tmp/argus-runtime")  # noqa: S108 - overridden from XDG_RUNTIME_DIR
    runs_dir: Path = Path("runs")

    def redacted(self) -> dict[str, object]:
        """Safe-to-log view of the settings (never includes the API key)."""
        return {
            "planner": self.planner,
            "arm": self.arm,
            "llm_base_url": self.llm_base_url,
            "llm_model": self.llm_model,
            "llm_api_key_set": bool(self.llm_api_key),
            "tracing_enabled": self.tracing_enabled,
            "runtime_dir": str(self.runtime_dir),
            "runs_dir": str(self.runs_dir),
        }


def enforce_tracing_default_off(env: dict[str, str] | None = None) -> bool:
    """Disable hosted tracing unless explicitly opted in after privacy review.

    Mutates ``os.environ`` (or the supplied mapping) so that LangChain/LangGraph
    never pick up a stray tracing flag. Returns whether tracing remains enabled.
    """
    target = os.environ if env is None else env
    requested = any(_truthy(target.get(v)) for v in _TRACING_VARS)
    reviewed = _truthy(target.get("ARGUS_TRACING_PRIVACY_REVIEWED"))
    if requested and reviewed:
        return True
    for var in _TRACING_VARS:
        target[var] = "false"
    return False


def load_settings(env_file: Path | None = Path(".env")) -> Settings:
    """Load settings from ``.env`` (if present) overlaid by the real environment."""
    merged: dict[str, str] = {}
    if env_file is not None and env_file.is_file():
        merged.update({k: v for k, v in dotenv_values(env_file).items() if v is not None})
    merged.update(os.environ)

    tracing = enforce_tracing_default_off()
    planner = merged.get("PLANNER", "mock").strip() or "mock"
    if planner not in ("mock", "llm"):
        raise ValueError(f"PLANNER must be 'mock' or 'llm', got {planner!r}")
    arm = merged.get("ARGUS_ARM", "P1").strip() or "P1"
    if arm not in ("B0", "B1", "P1"):
        raise ValueError(f"ARGUS_ARM must be B0, B1 or P1, got {arm!r}")

    xdg_runtime = merged.get("XDG_RUNTIME_DIR")
    runtime_dir = Path(
        merged.get("ARGUS_RUNTIME_DIR")
        or (Path(xdg_runtime) / "argus" if xdg_runtime else "/tmp/argus-runtime")  # noqa: S108
    )
    return Settings(
        planner=planner,  # type: ignore[arg-type]
        arm=arm,  # type: ignore[arg-type]
        llm_base_url=merged.get("LLM_BASE_URL", "").strip(),
        llm_model=merged.get("LLM_MODEL", "").strip(),
        llm_api_key=merged.get("LLM_API_KEY", "").strip(),
        tracing_enabled=tracing,
        runtime_dir=runtime_dir,
        runs_dir=Path(merged.get("ARGUS_RUNS_DIR", "runs")),
    )
