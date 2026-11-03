"""Run one task end to end and write its evidence bundle.

runs/<run_id>/
  run_metadata.json   arm, planner/model, image, kernel, Docker, Landlock, versions, policy hash
  events.jsonl        hash-chained audit events
  result.json         outcome (independently verified), artifacts with SHA-256
  artifacts/          validated exports only
"""

from __future__ import annotations

import importlib.metadata as md
import json
import platform
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from langgraph.types import Command

from controller import docker_client as dc
from controller.audit.lifecycle import Lifecycle
from controller.audit.redact import Redactor
from controller.audit.writer import AuditWriter
from controller.config import Settings
from controller.executor import Executor
from controller.graph.build import Deps, build_graph
from controller.llm.planner import Planner
from controller.rust_client import RatchetClient
from controller.workspace import ExportRejected, build_stage_archive, safe_extract

InterruptHandler = Callable[[dict[str, Any]], None]
MAX_RESUMES = 4


@dataclass
class TaskSpec:
    task_id: str
    goal: str
    policy: dict[str, Any]
    arm: str = "P1"
    workspace_src: Path | None = None
    include: list[str] | None = None
    success_check: dict[str, Any] | None = None
    max_steps: int = 20
    scenario_id: str | None = None
    export: bool = True

    @classmethod
    def from_file(cls, path: Path, root: Path) -> TaskSpec:
        d = json.loads(path.read_text())
        policy = d["policy"]
        if isinstance(policy, str):  # template name or path
            p = root / "config/templates" / f"{policy}.json"
            policy = json.loads((p if p.exists() else root / policy).read_text())
        policy = {**policy, "task_id": d["task_id"]}
        src = d.get("workspace_src")
        return cls(
            task_id=d["task_id"],
            goal=d["goal"],
            policy=policy,
            arm=d.get("arm", "P1"),
            workspace_src=(path.parent / src).resolve() if src else None,
            include=d.get("include"),
            success_check=d.get("success_check"),
            max_steps=int(d.get("max_steps", 20)),
            scenario_id=d.get("scenario_id"),
        )


@dataclass
class RunResult:
    run_id: str
    run_dir: Path
    outcome: str
    outcome_reason: str
    state: dict[str, Any] = field(default_factory=dict)
    artifacts: list[dict[str, Any]] = field(default_factory=list)


def _versions() -> dict[str, str]:
    out = {"python": platform.python_version()}
    for pkg in ("langgraph", "langchain-core", "langchain-openai", "pydantic"):
        try:
            out[pkg] = md.version(pkg)
        except md.PackageNotFoundError:
            out[pkg] = "absent"
    return out


def run_task(
    spec: TaskSpec,
    *,
    settings: Settings,
    planner: Planner,
    executor: Executor | None = None,
    image: dc.WorkerImage | None = None,
    runs_dir: Path | None = None,
    on_interrupt: InterruptHandler | None = None,
    checkpointer: Any = None,
    executor_wrapper: Callable[[Executor], Executor] | None = None,
) -> RunResult:
    """Run ``spec``. Pass ``executor`` for tests (e.g. MockExecutor); otherwise a
    fresh Docker sandbox is created and destroyed around the run."""
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    run_dir = (runs_dir or settings.runs_dir) / run_id
    run_dir.mkdir(mode=0o700, parents=True)
    rust = RatchetClient(settings.runtime_dir)
    health = rust.health()
    if health["arm"] != spec.arm:
        raise RuntimeError(f"ratchetd runs arm {health['arm']}, task requests {spec.arm}")
    redactor = Redactor(known_secrets=[settings.llm_api_key])
    audit = AuditWriter(
        run_dir / "events.jsonl",
        run_id=run_id,
        task_id=spec.task_id,
        arm=spec.arm,
        scenario_id=spec.scenario_id,
        redactor=redactor,
    )
    sandbox: dc.TaskSandbox | None = None
    metadata: dict[str, Any] = {
        "run_id": run_id,
        "task_id": spec.task_id,
        "scenario_id": spec.scenario_id,
        "arm": spec.arm,
        "planner": planner.name,
        "model": getattr(planner, "model_name", None),
        "kernel": platform.release(),
        "machine": platform.machine(),
        "landlock_abi_host": health.get("landlock_abi"),
        "deployment_hash": health.get("deployment_hash"),
        "versions": _versions(),
        "settings": settings.redacted(),
    }
    try:
        if executor is None:
            image = image or dc.WorkerImage.from_lock()
            sandbox = dc.TaskSandbox(image, spec.task_id)
            sandbox.create()
            if spec.workspace_src is not None:
                sandbox.stage(build_stage_archive(spec.workspace_src, include=spec.include))
            executor = dc.DockerExecutor(sandbox)
            metadata.update(
                image_tag=image.tag,
                image_id=image.image_id,
                docker=dc.ping().get("Server", {}).get("Version"),
            )
        else:
            metadata["executor"] = type(executor).__name__
        if executor_wrapper is not None:
            executor = executor_wrapper(executor)
        deps = Deps(
            rust=rust,
            executor=executor,
            planner=planner,
            audit=audit,
            lifecycle=Lifecycle(audit),
            policy=spec.policy,
            redactor=redactor,
            success_check=spec.success_check,
            max_steps=spec.max_steps,
        )
        if checkpointer is None:
            from langgraph.checkpoint.memory import InMemorySaver

            checkpointer = InMemorySaver()
        graph = build_graph(deps, checkpointer=checkpointer)
        config = {"configurable": {"thread_id": run_id}, "recursion_limit": 500}
        state: dict[str, Any] = graph.invoke(
            {"run_id": run_id, "task_id": spec.task_id, "arm": spec.arm, "goal": spec.goal}, config
        )
        resumes = 0
        while "__interrupt__" in state and resumes < MAX_RESUMES:
            payload = state["__interrupt__"][0].value
            if on_interrupt is not None:
                on_interrupt({**payload, "task_id": spec.task_id})
            resumes += 1
            state = graph.invoke(Command(resume={"check": True}), config)
        metadata["policy_hash_final"] = state.get("policy_hash")
        metadata["epochs"] = state.get("epoch")
        artifacts: list[dict[str, Any]] = []
        if sandbox is not None and spec.export:
            try:
                arts = safe_extract(sandbox.export(), run_dir / "artifacts", strip_prefix="task")
                artifacts = [a.__dict__ for a in arts]
            except ExportRejected as e:
                artifacts = [{"export_rejected": e.reasons[:20]}]
        outcome = state.get("outcome", "failed")
        result = {
            "run_id": run_id,
            "task_id": spec.task_id,
            "outcome": outcome,
            "outcome_reason": state.get("outcome_reason", ""),
            "independently_verified": outcome == "completed",
            "steps": state.get("step", 0),
            "denials": state.get("denials", 0),
            "artifacts": artifacts,
        }
        (run_dir / "result.json").write_text(json.dumps(result, indent=2))
        return RunResult(
            run_id,
            run_dir,
            outcome,
            result["outcome_reason"],
            {k: v for k, v in state.items() if k != "__interrupt__"},
            artifacts,
        )
    finally:
        (run_dir / "run_metadata.json").write_text(json.dumps(metadata, indent=2, default=str))
        audit.close()
        rust.close()
        if sandbox is not None:
            sandbox.destroy()
