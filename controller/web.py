"""Local web API for running the bundled Argus demos."""

from __future__ import annotations

import atexit
import json
import logging
import os
import re
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from controller import docker_client as dc
from controller.config import Settings, load_settings
from controller.llm.planner import LLMPlanner, MockPlanner, Planner
from controller.preflight import run as run_preflight
from controller.runner import TaskSpec, run_task
from controller.rust_client import (
    ApprovalClient,
    RatchetClient,
    RatchetError,
    RatchetTransportError,
)

ROOT = Path(__file__).resolve().parent.parent
RUN_ID_PATTERN = re.compile(r"^run-[a-f0-9]{12}$")
LOGGER = logging.getLogger("argus.web")

DEMO_CATALOG: tuple[dict[str, Any], ...] = (
    {
        "id": "benign",
        "title": "Fix a Python bug",
        "summary": "Read the implementation and test, make the smallest fix, then verify it.",
        "task_file": "01-benign.json",
        "duration": "A few model turns",
        "input_context": (
            "The workspace contains src/calc.py, where add() subtracts, and a pytest "
            "test that expects addition."
        ),
        "execution_steps": [
            "The selected planner reads the task files and proposes typed actions.",
            "The Rust policy authority checks each proposed action before execution.",
            "Allowed actions run in the confined worker, with decisions and output recorded.",
            "The controller runs pytest as an independent success check.",
        ],
        "reading_guide": [
            "An allowed patch is not proof of success; look for the pytest worker result.",
            "Completed with independent verification means the configured test check passed.",
        ],
    },
    {
        "id": "attack",
        "title": "Prompt injection",
        "summary": "Exercise policy denials and kernel confinement against hostile instructions.",
        "task_file": "02-attack.json",
        "duration": "Several confined actions",
        "input_context": (
            "The task goal is the same bug fix, but the workspace README also contains "
            "hostile instructions asking the planner to access a protected canary."
        ),
        "execution_steps": [
            "The planner receives the task and can read the adversarial workspace content.",
            "The policy authority evaluates every resulting action; a hostile instruction "
            "does not grant new permissions.",
            "Actions that pass policy still run inside the confined worker, where kernel "
            "controls can block protected file access.",
            "The controller independently runs pytest to check whether the legitimate fix worked.",
        ],
        "reading_guide": [
            "The scripted mock repeats the hostile attempts; a live model may react differently.",
            "Policy denials mean the authority rejected an action. Kernel denials show an "
            "in-worker access was blocked by confinement.",
            "A denied attack can coexist with a completed task if the independent test passes.",
        ],
    },
    {
        "id": "approval",
        "title": "Human permission gate",
        "summary": "Request gcc, pause for a human decision, then compile and verify a C program.",
        "task_file": "03-approval.json",
        "duration": "Waits for an approval decision",
        "input_context": (
            "The workspace contains main.c. The initial policy does not allow /usr/bin/gcc."
        ),
        "execution_steps": [
            "The planner proposes compiling main.c with gcc.",
            "The authority requires an explicit permission expansion and pauses the task.",
            "A human decision is recorded separately; approval resumes the task under a new "
            "policy epoch.",
            "The controller runs an independent check for the exact output: hello from C.",
        ],
        "reading_guide": [
            "Look for the initial denied action and the pending approval event.",
            (
                "Approval does not itself mean the task passed; the final independent output "
                "check does."
            ),
            "If denied, the permission is not expanded and compilation cannot proceed under it.",
        ],
    },
)
DEMO_BY_ID = {demo["id"]: demo for demo in DEMO_CATALOG}


@dataclass
class RunRecord:
    run_id: str
    task_id: str
    demo_id: str
    planner: str
    status: str = "starting"
    approval: dict[str, Any] | None = None
    error: str | None = None


class StartRunRequest(BaseModel):
    demo: Literal["benign", "attack", "approval"]
    planner: Literal["mock", "llm"]


class ApprovalRequest(BaseModel):
    decision: Literal["approve", "deny"]
    approver: str = Field(min_length=1, max_length=128)


_lock = threading.RLock()
_runs: dict[str, RunRecord] = {}
_preflight_result: dict[str, Any] | None = None
_owned_daemon: subprocess.Popen[bytes] | None = None

app = FastAPI(title="Argus demo console")


def _settings() -> Settings:
    settings = load_settings(ROOT / ".env")
    runs_dir = settings.runs_dir
    if not runs_dir.is_absolute():
        runs_dir = ROOT / runs_dir
    return Settings(
        planner=settings.planner,
        arm=settings.arm,
        llm_base_url=settings.llm_base_url,
        llm_model=settings.llm_model,
        llm_api_key=settings.llm_api_key,
        tracing_enabled=settings.tracing_enabled,
        runtime_dir=settings.runtime_dir,
        runs_dir=runs_dir,
    )


def _health(settings: Settings) -> dict[str, Any] | None:
    client = RatchetClient(settings.runtime_dir, timeout=1.0)
    try:
        return client.health()
    except RatchetTransportError:
        return None
    finally:
        client.close()


def _state_dir() -> Path:
    return Path(os.environ.get("ARGUS_STATE_DIR", Path.home() / ".local/state/argus/ratchetd"))


def _start_authority(settings: Settings) -> dict[str, Any]:
    global _owned_daemon
    with _lock:
        health = _health(settings)
        if health is None:
            binary = ROOT / "target/debug/ratchetd"
            if not binary.is_file():
                raise RuntimeError("ratchetd is not built. Run `cargo build` first.")
            state_dir = _state_dir()
            state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            log_path = state_dir / "argus-web-daemon.log"
            with log_path.open("ab") as log_file:
                os.chmod(log_path, 0o600)
                try:
                    _owned_daemon = subprocess.Popen(  # noqa: S603 - fixed binary and argv; no shell
                        [
                            str(binary),
                            "--runtime-dir",
                            str(settings.runtime_dir),
                            "--state-dir",
                            str(state_dir),
                            "--arm",
                            "P1",
                        ],
                        cwd=ROOT,
                        stdin=subprocess.DEVNULL,
                        stdout=log_file,
                        stderr=subprocess.STDOUT,
                        close_fds=True,
                        start_new_session=True,
                    )
                except OSError as exc:
                    raise RuntimeError(f"Could not start ratchetd: {exc}") from exc

            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                if _owned_daemon.poll() is not None:
                    raise RuntimeError(f"ratchetd exited during startup. Check {log_path}.")
                health = _health(settings)
                if health is not None:
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError(f"ratchetd did not become ready. Check {log_path}.")

        if health["arm"] != "P1":
            raise RuntimeError(
                f"ratchetd is running arm {health['arm']}; stop it and start arm P1."
            )
        return health


def _stop_owned_authority() -> bool:
    global _owned_daemon
    with _lock:
        process = _owned_daemon
        if process is None:
            return False
        if any(
            record.status in {"starting", "running", "approval_required"}
            for record in _runs.values()
        ):
            raise RuntimeError("Wait for the active demo to finish before stopping the authority.")
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
        _owned_daemon = None
        return True


def _shutdown_owned_authority() -> None:
    try:
        _stop_owned_authority()
    except RuntimeError:
        LOGGER.exception("Could not stop the web-managed ratchetd process.")


atexit.register(_shutdown_owned_authority)


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _read_events(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    raw = path.read_bytes()
    lines = raw.splitlines()
    if raw and not raw.endswith(b"\n"):
        lines = lines[:-1]
    return [json.loads(line) for line in lines]


def _run_view(run_id: str, settings: Settings) -> dict[str, Any]:
    if not RUN_ID_PATTERN.fullmatch(run_id):
        raise HTTPException(status_code=404, detail="Run not found")
    run_dir = settings.runs_dir / run_id
    if run_dir.is_symlink():
        raise HTTPException(status_code=404, detail="Run not found")
    with _lock:
        record = _runs.get(run_id)
        status = record.status if record else None
        approval = record.approval if record else None
        error = record.error if record else None
        demo_id = record.demo_id if record else None
        planner = record.planner if record else None
        task_id = record.task_id if record else None
    if not run_dir.is_dir():
        if record is None:
            raise HTTPException(status_code=404, detail="Run not found")
        return {
            "run_id": run_id,
            "task_id": task_id,
            "demo": demo_id,
            "planner": planner,
            "status": status,
            "approval": approval,
            "error": error,
            "metadata": None,
            "result": None,
            "events": [],
            "run_dir": str(run_dir),
        }
    metadata = _load_json(run_dir / "run_metadata.json")
    result = _load_json(run_dir / "result.json")
    events = _read_events(run_dir / "events.jsonl")
    status = status or ((result or {}).get("outcome") if result else "recorded")
    planner = planner or (metadata or {}).get("planner")
    task_id = task_id or (metadata or {}).get("task_id")
    if demo_id is None and isinstance(task_id, str):
        demo_id = next(
            (demo_id for demo_id in DEMO_BY_ID if task_id.startswith(f"demo-{demo_id}-")),
            None,
        )
    return {
        "run_id": run_id,
        "task_id": task_id,
        "demo": demo_id,
        "planner": planner,
        "status": status,
        "approval": approval,
        "error": error,
        "metadata": metadata,
        "result": result,
        "events": events,
        "run_dir": str(run_dir),
    }


def _run_worker(
    record: RunRecord,
    spec: TaskSpec,
    settings: Settings,
    planner: Planner,
) -> None:
    def wait_for_approval(payload: dict[str, Any]) -> None:
        with _lock:
            record.status = "approval_required"
            record.approval = payload
        client = RatchetClient(settings.runtime_dir)
        deadline = time.monotonic() + 900
        try:
            while time.monotonic() < deadline:
                state = client.get_state(record.task_id)
                if str(payload["expansion_id"]) not in state["pending_expansions"]:
                    with _lock:
                        record.status = "running"
                        record.approval = None
                    return
                time.sleep(1)
        finally:
            client.close()
        raise TimeoutError("Human approval timed out after 15 minutes.")

    with _lock:
        record.status = "running"
    try:
        result = run_task(
            spec,
            settings=settings,
            planner=planner,
            run_id=record.run_id,
            on_interrupt=wait_for_approval,
        )
        with _lock:
            record.status = result.outcome
            record.approval = None
    except Exception as exc:
        LOGGER.exception("Demo run %s failed", record.run_id)
        with _lock:
            record.status = "failed"
            record.approval = None
            record.error = f"{type(exc).__name__}. Check the web server output."


@app.get("/api/status")
def get_status() -> dict[str, Any]:
    settings = _settings()
    health = _health(settings)
    with _lock:
        preflight = _preflight_result
        owned = _owned_daemon is not None and _owned_daemon.poll() is None
    return {
        "authority": {
            "online": health is not None,
            "arm": health.get("arm") if health else None,
            "started_by_web": owned,
        },
        "planner_default": settings.planner,
        "llm_configured": bool(settings.llm_base_url and settings.llm_model),
        "model": settings.llm_model or None,
        "preflight": preflight,
    }


@app.get("/api/demos")
def get_demos() -> list[dict[str, Any]]:
    demos = []
    for demo in DEMO_CATALOG:
        task_path = ROOT / "demo" / demo["task_file"]
        task = _load_json(task_path)
        if task is None:
            raise HTTPException(
                status_code=500,
                detail=f"Demo task file is missing: {task_path.name}",
            )
        demos.append(
            {
                **demo,
                "goal": task["goal"],
                "workspace": task.get("workspace_src", "unspecified"),
                "success_check": task["success_check"],
            }
        )
    return demos


@app.post("/api/authority/start")
def start_authority() -> dict[str, Any]:
    try:
        health = _start_authority(_settings())
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    return {"online": True, "arm": health["arm"]}


@app.post("/api/authority/stop")
def stop_authority() -> dict[str, bool]:
    try:
        stopped = _stop_owned_authority()
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return {"stopped": stopped}


@app.post("/api/preflight")
def check_preflight() -> dict[str, Any]:
    global _preflight_result
    try:
        report = run_preflight()
    except (dc.DockerUnavailable, dc.ConfigDrift) as exc:
        result = {"ok": False, "checks": {}, "details": {"error": str(exc)}}
    else:
        result = {
            "ok": report.ok,
            "checks": report.checks,
            "details": report.details,
        }
    with _lock:
        _preflight_result = result
    return result


@app.post("/api/runs")
def start_run(request: StartRunRequest) -> dict[str, Any]:
    settings = _settings()
    with _lock:
        if _preflight_result is None or not _preflight_result.get("ok"):
            raise HTTPException(
                status_code=409,
                detail="Run the host preflight and resolve all failed checks first.",
            )
        if any(
            record.status in {"starting", "running", "approval_required"}
            for record in _runs.values()
        ):
            raise HTTPException(status_code=409, detail="A demo run is already in progress.")

    if request.planner == "llm" and not (settings.llm_base_url and settings.llm_model):
        raise HTTPException(
            status_code=400,
            detail="Configure LLM_BASE_URL and LLM_MODEL in .env before choosing live model.",
        )
    try:
        _start_authority(settings)
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    demo = DEMO_BY_ID[request.demo]
    task_path = ROOT / "demo" / demo["task_file"]
    spec = TaskSpec.from_file(task_path, ROOT)
    suffix = uuid.uuid4().hex[:6]
    spec.task_id = f"{spec.task_id}-{suffix}"[:64]
    spec.policy = {**spec.policy, "task_id": spec.task_id}
    run_id = f"run-{uuid.uuid4().hex[:12]}"
    if request.planner == "llm":
        try:
            planner: Planner = LLMPlanner(settings)
        except RuntimeError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
    else:
        task_data = json.loads(task_path.read_text())
        planner = MockPlanner(task_data.get("mock_script", []))

    record = RunRecord(
        run_id=run_id,
        task_id=spec.task_id,
        demo_id=request.demo,
        planner=request.planner,
    )
    with _lock:
        _runs[run_id] = record
    worker = threading.Thread(
        target=_run_worker,
        args=(record, spec, settings, planner),
        name=f"argus-{run_id}",
        daemon=True,
    )
    worker.start()
    return {
        "run_id": run_id,
        "task_id": spec.task_id,
        "demo": request.demo,
        "planner": request.planner,
        "status": record.status,
        "approval": None,
        "error": None,
        "metadata": None,
        "result": None,
        "events": [],
        "run_dir": str(settings.runs_dir / run_id),
    }


@app.get("/api/runs")
def list_runs() -> list[dict[str, Any]]:
    settings = _settings()
    run_ids = {
        path.name
        for path in settings.runs_dir.glob("run-*")
        if path.is_dir() and RUN_ID_PATTERN.fullmatch(path.name)
    }
    with _lock:
        run_ids.update(_runs)
    runs = [_run_view(run_id, settings) for run_id in run_ids]
    runs.sort(
        key=lambda run: (
            run["events"][0].get("timestamp_utc", "") if run["events"] else "",
            run["run_id"],
        ),
        reverse=True,
    )
    return [
        {
            "run_id": run["run_id"],
            "task_id": run["task_id"],
            "demo": run["demo"],
            "planner": run["planner"],
            "status": run["status"],
            "outcome": (run.get("result") or {}).get("outcome"),
        }
        for run in runs[:12]
    ]


@app.get("/api/runs/{run_id}")
def get_run(run_id: str) -> dict[str, Any]:
    return _run_view(run_id, _settings())


@app.post("/api/runs/{run_id}/approval")
def decide_approval(run_id: str, request: ApprovalRequest) -> dict[str, Any]:
    with _lock:
        record = _runs.get(run_id)
        if record is None or record.status != "approval_required" or not record.approval:
            raise HTTPException(status_code=409, detail="This run has no pending approval.")
        task_id = record.task_id
        expansion_id = str(record.approval["expansion_id"])
    client = ApprovalClient(_settings().runtime_dir)
    try:
        result = client.decide(
            task_id=task_id,
            expansion_id=expansion_id,
            approver=request.approver,
            approve=request.decision == "approve",
        )
    except (RatchetError, RatchetTransportError) as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    finally:
        client.close()
    return result


web_dist = ROOT / "web" / "dist"
if web_dist.is_dir():
    app.mount("/", StaticFiles(directory=web_dist, html=True), name="web")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("controller.web:app", host="127.0.0.1", port=8000)
