"""B0 / B1 / P1 evaluation harness.

    uv run python -m evaluation.harness --reps 3 --out evaluation/results/<batch>

* One ratchetd per arm (separate state); same image, fixtures, scripts and
  limits in every arm (EVA-001).
* Order is counterbalanced: the arm order rotates per repetition and the
  scenario order is shuffled with a recorded seed.
* Every run gets a fresh sandbox (run_task) and is recorded, including INVALID
  runs (fixture drift, harness error). INVALID runs are excluded from rates by
  one documented rule: the run could not be scored (EVA-011).
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import random
import subprocess
import tempfile
import time
import traceback
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from controller import docker_client as dc
from controller.audit.events import EventType
from controller.audit.writer import verify
from controller.config import Settings
from controller.runner import TaskSpec, run_task
from controller.rust_client import RatchetClient
from evaluation import oracle
from evaluation.planner import ScenarioPlanner
from evaluation.scenario import Scenario, fixture_hash, load_all

ROOT = Path(__file__).resolve().parent.parent
ARMS = ("B0", "B1", "P1")


@dataclass
class Daemon:
    arm: str
    proc: subprocess.Popen[bytes]
    runtime: Path


def start_daemons(base: Path) -> dict[str, Daemon]:
    # Socket paths must fit in sockaddr_un (108 bytes), so the runtime dirs
    # live in a short private dir; daemon *state* stays in the batch dir.
    short = Path(tempfile.mkdtemp(prefix="ae-", dir=os.environ.get("XDG_RUNTIME_DIR")))
    out = {}
    for arm in ARMS:
        run = short / arm
        proc = subprocess.Popen(  # noqa: S603 - fixed trusted binary
            [
                str(ROOT / "target/debug/ratchetd"),
                "--runtime-dir",
                str(run),
                "--state-dir",
                str(base / "daemons" / arm / "state"),
                "--arm",
                arm,
            ],
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while not (run / "ratchetd.ready").exists():
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"ratchetd for {arm} failed to start")
            time.sleep(0.05)
        out[arm] = Daemon(arm, proc, run)
    return out


def _approval_never(_: dict[str, Any]) -> None:
    """No human approves anything during the batch (documented condition)."""


def run_one(
    sc: Scenario, arm: str, rep: int, daemon: Daemon, out: Path, image: dc.WorkerImage
) -> dict[str, Any]:
    fixture_dir = ROOT / "evaluation/fixtures" / sc.fixture
    task_id = f"{sc.scenario_id}-{arm}-r{rep}".lower()
    base = {
        "scenario_id": sc.scenario_id,
        "scenario_version": sc.scenario_version,
        "category": sc.category,
        "arm": arm,
        "rep": rep,
        "task_id": task_id,
        "fixture_hash": sc.fixture_sha256,
        "image_digest": image.image_id,
        "kernel_version": platform.release(),
    }
    actual = fixture_hash(fixture_dir)
    if actual != sc.fixture_sha256:
        return {
            **base,
            "status": "INVALID",
            "invalid_reason": "fixture hash mismatch",
            "fixture_hash_actual": actual,
        }
    rust = RatchetClient(daemon.runtime)
    planner = ScenarioPlanner(sc.planner_script, rust, task_id)
    recorder: list[oracle.RecordingExecutor] = []

    def wrap(ex: Any) -> Any:
        r = oracle.RecordingExecutor(ex)
        recorder.append(r)
        return r

    spec = TaskSpec(
        task_id=task_id,
        goal=sc.goal,
        policy={**sc.policy, "task_id": task_id},
        arm=arm,
        workspace_src=fixture_dir,
        success_check=sc.success_check,
        max_steps=40,
        scenario_id=sc.scenario_id,
    )
    t0 = time.monotonic()
    try:
        res = run_task(
            spec,
            settings=Settings(runtime_dir=daemon.runtime, runs_dir=out / "runs", arm=arm),  # type: ignore[arg-type]
            planner=planner,
            image=image,
            on_interrupt=_approval_never,
            executor_wrapper=wrap,
        )
    except Exception as exc:  # noqa: BLE001 - recorded as INVALID, never dropped
        return {
            **base,
            "status": "INVALID",
            "invalid_reason": f"harness error: {exc!r}",
            "traceback": traceback.format_exc()[-2000:],
        }
    wall_ms = (time.monotonic() - t0) * 1000
    records = recorder[0].records if recorder else []
    events = verify(res.run_dir / "events.jsonl")
    eff = oracle.effects(sc.attack_effects, records, res.run_dir / "artifacts", fixture_dir)
    n_proposals = oracle.proposals(events)
    worker_ms = [float(r["result"].get("duration_ms") or 0) for r in records]
    peak_mem = (
        max((r["result"].get("resource_usage", {}).get("peak_memory_bytes") or 0) for r in records)
        if records
        else 0
    )
    requested = sum(e.event_type == EventType.PRIVILEGE_EXPANSION_REQUESTED for e in events)
    conf = [r["result"].get("confinement", {}) for r in records]
    decisive = [
        e.event_id
        for e in events
        if e.event_type
        in (
            EventType.ACTION_DENIED,
            EventType.FILESYSTEM_DENIAL,
            EventType.CONFINEMENT_INSTALLED,
            EventType.TASK_COMPLETED,
            EventType.TASK_FAILED,
        )
    ][:50]
    if sc.is_attack:
        legit_ok = None
    elif sc.legit_expected == "blocked_with_request":
        legit_ok = requested > 0
    else:
        legit_ok = res.outcome == "completed"
    return {
        **base,
        "status": "SCORED",
        "run_id": res.run_id,
        "run_dir": str(res.run_dir),
        "outcome": res.outcome,
        "outcome_reason": res.outcome_reason,
        "policy_hash": events[0].policy_hash
        if events and events[0].policy_hash
        else next((e.policy_hash for e in events if e.policy_hash), None),
        "landlock_abi": next((c.get("landlock_abi") for c in conf if c.get("landlock_abi")), None),
        "seccomp_profile": next(
            (c.get("seccomp_profile") for c in conf if c.get("seccomp_profile")), None
        ),
        "confinement_modes": sorted({str(c.get("mode")) for c in conf}),
        "attempted": n_proposals > 0,
        "proposals": n_proposals,
        "policy_denials": oracle.policy_denials(events),
        "kernel_denials": oracle.kernel_denials(records),
        "effects": eff,
        "unauthorized_effect_completed": any(eff.values()) if sc.is_attack else None,
        "legit_success": legit_ok,
        "expansions_requested": requested,
        "transitions": planner.transitions,
        "wall_ms": round(wall_ms, 1),
        "worker_ms_total": round(sum(worker_ms), 1),
        "worker_actions": len(records),
        "peak_memory_bytes": peak_mem,
        "evidence": [f"{res.run_dir.name}/events.jsonl#{i}" for i in decisive],
    }


def environment(image: dc.WorkerImage) -> dict[str, Any]:
    ver = dc.ping()
    return {
        "kernel": platform.release(),
        "machine": platform.machine(),
        "docker": ver.get("Server", {}).get("Version"),
        "image_tag": image.tag,
        "image_id": image.image_id,
        "python": platform.python_version(),
    }


def run_batch(
    out: Path, reps: int = 3, seed: int = 20261103, only: list[str] | None = None
) -> Path:
    out.mkdir(parents=True, exist_ok=True)
    scenarios = [
        s for s in load_all(ROOT / "evaluation/scenarios") if not only or s.scenario_id in only
    ]
    image = dc.WorkerImage.from_lock()
    image.verify_present()
    (out / "environment.json").write_text(json.dumps(environment(image), indent=2))
    (out / "scenarios.json").write_text(json.dumps([s.model_dump() for s in scenarios], indent=1))
    rng = random.Random(seed)
    schedule = []
    for rep in range(reps):
        arms = ARMS[rep % 3 :] + ARMS[: rep % 3]  # rotate arm order
        order = scenarios[:]
        rng.shuffle(order)
        schedule += [(sc, arm, rep) for sc in order for arm in arms]
    (out / "schedule.json").write_text(
        json.dumps(
            {"seed": seed, "reps": reps, "runs": [[s.scenario_id, a, r] for s, a, r in schedule]}
        )
    )
    daemons = start_daemons(out)
    try:
        with open(out / "runs.jsonl", "w") as fh:
            for i, (sc, arm, rep) in enumerate(schedule):
                rec = run_one(sc, arm, rep, daemons[arm], out, image)
                fh.write(json.dumps(rec, default=str) + "\n")
                fh.flush()
                print(
                    f"[{i + 1}/{len(schedule)}] {sc.scenario_id} {arm} r{rep}: "
                    f"{rec['status']} {rec.get('outcome', rec.get('invalid_reason'))}",
                    flush=True,
                )
    finally:
        for d in daemons.values():
            d.proc.kill()
            d.proc.wait()
    from evaluation import metrics, report

    m = metrics.compute([json.loads(x) for x in (out / "runs.jsonl").read_text().splitlines()])
    (out / "metrics.json").write_text(json.dumps(m, indent=2))
    report.write(out, m)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--seed", type=int, default=20261103)
    ap.add_argument("--only", nargs="*")
    a = ap.parse_args()
    run_batch(a.out, a.reps, a.seed, a.only)


if __name__ == "__main__":
    main()
