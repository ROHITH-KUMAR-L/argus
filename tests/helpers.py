"""Shared helpers for tests that need a real ratchetd and the Docker worker."""

from __future__ import annotations

import copy
import json
import subprocess
import time
from pathlib import Path
from typing import Any

import pytest

from controller import docker_client as dc
from controller.rust_client import RatchetClient

ROOT = Path(__file__).resolve().parents[1]
RATCHETD = ROOT / "target/debug/ratchetd"
PY = "/usr/local/bin/python3"


def worker_image() -> dc.WorkerImage:
    try:
        dc.ping()
        img = dc.WorkerImage.from_lock()
        img.verify_present()
        return img
    except (dc.DockerUnavailable, dc.ConfigDrift) as exc:
        pytest.skip(f"docker/worker image unavailable: {exc}")


def start_ratchetd(tmp: Path, arm: str) -> tuple[subprocess.Popen[bytes], Path]:
    if not RATCHETD.exists():
        pytest.skip("ratchetd not built")
    run = tmp / f"run-{arm}"
    proc = subprocess.Popen(
        [
            str(RATCHETD),
            "--runtime-dir",
            str(run),
            "--state-dir",
            str(tmp / f"state-{arm}"),
            "--arm",
            arm,
        ],
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while not (run / "ratchetd.ready").exists():
        assert proc.poll() is None and time.monotonic() < deadline
        time.sleep(0.02)
    return proc, run


def template(name: str = "python-task") -> dict[str, Any]:
    d: dict[str, Any] = json.loads((ROOT / f"config/templates/{name}.json").read_text())
    return d


class Gate:
    """Open one task on ratchetd and turn actions into ALLOW dispatches."""

    def __init__(self, run: Path, task: str, policy: dict[str, Any]) -> None:
        p = copy.deepcopy(policy)
        p["task_id"] = task
        self.c = RatchetClient(run)
        t = self.c.open_task(task, json.dumps(p))
        self.ctx = {"task_id": task, "epoch_id": t["epoch_id"], "policy_hash": t["policy_hash"]}
        self.n = 0

    def dispatch(self, action: dict[str, Any]) -> dict[str, Any]:
        self.n += 1
        d = self.c.evaluate_action(
            **self.ctx, run_id="run-test", action_id=f"a{self.n}", action=action
        )
        assert d["decision"] == "ALLOW", d
        out: dict[str, Any] = d["dispatch"]
        return out

    def py(self, code: str, timeout: int = 30) -> dict[str, Any]:
        return self.dispatch(
            {
                "type": "run_command",
                "executable": PY,
                "argv": [PY, "-c", code],
                "timeout_seconds": timeout,
            }
        )
