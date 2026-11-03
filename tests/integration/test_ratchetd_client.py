"""Python controller <-> ratchetd end-to-end (requires `cargo build`)."""

from __future__ import annotations

import json
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from controller.rust_client import ApprovalClient, RatchetClient, RatchetError

ROOT = Path(__file__).resolve().parents[2]
RATCHETD = ROOT / "target/debug/ratchetd"

pytestmark = pytest.mark.rust


def _template(task: str) -> dict[str, Any]:
    p = json.loads((ROOT / "config/templates/python-task.json").read_text())
    p["task_id"] = task
    return p


@pytest.fixture
def daemon(tmp_path: Path) -> Iterator[Path]:
    if not RATCHETD.exists():
        pytest.skip("ratchetd not built (run `cargo build`)")
    run = tmp_path / "run"
    proc = subprocess.Popen(
        [str(RATCHETD), "--runtime-dir", str(run), "--state-dir", str(tmp_path / "state")],
        stderr=subprocess.PIPE,
    )
    deadline = time.monotonic() + 10
    while not (run / "ratchetd.ready").exists():
        assert proc.poll() is None, proc.stderr.read() if proc.stderr else ""
        assert time.monotonic() < deadline
        time.sleep(0.02)
    yield run
    proc.kill()
    proc.wait()


def test_full_flow(daemon: Path) -> None:
    c = RatchetClient(daemon)
    assert c.health()["arm"] == "P1"
    t = c.open_task("py-flow", json.dumps(_template("py-flow")))
    ctx = {"task_id": "py-flow", "epoch_id": t["epoch_id"], "policy_hash": t["policy_hash"]}

    allow = c.evaluate_action(
        **ctx, run_id="run-1", action_id="a1", action={"type": "read_file", "path": "src/app.py"}
    )
    assert allow["decision"] == "ALLOW"
    assert allow["dispatch"]["operation"]["path"] == "/workspace/task/src/app.py"

    deny = c.evaluate_action(
        **ctx,
        run_id="run-1",
        action_id="a2",
        action={"type": "read_file", "path": "../../etc/shadow"},
    )
    assert deny["decision"] == "DENY"
    assert deny["reason_code"] == "PATH_OUTSIDE_WORKSPACE"

    # Expansion is denied in-epoch, then approved only via the approval socket.
    wider = _template("py-flow")
    wider["commands"]["allowed_executables"].append("/usr/bin/gcc")
    with pytest.raises(RatchetError) as e:
        c.apply_narrowing(
            **{k: ctx[k] for k in ("task_id", "epoch_id")},
            expected_policy_hash=ctx["policy_hash"],
            proposed_policy_json=json.dumps(wider),
            reason="sneaky",
        )
    assert e.value.code == "PRIVILEGE_EXPANSION_DENIED"
    assert e.value.detail["delta"][0]["kind"] == "EXECUTABLE_ADDED"

    x = c.request_expansion(**ctx, proposed_policy_json=json.dumps(wider), reason="need gcc")
    assert x["status"] == "APPROVAL_PENDING"
    a = ApprovalClient(daemon)
    r = a.decide(task_id="py-flow", expansion_id=x["expansion_id"], approver="alice", approve=True)
    assert r["epoch"] == 2

    # Old epoch is dead.
    with pytest.raises(RatchetError) as e:
        c.evaluate_action(**ctx, run_id="run-1", action_id="a3", action={"type": "list_files"})
    assert e.value.code == "STALE_EPOCH"


def test_decision_client_has_no_approve_method() -> None:
    # STK-008 / RAT-023 at the API level: the graph's client cannot approve.
    assert not any("approve" in name or "decide" in name for name in dir(RatchetClient))


def test_duplicate_keys_reach_rust_and_are_rejected(daemon: Path) -> None:
    c = RatchetClient(daemon)
    text = json.dumps(_template("dup"))[:-1] + ', "task_id": "other"}'
    with pytest.raises(RatchetError) as e:
        c.validate_policy(text)
    assert e.value.code == "POLICY_VALIDATION_FAILED"
    assert e.value.detail["issues"][0]["code"] == "DUPLICATE_FIELD"
