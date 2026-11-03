"""Failure injection and fail-closed behaviour: FAIL-001 … FAIL-014.

Several cases are proven in earlier suites; they are listed here for traceability:
FAIL-001 → test_landlock::test_ll_018_landlock_unavailable_fails_closed
FAIL-002 → test_landlock::test_ll_019_planted_symlink_rule_root_fails_closed
FAIL-003/004 → test_seccomp::test_sec_017_install_failure_fails_closed
FAIL-005 → test_docker::test_dkr_016_docker_unavailable_no_fallback
FAIL-006 → test_docker::test_dkr_014_image_mismatch_refused
FAIL-009 → crates/ratchetd/tests/daemon.rs::rat_019_corruption_fails_closed
FAIL-010 → tests/unit/test_audit.py::test_aud_013_missing_store_fails_closed
FAIL-013 → test_docker::test_res_012_worker_killed_is_not_success
"""

from __future__ import annotations

import json
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

from controller import docker_client as dc
from controller.preflight import PREFLIGHT_LIMITS, evaluate
from controller.rust_client import ApprovalClient, RatchetClient, RatchetTransportError
from controller.workspace import ExportRejected, safe_extract
from tests.helpers import Gate, start_ratchetd, template, worker_image
from tests.unit.test_preflight_eval import GOOD

pytestmark = [pytest.mark.docker, pytest.mark.rust]


@pytest.fixture(scope="module")
def image() -> dc.WorkerImage:
    return worker_image()


@pytest.fixture
def p1(tmp_path: Path) -> Iterator[tuple[subprocess.Popen[bytes], Path]]:
    proc, run = start_ratchetd(tmp_path, "P1")
    yield proc, run
    proc.kill()
    proc.wait()


def test_fail_007_task_volume_missing(image: dc.WorkerImage, p1: tuple) -> None:
    _, run = p1
    sb = dc.TaskSandbox(image, "fail7")
    sb.create()
    g = Gate(run, "fail7", template())
    d = g.py("print('ran')")
    sb.destroy()  # volume and holder gone before dispatch
    before = dc._docker(["ps", "-aq", "--filter", "label=argus.role=worker"]).stdout
    with pytest.raises(dc.ConfigDrift, match="missing"):
        dc.DockerExecutor(sb).execute(d)
    after = dc._docker(["ps", "-aq", "--filter", "label=argus.role=worker"]).stdout
    assert before == after  # no worker created with some other (broader) mount
    vols = dc._docker(["volume", "ls", "-q", "--filter", f"name={sb.volume}"]).stdout.decode()
    assert not vols.strip(), "no substitute (unbounded) volume may be auto-created"


def test_fail_008_policy_authority_unavailable(p1: tuple) -> None:
    proc, run = p1
    c = RatchetClient(run)
    c.health()
    proc.kill()
    proc.wait()
    with pytest.raises(RatchetTransportError):
        RatchetClient(run).open_task("t", json.dumps(template()))
    # Nothing in the controller can produce a dispatch without ratchetd.


def test_fail_011_approval_system_unavailable(p1: tuple) -> None:
    _, run = p1
    p = template()
    p["task_id"] = "fail11"
    c = RatchetClient(run)
    t = c.open_task("fail11", json.dumps(p))
    wider = dict(
        p,
        commands={
            **p["commands"],
            "allowed_executables": p["commands"]["allowed_executables"] + ["/usr/bin/gcc"],
        },
    )
    x = c.request_expansion(
        task_id="fail11",
        epoch_id=t["epoch_id"],
        policy_hash=t["policy_hash"],
        proposed_policy_json=json.dumps(wider),
        reason="need gcc",
    )
    (run / "ratchetd-approve.sock").unlink()  # approval channel down
    with pytest.raises(RatchetTransportError):
        ApprovalClient(run).decide(
            task_id="fail11", expansion_id=x["expansion_id"], approver="alice", approve=True
        )
    st = c.get_state("fail11")
    assert st["epoch"] == 1 and st["policy_hash"] == t["policy_hash"]
    assert x["expansion_id"] in st["pending_expansions"]  # still pending, never granted


def test_fail_012_exporter_error_is_not_success(image: dc.WorkerImage, tmp_path: Path) -> None:
    sb = dc.TaskSandbox(image, "fail12")
    sb.create()
    sb.destroy()
    with pytest.raises(RuntimeError):
        sb.export()  # holder gone: export fails loudly
    import io
    import tarfile

    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        info = tarfile.TarInfo("task/big.bin")
        info.size = 100_000
        t.addfile(info, io.BytesIO(b"x" * 100_000))
    truncated = buf.getvalue()[:20_000]  # stream cut mid-file
    with pytest.raises(ExportRejected, match="corrupt"):
        safe_extract(truncated, tmp_path / "x", strip_prefix="task")
    assert not (tmp_path / "x").exists() or not any((tmp_path / "x").iterdir())


def test_fail_014_resource_controller_unsupported_is_reported() -> None:
    r = json.loads(json.dumps(GOOD))
    r["cgroup"] = {
        "memory_max": "max",
        "memory_swap_max": "max",
        "pids_max": "max",
        "cpu_max": "max 100000",
    }
    checks = evaluate(r, limits=PREFLIGHT_LIMITS)
    for k in ("memory_limit_active", "pids_limit_active", "cpu_limit_active", "swap_disabled"):
        assert checks[k] is False, k
