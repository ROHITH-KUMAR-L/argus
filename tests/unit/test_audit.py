"""Audit store tests: AUD-001/002/003/004/008/009/010/011/013/014 (non-execution parts)."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import jsonschema
import pytest

from controller.audit import bridge
from controller.audit.events import Component, EventType
from controller.audit.lifecycle import IllegalTransition, Lifecycle, TaskState
from controller.audit.redact import REDACTED, Redactor, bound
from controller.audit.report import aggregate, reconstruct
from controller.audit.writer import AuditIntegrityError, AuditUnavailable, AuditWriter, verify
from controller.rust_client import RatchetError

ROOT = Path(__file__).resolve().parents[2]
H1 = "sha256:" + "1" * 64
H2 = "sha256:" + "2" * 64


def writer(tmp_path: Path, **kw: object) -> AuditWriter:
    return AuditWriter(
        tmp_path / "run-1" / "events.jsonl", run_id="run-1", task_id="task-1", arm="P1", **kw
    )  # type: ignore[arg-type]


def test_aud_001_008_lifecycle_reconstructs(tmp_path: Path) -> None:
    w = writer(tmp_path)
    lc = Lifecycle(w)
    for s in [
        TaskState.POLICY_VALIDATION,
        TaskState.PLANNING,
        TaskState.ACTION_REVIEW,
        TaskState.RATCHETED,
        TaskState.WORKER_SETUP,
        TaskState.CONFINEMENT_CHECK,
        TaskState.EXECUTING,
        TaskState.COMPLETED,
    ]:
        lc.to(s, epoch=1)
    w.close()
    events = verify(w.path)
    r = reconstruct(events)
    assert r.states[0] == "RECEIVED" and r.states[-1] == "COMPLETED"
    assert r.terminal == "COMPLETED"
    assert events[0].event_type == EventType.TASK_STARTED
    assert events[-1].event_type == EventType.TASK_COMPLETED
    assert [e.seq for e in events] == list(range(len(events)))


def test_aud_001_failed_task_has_terminal_event(tmp_path: Path) -> None:
    w = writer(tmp_path)
    lc = Lifecycle(w)
    lc.to(TaskState.POLICY_VALIDATION)
    lc.to(TaskState.PLANNING)
    lc.to(TaskState.FAILED, reason_code="CONFINEMENT_INSTALL_FAILED")
    assert reconstruct(verify(w.path)).terminal == "FAILED"
    with pytest.raises(IllegalTransition):
        lc.to(TaskState.EXECUTING)


def test_illegal_transition_rejected(tmp_path: Path) -> None:
    lc = Lifecycle(writer(tmp_path))
    with pytest.raises(IllegalTransition):
        lc.to(TaskState.EXECUTING)  # cannot skip policy validation / confinement check


def test_aud_002_003_004_ratchet_events(tmp_path: Path) -> None:
    w = writer(tmp_path)
    bridge.policy_rejected(
        w, RatchetError("POLICY_VALIDATION_FAILED", "bad", {"issues": [{"code": "PATH_FORBIDDEN"}]})
    )
    bridge.narrowing(
        w, epoch=1, from_hash=H1, outcome={"accepted": True, "changed": True, "policy_hash": H2}
    )
    delta = [{"kind": "EXECUTABLE_ADDED", "executable": "/usr/bin/gcc"}]
    bridge.narrowing(
        w,
        epoch=1,
        from_hash=H2,
        outcome=RatchetError("PRIVILEGE_EXPANSION_DENIED", "no", {"delta": delta}),
    )
    ev = verify(w.path)
    assert ev[0].event_type == EventType.POLICY_VALIDATION_FAILED
    assert ev[0].data["issues"][0]["code"] == "PATH_FORBIDDEN"
    assert ev[1].data == {"from_hash": H1, "to_hash": H2}
    assert ev[2].event_type == EventType.PRIVILEGE_EXPANSION_DENIED
    assert ev[2].data["delta"] == delta and ev[2].reason_code == "PRIVILEGE_EXPANSION_DENIED"
    assert ev[2].enforcement_layer == "ratchet"


def test_aud_009_every_row_matches_published_schema(tmp_path: Path) -> None:
    schema = json.loads((ROOT / "schemas/event.schema.json").read_text())
    w = writer(tmp_path)
    Lifecycle(w).to(TaskState.POLICY_VALIDATION)
    bridge.action_decision(
        w,
        epoch=1,
        policy_hash=H1,
        action_id="a1",
        action={"type": "read_file", "path": "../x"},
        decision={"decision": "DENY", "reason_code": "PATH_OUTSIDE_WORKSPACE"},
    )
    for line in w.path.read_text().splitlines():
        jsonschema.validate(json.loads(line), schema)


def test_aud_010_secrets_redacted(tmp_path: Path) -> None:
    key = "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    w = writer(tmp_path, redactor=Redactor(known_secrets=["hunter2-canary-value"]))
    w.append(
        EventType.COMMAND_FINISHED,
        Component.WORKER,
        resource=f"/tmp/{key}",
        data={
            "stdout": f"OPENAI_API_KEY={key}\npassword: hunter2-canary-value\n"
            "Authorization: Bearer abcdefghijklmnop123\nAKIAABCDEFGHIJKLMNOP",
            "nested": [{"token": "zzzzzzzzzzzz"}],
        },
    )
    raw = w.path.read_text()
    for secret in (
        key,
        "hunter2-canary-value",
        "abcdefghijklmnop123",
        "AKIAABCDEFGHIJKLMNOP",
        "zzzzzzzzzzzz",
    ):
        assert secret not in raw
    assert REDACTED in raw


def test_aud_011_bounded_output_has_marker() -> None:
    text, truncated = bound("x" * 100_000, 4096)
    assert truncated and "truncated by argus" in text
    assert len(text.encode()) < 4096 + 100
    assert bound("small", 4096) == ("small", False)


def test_large_event_data_is_bounded(tmp_path: Path) -> None:
    w = writer(tmp_path)
    ev = w.append(EventType.COMMAND_FINISHED, Component.WORKER, data={"stdout": "y" * 100_000})
    assert ev.data["truncated"] is True


def test_aud_012_tamper_detected(tmp_path: Path) -> None:
    w = writer(tmp_path)
    Lifecycle(w).to(TaskState.POLICY_VALIDATION)
    w.close()
    lines = w.path.read_text().splitlines()
    tampered = lines[1].replace("POLICY_VALIDATION", "PLANNING")
    w.path.write_text("\n".join([lines[0], tampered, *lines[2:]]) + "\n")
    with pytest.raises(AuditIntegrityError, match="hash"):
        verify(w.path)
    w.path.write_text(lines[1] + "\n")  # dropped first row
    with pytest.raises(AuditIntegrityError):
        verify(w.path)


def test_audit_store_permissions(tmp_path: Path) -> None:
    w = writer(tmp_path)
    w.append(EventType.TASK_STARTED, Component.CONTROLLER, data={"state": "RECEIVED"})
    assert stat.S_IMODE(w.path.stat().st_mode) == 0o600
    assert stat.S_IMODE(w.path.parent.stat().st_mode) == 0o700


def test_resume_extends_verified_chain(tmp_path: Path) -> None:
    w = writer(tmp_path)
    Lifecycle(w)
    w.close()
    w2 = writer(tmp_path)
    w2.append(EventType.ERROR, Component.CONTROLLER, reason_code="TEST")
    assert [e.seq for e in verify(w2.path)] == [0, 1]


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores directory permissions")
def test_aud_013_missing_store_fails_closed(tmp_path: Path) -> None:
    locked = tmp_path / "ro"
    locked.mkdir(mode=0o500)
    with pytest.raises(AuditUnavailable):
        AuditWriter(locked / "sub" / "events.jsonl", run_id="r", task_id="t")
    w = writer(tmp_path)
    os.close(w._fd)  # simulate the store disappearing under the writer
    with pytest.raises(AuditUnavailable):
        w.append(EventType.ERROR, Component.CONTROLLER)


def test_aud_014_metrics_reconcile_with_raw_events(tmp_path: Path) -> None:
    w = writer(tmp_path)
    for i in range(3):
        bridge.action_decision(
            w,
            epoch=1,
            policy_hash=H1,
            action_id=f"a{i}",
            action={"type": "read_file", "path": "x"},
            decision={"decision": "DENY", "reason_code": "PATH_NOT_PERMITTED"},
        )
    bridge.action_decision(
        w,
        epoch=1,
        policy_hash=H1,
        action_id="a9",
        action={"type": "list_files"},
        decision={"decision": "ALLOW", "reason_code": "WITHIN_POLICY"},
    )
    bridge.expansion_requested(
        w, epoch=1, policy_hash=H1, result={"expansion_id": "t:e1:x1", "delta": []}
    )
    events = verify(w.path)
    m = aggregate(events)
    assert m["events"] == len(events) == 5
    assert m["decisions"] == {"allow": 1, "approval_required": 1, "deny": 3}
    assert m["denials_by_layer"] == {"policy_gate": 3}
    assert m["expansions"]["requested"] == 1
    # Recount independently from the raw file.
    rows = [json.loads(x) for x in w.path.read_text().splitlines()]
    assert sum(r.get("decision") == "deny" for r in rows) == m["decisions"]["deny"]
