"""Trusted, append-only, hash-chained JSONL audit writer.

The audit store lives on the controller host (never inside a worker). Every
row is redacted, schema-validated, chained to the previous row and fsynced.
If the store cannot be written the writer raises :class:`AuditUnavailable`,
and protected runs must stop: unaudited protected execution is not allowed
(architecture.md §13, AUD-013).
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import uuid
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from controller.audit.events import Event
from controller.audit.redact import Redactor, bound

GENESIS = "sha256:genesis"
MAX_DATA_BYTES = 16 * 1024


class AuditUnavailable(RuntimeError):
    """The trusted audit store could not be written. Protected runs must stop."""


class AuditIntegrityError(ValueError):
    """An audit file failed schema or hash-chain verification."""


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _row_hash(row_without_hash: dict[str, Any]) -> str:
    body = json.dumps(row_without_hash, sort_keys=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(body.encode()).hexdigest()


class AuditWriter:
    def __init__(
        self,
        path: Path,
        *,
        run_id: str,
        task_id: str,
        redactor: Redactor | None = None,
        arm: str | None = None,
        scenario_id: str | None = None,
    ) -> None:
        self.path = path
        self.run_id = run_id
        self.task_id = task_id
        self.arm = arm
        self.scenario_id = scenario_id
        self.redactor = redactor or Redactor()
        self._seq = 0
        self._prev = GENESIS
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if path.exists():
                # Resume an existing chain only if it verifies.
                rows = verify(path)
                if rows:
                    self._seq = rows[-1].seq + 1
                    self._prev = rows[-1].hash
            fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC, 0o600)
        except AuditIntegrityError:
            raise
        except OSError as exc:
            raise AuditUnavailable(f"cannot open audit store {path}: {exc}") from exc
        self._fd = fd

    def append(self, event_type: str, component: str, **fields: Any) -> Event:
        data = self.redactor.value(fields.pop("data", {}) or {})
        encoded = json.dumps(data, sort_keys=True)
        if len(encoded.encode()) > MAX_DATA_BYTES:
            text, _ = bound(encoded, MAX_DATA_BYTES)
            data = {"truncated": True, "excerpt": text}
        for k in ("resource", "action"):
            if isinstance(fields.get(k), str):
                fields[k] = self.redactor.text(fields[k])
        row: dict[str, Any] = {
            "event_version": "1.0",
            "event_id": uuid.uuid4().hex,
            "seq": self._seq,
            "timestamp_utc": _now(),
            "run_id": self.run_id,
            "task_id": self.task_id,
            "arm": self.arm,
            "scenario_id": self.scenario_id,
            "component": component,
            "event_type": event_type,
            "data": data,
            "prev_hash": self._prev,
            **fields,
        }
        row = {k: v for k, v in row.items() if v is not None}
        row["hash"] = _row_hash(row)
        event = Event.model_validate(row)  # schema check before anything is written
        line = json.dumps(row, sort_keys=True, separators=(",", ":")) + "\n"
        try:
            os.write(self._fd, line.encode())
            os.fsync(self._fd)
        except OSError as exc:
            raise AuditUnavailable(f"audit write failed: {exc}") from exc
        self._seq += 1
        self._prev = row["hash"]
        return event

    def close(self) -> None:
        os.close(self._fd)

    def __enter__(self) -> AuditWriter:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def verify(path: Path) -> list[Event]:
    """Load and verify an audit file: schema, sequence and hash chain."""
    st = path.stat()
    if stat.S_IMODE(st.st_mode) & 0o077:
        raise AuditIntegrityError(f"{path} is accessible by group/other")
    events: list[Event] = []
    prev = GENESIS
    raw = path.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise AuditIntegrityError("truncated final row")
    for i, line in enumerate(raw.decode().splitlines()):
        try:
            row = json.loads(line)
            ev = Event.model_validate(row)
        except ValueError as exc:
            raise AuditIntegrityError(f"row {i}: {exc}") from exc
        if ev.seq != i:
            raise AuditIntegrityError(f"row {i}: sequence gap (seq={ev.seq})")
        if ev.prev_hash != prev:
            raise AuditIntegrityError(f"row {i}: hash chain broken")
        claimed = row.pop("hash")
        if _row_hash(row) != claimed:
            raise AuditIntegrityError(f"row {i}: content does not match its hash")
        prev = claimed
        events.append(ev)
    return events
