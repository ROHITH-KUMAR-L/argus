"""Client for the authoritative Rust ``ratchetd`` daemon (protocol v1).

The controller never decides permissions itself: every method here is a thin
transport to ``ratchetd``. Any error response is raised as
:class:`RatchetError` and must be treated by callers as DENY.
"""

from __future__ import annotations

import json
import socket
import struct
import uuid
from pathlib import Path
from typing import Any

PROTOCOL_VERSION = "1"
MAX_FRAME_BYTES = 1024 * 1024


class RatchetError(RuntimeError):
    """``ratchetd`` returned an error. Never a grant."""

    def __init__(self, code: str, message: str, detail: Any = None) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.detail = detail


class RatchetTransportError(RuntimeError):
    """The daemon could not be reached or spoke an invalid frame."""


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise RatchetTransportError("connection closed by ratchetd")
        buf.extend(chunk)
    return bytes(buf)


class _Conn:
    def __init__(self, path: Path, timeout: float) -> None:
        self.path = path
        self.timeout = timeout
        self._sock: socket.socket | None = None

    def _socket(self) -> socket.socket:
        if self._sock is None:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            try:
                s.connect(str(self.path))
            except OSError as exc:
                s.close()
                raise RatchetTransportError(f"cannot connect to {self.path}: {exc}") from exc
            self._sock = s
        return self._sock

    def call(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        req = {
            "protocol_version": PROTOCOL_VERSION,
            "request_id": uuid.uuid4().hex,
            "method": method,
            "params": params if params is not None else {},
        }
        payload = json.dumps(req).encode()
        if len(payload) > MAX_FRAME_BYTES:
            raise RatchetTransportError("request exceeds frame limit")
        s = self._socket()
        try:
            s.sendall(struct.pack(">I", len(payload)) + payload)
            (length,) = struct.unpack(">I", _recv_exact(s, 4))
            if length > MAX_FRAME_BYTES:
                raise RatchetTransportError("response exceeds frame limit")
            resp = json.loads(_recv_exact(s, length))
        except (OSError, ValueError) as exc:
            self.close()
            raise RatchetTransportError(str(exc)) from exc
        if resp.get("request_id") != req["request_id"]:
            self.close()
            raise RatchetTransportError("response request_id mismatch")
        if not resp.get("ok"):
            err = resp.get("error") or {}
            raise RatchetError(
                str(err.get("code", "INTERNAL")), str(err.get("message", "")), err.get("detail")
            )
        result = resp.get("result")
        if not isinstance(result, dict):
            raise RatchetTransportError("missing result")
        return result

    def close(self) -> None:
        if self._sock is not None:
            self._sock.close()
            self._sock = None


class RatchetClient:
    """Decision-socket client used by the agent graph. It cannot approve."""

    def __init__(self, runtime_dir: Path, timeout: float = 10.0) -> None:
        self._conn = _Conn(runtime_dir / "ratchetd.sock", timeout)

    def close(self) -> None:
        self._conn.close()

    def health(self) -> dict[str, Any]:
        return self._conn.call("health")

    def validate_policy(self, policy_json: str) -> dict[str, Any]:
        return self._conn.call("validate_policy", {"policy_json": policy_json})

    def open_task(self, task_id: str, policy_json: str) -> dict[str, Any]:
        return self._conn.call("open_task", {"task_id": task_id, "policy_json": policy_json})

    def evaluate_action(
        self,
        *,
        task_id: str,
        epoch_id: str,
        policy_hash: str,
        run_id: str,
        action_id: str,
        action: dict[str, Any],
    ) -> dict[str, Any]:
        return self._conn.call(
            "evaluate_action",
            {
                "task_id": task_id,
                "epoch_id": epoch_id,
                "policy_hash": policy_hash,
                "run_id": run_id,
                "action_id": action_id,
                "action": action,
            },
        )

    def apply_narrowing(
        self,
        *,
        task_id: str,
        epoch_id: str,
        expected_policy_hash: str,
        proposed_policy_json: str,
        reason: str,
    ) -> dict[str, Any]:
        return self._conn.call(
            "apply_narrowing",
            {
                "task_id": task_id,
                "epoch_id": epoch_id,
                "expected_policy_hash": expected_policy_hash,
                "proposed_policy_json": proposed_policy_json,
                "reason": reason,
            },
        )

    def request_expansion(
        self,
        *,
        task_id: str,
        epoch_id: str,
        policy_hash: str,
        proposed_policy_json: str,
        reason: str,
    ) -> dict[str, Any]:
        return self._conn.call(
            "request_expansion",
            {
                "task_id": task_id,
                "epoch_id": epoch_id,
                "policy_hash": policy_hash,
                "proposed_policy_json": proposed_policy_json,
                "reason": reason,
            },
        )

    def close_epoch(self, *, task_id: str, epoch_id: str, reason: str) -> dict[str, Any]:
        return self._conn.call(
            "close_epoch", {"task_id": task_id, "epoch_id": epoch_id, "reason": reason}
        )

    def get_state(self, task_id: str) -> dict[str, Any]:
        return self._conn.call("get_state", {"task_id": task_id})


class ApprovalClient:
    """Approval-socket client for the trusted human approval CLI only."""

    def __init__(self, runtime_dir: Path, timeout: float = 10.0) -> None:
        self._conn = _Conn(runtime_dir / "ratchetd-approve.sock", timeout)

    def close(self) -> None:
        self._conn.close()

    def decide(
        self, *, task_id: str, expansion_id: str, approver: str, approve: bool
    ) -> dict[str, Any]:
        return self._conn.call(
            "approve_expansion",
            {
                "task_id": task_id,
                "expansion_id": expansion_id,
                "approver": approver,
                "decision": "approve" if approve else "deny",
            },
        )

    def get_state(self, task_id: str) -> dict[str, Any]:
        return self._conn.call("get_state", {"task_id": task_id})
