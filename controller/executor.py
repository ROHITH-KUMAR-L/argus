"""Executor interface between the graph and a disposable worker.

``DockerExecutor`` (Phase 5) runs ``argus-worker`` in a fresh hardened
container per dispatch. ``MockExecutor`` emulates the worker result contract
over an in-memory workspace, so graph routing tests run without Docker. It is
never selected implicitly for protected runs.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol


class Executor(Protocol):
    def execute(self, dispatch: dict[str, Any]) -> dict[str, Any]:
        """Run one ratchetd-approved WorkerRequest and return the WorkerResult."""
        ...


ExecHandler = Callable[[list[str]], tuple[int, str, str]]


class MockExecutor:
    """In-memory stand-in for the worker (tests only; reports confinement mode 'mock')."""

    is_mock = True

    def __init__(
        self, files: dict[str, str] | None = None, exec_handler: ExecHandler | None = None
    ) -> None:
        self.files: dict[str, str] = dict(files or {})
        self.exec_handler = exec_handler or (lambda argv: (0, "", ""))
        self.calls: list[dict[str, Any]] = []

    def execute(self, dispatch: dict[str, Any]) -> dict[str, Any]:
        self.calls.append(dispatch)
        op = dispatch["operation"]
        base: dict[str, Any] = {
            "result_version": "1.0",
            "run_id": dispatch["run_id"],
            "task_id": dispatch["task_id"],
            "epoch": dispatch["epoch"],
            "action_id": dispatch["action_id"],
            "policy_hash": dispatch["policy_hash"],
            "arm": dispatch["arm"],
            "exit_code": None,
            "signal": None,
            "stdout": "",
            "stderr": "",
            "stdout_truncated": False,
            "stderr_truncated": False,
            "duration_ms": 0,
            "resource_usage": {
                "peak_memory_bytes": 0,
                "cpu_seconds": 0.0,
                "peak_process_count": None,
            },
            "limit_hit": None,
            "descendants_killed": 0,
            "confinement": {
                "mode": "mock",
                "installed": False,
                "landlock_abi": None,
                "seccomp_profile": None,
                "no_new_privs": False,
            },
        }
        kind = op["type"]
        if kind == "exec":
            code, out, err = self.exec_handler(op["argv"])
            return {
                **base,
                "status": "completed" if code == 0 else "failed",
                "exit_code": code,
                "stdout": out,
                "stderr": err,
            }
        path = op["path"]
        if kind == "write_file":
            self.files[path] = op["content"]
            fr: dict[str, Any] = {"ok": True, "data": {"bytes_written": len(op["content"])}}
        elif kind == "read_file":
            if path in self.files:
                text = self.files[path][op["offset"] : op["offset"] + op["length"]]
                fr = {"ok": True, "data": {"content": text, "size": len(self.files[path])}}
            else:
                fr = {"ok": False, "error_kind": "not_found", "message": path}
        elif kind == "list_files":
            prefix = path.rstrip("/") + "/"
            entries = sorted(p[len(prefix) :] for p in self.files if p.startswith(prefix))
            fr = {
                "ok": True,
                "data": {
                    "entries": [{"path": e, "type": "file"} for e in entries],
                    "truncated": False,
                },
            }
        else:
            fr = {"ok": False, "error_kind": "unsupported", "message": f"mock cannot {kind}"}
        return {**base, "status": "completed" if fr["ok"] else "failed", "file_result": fr}
