"""Narrow, hard-coded Docker adapter for disposable workers.

The controller drives the Docker CLI with argv arrays (never a shell). Nothing
here is planner-controllable: the planner cannot choose images, flags, mounts,
capabilities or networks. Every worker container gets the same hardened
configuration, derived only from the validated policy limits, and that
configuration is re-checked against ``docker inspect`` before the container
is started (DKR-017). If Docker is unavailable or the configuration drifts,
execution stops and never falls back to the host (DKR-016).

Workspace (D8, revised): each task gets a **tmpfs-backed named volume** with a
size cap, kept mounted by a minimal "holder" container (``sleep infinity``,
no network, no capabilities). Files are staged in and exported out as tar
streams through the holder with ``docker cp``. No host directory is ever
bind-mounted into a worker.
"""

from __future__ import annotations

import json
import re
import subprocess
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

WORKER_USER = "10001:10001"
WORKSPACE = "/workspace/task"
TMP_SPEC = "rw,nosuid,nodev,noexec,size=64m"
DEFAULT_WORKSPACE_BYTES = 512 * 1024 * 1024
MEMORY_OVERHEAD = 64 * 1024 * 1024  # worker entrypoint + file-op child
PIDS_OVERHEAD = 4
CLI_TIMEOUT = 60
LOCK_FILE = Path(__file__).resolve().parent.parent / "config" / "worker-image.lock"

_NAME_RE = re.compile(r"[^a-zA-Z0-9_.-]")


class DockerUnavailable(RuntimeError):
    """Docker cannot be used. Protected execution must not fall back to the host."""


class ConfigDrift(RuntimeError):
    """A worker container's effective configuration violates the hardening contract."""

    def __init__(self, problems: list[str]) -> None:
        super().__init__("; ".join(problems))
        self.problems = problems


def _docker(
    args: list[str], *, input: bytes | None = None, timeout: float = CLI_TIMEOUT, check: bool = True
) -> subprocess.CompletedProcess[bytes]:
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            ["docker", *args], input=input, capture_output=True, timeout=timeout, check=False
        )
    except FileNotFoundError as exc:
        raise DockerUnavailable("docker CLI not found") from exc
    if check and proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        if "Cannot connect to the Docker daemon" in err or "connect: " in err:
            raise DockerUnavailable(err)
        raise RuntimeError(f"docker {args[0]} failed: {err}")
    return proc


def _safe_name(*parts: str) -> str:
    return _NAME_RE.sub("-", "-".join(parts))[:100]


@dataclass(frozen=True)
class WorkerImage:
    tag: str
    image_id: str

    @classmethod
    def from_lock(cls, path: Path = LOCK_FILE) -> WorkerImage:
        if not path.exists():
            raise DockerUnavailable(f"{path} missing: run scripts/build_worker_image.sh")
        d = json.loads(path.read_text())
        return cls(tag=d["tag"], image_id=d["image_id"])

    def verify_present(self) -> None:
        proc = _docker(["image", "inspect", "--format", "{{.Id}}", self.tag], check=False)
        if proc.returncode != 0:
            raise DockerUnavailable(f"worker image {self.tag} not present")
        actual = proc.stdout.decode().strip()
        if actual != self.image_id:
            raise ConfigDrift([f"image {self.tag} is {actual}, expected pinned {self.image_id}"])


def ping() -> dict[str, Any]:
    """Raise DockerUnavailable unless the daemon answers."""
    proc = _docker(["version", "--format", "{{json .}}"], check=False, timeout=15)
    if proc.returncode != 0:
        raise DockerUnavailable(
            proc.stderr.decode(errors="replace").strip() or "daemon unreachable"
        )
    data: dict[str, Any] = json.loads(proc.stdout)
    return data


def worker_flags(limits: dict[str, int], volume: str) -> list[str]:
    """The complete, fixed hardening for a worker container."""
    mem = int(limits["memory_bytes"]) + MEMORY_OVERHEAD
    nofile = int(limits["open_files"]) + 16
    return [
        "--user",
        WORKER_USER,
        "--read-only",
        "--network",
        "none",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--ipc",
        "private",
        "--pids-limit",
        str(int(limits["process_count"]) + PIDS_OVERHEAD),
        "--memory",
        str(mem),
        "--memory-swap",
        str(mem),
        "--cpus",
        "1",
        "--ulimit",
        "core=0:0",
        "--ulimit",
        f"nofile={nofile}:{nofile}",
        "--tmpfs",
        f"/tmp:{TMP_SPEC}",
        "--mount",
        f"type=volume,source={volume},target={WORKSPACE}",
        "--hostname",
        "worker",
        "--label",
        "argus.role=worker",
        "--stop-timeout",
        "1",
    ]


def check_config(inspect: dict[str, Any], *, image_id: str, volume: str) -> list[str]:
    """Compare ``docker inspect`` output with the hardening contract (DKR-017)."""
    p: list[str] = []
    cfg, host = inspect.get("Config", {}), inspect.get("HostConfig", {})
    if cfg.get("User") != WORKER_USER:
        p.append(f"user is {cfg.get('User')!r}")
    if inspect.get("Image") != image_id:
        p.append("image id is not the pinned worker image")
    if host.get("Privileged"):
        p.append("privileged mode")
    if not host.get("ReadonlyRootfs"):
        p.append("root filesystem is writable")
    if host.get("NetworkMode") != "none":
        p.append(f"network mode {host.get('NetworkMode')!r}")
    if [c.upper() for c in host.get("CapDrop") or []] not in (["ALL"], ["CAP_ALL"]):
        p.append(f"cap_drop is {host.get('CapDrop')!r}")
    if host.get("CapAdd"):
        p.append(f"cap_add is {host.get('CapAdd')!r}")
    if not any(str(o).startswith("no-new-privileges") for o in host.get("SecurityOpt") or []):
        p.append("no-new-privileges missing")
    if any(
        "seccomp=unconfined" in str(o) or "apparmor=unconfined" in str(o)
        for o in host.get("SecurityOpt") or []
    ):
        p.append("security profile disabled")
    for ns in ("PidMode", "IpcMode", "UTSMode", "UsernsMode", "CgroupnsMode"):
        if str(host.get(ns, "")).startswith("host"):
            p.append(f"{ns} shares a host namespace")
    if host.get("Binds"):
        p.append(f"bind mounts present: {host.get('Binds')}")
    if host.get("Devices"):
        p.append("devices mapped into worker")
    if not host.get("PidsLimit") or host["PidsLimit"] <= 0:
        p.append("no pids limit")
    if not host.get("Memory"):
        p.append("no memory limit")
    if host.get("MemorySwap") not in (host.get("Memory"),):
        p.append("swap not capped to memory limit")
    if not host.get("NanoCpus"):
        p.append("no cpu limit")
    if set((host.get("Tmpfs") or {}).keys()) != {"/tmp"}:
        p.append(f"unexpected tmpfs set {host.get('Tmpfs')}")
    mounts = inspect.get("Mounts") or []
    allowed = [
        m
        for m in mounts
        if m.get("Type") == "volume"
        and m.get("Name") == volume
        and m.get("Destination") == WORKSPACE
    ]
    if len(mounts) != 1 or len(allowed) != 1:
        p.append(f"mounts must be exactly the task volume: {mounts}")
    for m in mounts:
        if "docker.sock" in str(m.get("Source", "")) + str(m.get("Destination", "")):
            p.append("docker socket mounted")
    return p


class TaskSandbox:
    """Bounded tmpfs workspace volume for one task, kept alive by a holder container."""

    def __init__(
        self, image: WorkerImage, task_id: str, *, size_bytes: int = DEFAULT_WORKSPACE_BYTES
    ) -> None:
        self.image = image
        suffix = uuid.uuid4().hex[:8]
        self.volume = _safe_name("argus-ws", task_id, suffix)
        self.holder = _safe_name("argus-hold", task_id, suffix)
        self.size_bytes = size_bytes
        self._created = False

    def create(self) -> None:
        ping()
        self.image.verify_present()
        opts = f"size={self.size_bytes},uid=10001,gid=10001,mode=0755,nosuid,nodev"
        _docker(
            [
                "volume",
                "create",
                "--driver",
                "local",
                "--opt",
                "type=tmpfs",
                "--opt",
                "device=tmpfs",
                "--opt",
                f"o={opts}",
                "--label",
                "argus.role=workspace",
                self.volume,
            ]
        )
        self._created = True
        _docker(
            [
                "run",
                "-d",
                "--name",
                self.holder,
                "--user",
                WORKER_USER,
                "--read-only",
                "--network",
                "none",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges:true",
                "--pids-limit",
                "2",
                "--memory",
                "16m",
                "--label",
                "argus.role=holder",
                "--mount",
                f"type=volume,source={self.volume},target={WORKSPACE}",
                "--entrypoint",
                "/usr/bin/sleep",
                self.image.tag,
                "infinity",
            ]
        )

    def verify(self) -> None:
        """Refuse to run unless the task volume is ours, bounded, and held.

        `docker create --mount type=volume,source=X` silently auto-creates a
        missing named volume (plain, disk-backed, unbounded), so the executor
        must check before every dispatch (FAIL-007).
        """
        proc = _docker(["volume", "inspect", self.volume], check=False)
        if proc.returncode != 0:
            raise ConfigDrift([f"task volume {self.volume} is missing"])
        vol = json.loads(proc.stdout)[0]
        opts = vol.get("Options") or {}
        problems = []
        if (vol.get("Labels") or {}).get("argus.role") != "workspace":
            problems.append("task volume lacks the argus workspace label")
        if opts.get("type") != "tmpfs" or f"size={self.size_bytes}" not in opts.get("o", ""):
            problems.append(f"task volume is not the size-capped tmpfs: {opts}")
        state = _docker(["inspect", "--format", "{{.State.Running}}", self.holder], check=False)
        if state.returncode != 0 or state.stdout.strip() != b"true":
            problems.append("holder container is not running")
        if problems:
            raise ConfigDrift(problems)

    def stage(self, tar_bytes: bytes) -> None:
        _docker(["cp", "-", f"{self.holder}:{WORKSPACE}"], input=tar_bytes, timeout=120)

    def export(self) -> bytes:
        """Tar stream of the workspace (members prefixed ``task/``). Untrusted."""
        return _docker(["cp", f"{self.holder}:{WORKSPACE}", "-"], timeout=120).stdout

    def destroy(self) -> None:
        _docker(["rm", "-f", self.holder], check=False)
        if self._created:
            _docker(["volume", "rm", "-f", self.volume], check=False)

    def __enter__(self) -> TaskSandbox:
        self.create()
        return self

    def __exit__(self, *exc: object) -> None:
        self.destroy()


class DockerExecutor:
    """One fresh hardened container per approved dispatch (code_execution_agent.md §3)."""

    is_mock = False

    def __init__(self, sandbox: TaskSandbox, *, grace_seconds: float = 15.0) -> None:
        self.sandbox = sandbox
        self.grace = grace_seconds
        self.last_inspect: dict[str, Any] | None = None

    def execute(self, dispatch: dict[str, Any]) -> dict[str, Any]:
        policy = json.loads(dispatch["canonical_policy"])
        limits = policy["limits"]
        self.sandbox.verify()  # before create: Docker would auto-create a missing volume
        name = _safe_name(
            "argus-w", dispatch["run_id"], dispatch["action_id"], uuid.uuid4().hex[:6]
        )
        image = self.sandbox.image
        _docker(
            ["create", "-i", "--name", name, *worker_flags(limits, self.sandbox.volume), image.tag]
        )
        try:
            inspect = json.loads(_docker(["inspect", name]).stdout)[0]
            problems = check_config(inspect, image_id=image.image_id, volume=self.sandbox.volume)
            if problems:
                raise ConfigDrift(problems)
            self.last_inspect = inspect
            op = dispatch["operation"]
            budget = float(op.get("timeout_seconds", limits["wall_time_seconds"])) + self.grace
            try:
                proc = _docker(
                    ["start", "-a", "-i", name],
                    input=json.dumps(dispatch).encode(),
                    timeout=budget,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                _docker(["kill", name], check=False)
                return _synthetic(dispatch, "timeout", "container exceeded its deadline; killed")
            lines = [ln for ln in proc.stdout.decode(errors="replace").splitlines() if ln.strip()]
            try:
                result: dict[str, Any] = json.loads(lines[-1])
            except (IndexError, ValueError):
                state = json.loads(_docker(["inspect", name]).stdout)[0].get("State", {})
                why = "oom-killed" if state.get("OOMKilled") else f"exit {state.get('ExitCode')}"
                return _synthetic(
                    dispatch,
                    "error",
                    f"worker produced no result ({why})",
                    oom=bool(state.get("OOMKilled")),
                )
            return result
        finally:
            _docker(["rm", "-f", name], check=False)

    def cancel_all(self) -> None:
        """Kill every worker container (cancellation)."""
        ids = _docker(["ps", "-q", "--filter", "label=argus.role=worker"]).stdout.decode().split()
        for cid in ids:
            _docker(["kill", cid], check=False)


def _synthetic(
    dispatch: dict[str, Any], status: str, error: str, *, oom: bool = False
) -> dict[str, Any]:
    return {
        "result_version": "1.0",
        "run_id": dispatch["run_id"],
        "task_id": dispatch["task_id"],
        "epoch": dispatch["epoch"],
        "action_id": dispatch["action_id"],
        "policy_hash": dispatch["policy_hash"],
        "arm": dispatch["arm"],
        "status": status,
        "exit_code": None,
        "signal": None,
        "stdout": "",
        "stderr": "",
        "error": error,
        "limit_hit": "memory_bytes"
        if oom
        else ("wall_time_seconds" if status == "timeout" else None),
        "confinement": {"mode": dispatch["confinement"], "installed": False},
    }


def leaked_resources() -> dict[str, list[str]]:
    """Argus containers/volumes still present (RES-010 / DKR-013).

    Matches by label *and* by name prefix: a volume Docker auto-created for a
    missing source would carry no argus label.
    """
    c = _docker(["ps", "-a", "-q", "--filter", "label=argus.role"]).stdout.decode().split()
    c += _docker(["ps", "-a", "-q", "--filter", "name=^argus-"]).stdout.decode().split()
    v = _docker(["volume", "ls", "-q"]).stdout.decode().split()
    return {"containers": sorted(set(c)), "volumes": sorted(x for x in v if x.startswith("argus-"))}
