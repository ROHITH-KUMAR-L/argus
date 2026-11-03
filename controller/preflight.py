"""Protected-execution preflight (code_execution_agent.md §13).

Runs the pinned worker image under the exact worker hardening with
``--preflight`` and checks its self-reported security state. Any failed
mandatory check marks protected execution unavailable.
"""

from __future__ import annotations

import json
import os
import platform
from dataclasses import dataclass, field
from typing import Any

from controller import docker_client as dc

SAFE_ENV = {"PATH", "HOSTNAME", "HOME", "LANG", "GPG_KEY", "PYTHON_VERSION", "PYTHON_SHA256"}
DOCKER_MANAGED_FILES = {"/etc/hosts", "/etc/hostname", "/etc/resolv.conf"}
PREFLIGHT_LIMITS = {
    "memory_bytes": 128 * 1024 * 1024,
    "open_files": 64,
    "process_count": 16,
    "wall_time_seconds": 30,
}


@dataclass
class PreflightReport:
    ok: bool
    checks: dict[str, bool] = field(default_factory=dict)
    details: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)

    def failures(self) -> list[str]:
        return [k for k, v in self.checks.items() if not v]


def evaluate(r: dict[str, Any], *, limits: dict[str, int]) -> dict[str, bool]:
    """Pure check of a ``--preflight`` report against the hardening contract."""
    zero_caps = "0000000000000000"
    mounts = r.get("mounts", [])
    unexpected = [
        m["mount_point"]
        for m in mounts
        if m["mount_point"] not in DOCKER_MANAGED_FILES
        and not any(
            m["mount_point"] == p or m["mount_point"].startswith(p + "/")
            for p in ("/", "/proc", "/dev", "/sys")
        )
        and m["mount_point"] not in ("/tmp", dc.WORKSPACE)
    ]
    # Every mount other than the ones above is unexpected; "/" itself is the overlay root.
    unexpected = [m for m in unexpected if m != "/"]
    by_point = {m["mount_point"]: m for m in mounts}
    tmp = by_point.get("/tmp", {})
    ws = by_point.get(dc.WORKSPACE, {})
    cg = r.get("cgroup", {})
    expect_mem = str(limits["memory_bytes"] + dc.MEMORY_OVERHEAD)
    return {
        "non_root_uid": str(r.get("uid", "")).split()[:1] == ["10001"],
        "non_root_gid": str(r.get("gid", "")).split()[:1] == ["10001"],
        "capabilities_dropped": all(
            r.get(k) == zero_caps for k in ("cap_eff", "cap_prm", "cap_bnd")
        ),
        "no_new_privs": r.get("no_new_privs") == "1",
        "docker_seccomp_active": r.get("seccomp_mode") == "2",
        "landlock_reachable": int(r.get("landlock_abi", 0)) >= 1,
        "root_read_only": not r.get("root_write", {}).get("writable", True)
        and not r.get("usr_write", {}).get("writable", True),
        "tmp_writable_noexec": r.get("tmp_write", {}).get("writable") is True
        and "noexec" in tmp.get("options", ""),
        "workspace_writable_bounded": r.get("workspace_write", {}).get("writable") is True
        and ws.get("fs_type") == "tmpfs",
        "network_none": r.get("network_interfaces") == ["lo"],
        "docker_socket_absent": r.get("docker_socket_present") is False,
        "host_home_absent": not r.get("host_paths_present", {}).get("/home_has_entries", True)
        and not r.get("host_paths_present", {}).get("/root_readable", True)
        and not r.get("host_paths_present", {}).get("/host", True),
        "no_unexpected_mounts": not unexpected,
        "no_secret_env": set(r.get("env_names", [])) <= SAFE_ENV,
        "memory_limit_active": cg.get("memory_max") == expect_mem,
        "swap_disabled": cg.get("memory_swap_max") == "0",
        "pids_limit_active": cg.get("pids_max") == str(limits["process_count"] + dc.PIDS_OVERHEAD),
        "cpu_limit_active": str(cg.get("cpu_max", "max")).split()[:1] != ["max"],
    }


def run(image: dc.WorkerImage | None = None) -> PreflightReport:
    details: dict[str, Any] = {"host_kernel": platform.release(), "machine": platform.machine()}
    checks: dict[str, bool] = {}
    try:
        version = dc.ping()
        details["docker_server_version"] = version.get("Server", {}).get("Version")
        checks["docker_available"] = True
    except dc.DockerUnavailable as exc:
        details["docker_error"] = str(exc)
        return PreflightReport(ok=False, checks={"docker_available": False}, details=details)
    image = image or dc.WorkerImage.from_lock()
    try:
        image.verify_present()
        checks["image_digest_matches"] = True
    except (dc.ConfigDrift, dc.DockerUnavailable) as exc:
        details["image_error"] = str(exc)
        return PreflightReport(
            ok=False, checks={**checks, "image_digest_matches": False}, details=details
        )
    details["image_id"] = image.image_id
    with dc.TaskSandbox(image, "preflight", size_bytes=8 * 1024 * 1024) as sb:
        name = dc._safe_name("argus-preflight", os.urandom(4).hex())
        dc._docker(
            [
                "create",
                "--name",
                name,
                *dc.worker_flags(PREFLIGHT_LIMITS, sb.volume),
                image.tag,
                "--preflight",
            ]
        )
        try:
            inspect = json.loads(dc._docker(["inspect", name]).stdout)[0]
            drift = dc.check_config(inspect, image_id=image.image_id, volume=sb.volume)
            checks["container_config_matches_contract"] = not drift
            details["config_drift"] = drift
            out = dc._docker(["start", "-a", name], timeout=60).stdout
            report: dict[str, Any] = json.loads(out.decode().strip().splitlines()[-1])
        finally:
            dc._docker(["rm", "-f", name], check=False)
    checks.update(evaluate(report, limits=PREFLIGHT_LIMITS))
    return PreflightReport(ok=all(checks.values()), checks=checks, details=details, report=report)
