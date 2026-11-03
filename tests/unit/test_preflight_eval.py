"""preflight.evaluate rejects each weakened security state (DKR-017 at the report level)."""

from __future__ import annotations

import copy
from typing import Any

from controller import docker_client as dc
from controller.preflight import PREFLIGHT_LIMITS, evaluate

GOOD: dict[str, Any] = {
    "uid": "10001\t10001\t10001\t10001",
    "gid": "10001\t10001\t10001\t10001",
    "cap_eff": "0000000000000000",
    "cap_prm": "0000000000000000",
    "cap_bnd": "0000000000000000",
    "no_new_privs": "1",
    "seccomp_mode": "2",
    "landlock_abi": 10,
    "root_write": {"writable": False},
    "usr_write": {"writable": False},
    "tmp_write": {"writable": True},
    "workspace_write": {"writable": True},
    "network_interfaces": ["lo"],
    "docker_socket_present": False,
    "host_paths_present": {"/host": False, "/home_has_entries": False, "/root_readable": False},
    "mounts": [
        {"mount_point": "/", "options": "ro", "fs_type": "overlay"},
        {"mount_point": "/tmp", "options": "rw,nosuid,nodev,noexec", "fs_type": "tmpfs"},
        {"mount_point": "/workspace/task", "options": "rw", "fs_type": "tmpfs"},
        {"mount_point": "/etc/hosts", "options": "ro", "fs_type": "ext4"},
    ],
    "env_names": ["PATH", "HOSTNAME", "LANG"],
    "cgroup": {
        "memory_max": str(PREFLIGHT_LIMITS["memory_bytes"] + dc.MEMORY_OVERHEAD),
        "memory_swap_max": "0",
        "pids_max": str(PREFLIGHT_LIMITS["process_count"] + dc.PIDS_OVERHEAD),
        "cpu_max": "100000 100000",
    },
}

BAD: list[tuple[str, str, Any]] = [
    ("non_root_uid", "uid", "0\t0\t0\t0"),
    ("capabilities_dropped", "cap_eff", "00000000a80425fb"),
    ("no_new_privs", "no_new_privs", "0"),
    ("docker_seccomp_active", "seccomp_mode", "0"),
    ("landlock_reachable", "landlock_abi", 0),
    ("root_read_only", "root_write", {"writable": True}),
    ("network_none", "network_interfaces", ["eth0", "lo"]),
    ("docker_socket_absent", "docker_socket_present", True),
    ("no_secret_env", "env_names", ["PATH", "OPENAI_API_KEY"]),
    ("swap_disabled", "cgroup", {**GOOD["cgroup"], "memory_swap_max": "max"}),
    ("cpu_limit_active", "cgroup", {**GOOD["cgroup"], "cpu_max": "max 100000"}),
]


def test_good_report_passes() -> None:
    checks = evaluate(GOOD, limits=PREFLIGHT_LIMITS)
    assert all(checks.values()), [k for k, v in checks.items() if not v]


def test_each_weakening_is_caught() -> None:
    for check, key, value in BAD:
        r = copy.deepcopy(GOOD)
        r[key] = value
        assert evaluate(r, limits=PREFLIGHT_LIMITS)[check] is False, check


def test_host_bind_mount_is_caught() -> None:
    r = copy.deepcopy(GOOD)
    r["mounts"].append({"mount_point": "/host", "options": "rw", "fs_type": "ext4"})
    assert evaluate(r, limits=PREFLIGHT_LIMITS)["no_unexpected_mounts"] is False
