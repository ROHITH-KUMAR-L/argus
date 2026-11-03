"""seccomp-BPF enforcement in the real worker: SEC-001 … SEC-020.

Docker's default profile already blocks many high-risk calls, so B0 is not a
clean contrast for those. Attribution to the *project* filter uses calls that
Docker allows but our profiles deny (ptrace TRACEME, socket under
minimal-run-v1, an extra-denied uname), plus prctl(PR_GET_SECCOMP).
"""

from __future__ import annotations

import copy
import json
import subprocess
import textwrap
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from controller import docker_client as dc
from controller.rust_client import RatchetError
from controller.workspace import build_stage_archive
from tests.helpers import Gate, start_ratchetd, template, worker_image

pytestmark = [pytest.mark.docker, pytest.mark.rust]
EPERM, ENOSYS = 1, 38

PY_POLICY = template()
PY_POLICY["commands"]["allowed_executables"] = ["/usr/local/bin/python3", "/usr/bin/sh"]
PY_POLICY["commands"]["shell"] = "allow"

LIB = textwrap.dedent("""
    import ctypes, json, os, sys
    libc = ctypes.CDLL(None, use_errno=True)
    R = {}
    def sc(name, nr, *args):
        ctypes.set_errno(0)
        r = libc.syscall(nr, *[ctypes.c_long(a) for a in args])
        R[name] = {"ret": r, "errno": ctypes.get_errno() if r == -1 else 0}
    def call(name, fn):
        try:
            R[name] = {"ret": fn(), "errno": 0}
        except OSError as e:
            R[name] = {"ret": -1, "errno": e.errno}
    PR_GET_SECCOMP, PR_GET_NO_NEW_PRIVS = 21, 39
""")

HIGH_RISK_PROBES = """
    sc("mount", 165, 0, 0, 0, 0, 0)
    sc("umount2", 166, 0, 0)
    sc("ptrace_traceme", 101, 0, 0, 0, 0)
    sc("setns", 308, 0, 0)
    sc("unshare_user", 272, 0x10000000)
    sc("init_module", 175, 0, 0, 0)
    sc("finit_module", 313, 0, 0, 0)
    sc("delete_module", 176, 0, 0)
    sc("bpf", 321, 0, 0, 0)
    sc("reboot", 169, 0, 0, 0, 0)
    sc("kexec_load", 246, 0, 0, 0, 0)
    sc("kexec_file_load", 320, 0, 0, 0, 0, 0)
    sc("io_uring_setup", 425, 1, 0)
    sc("keyctl", 250, 0, 0)
    sc("userfaultfd", 323, 0)
"""


@pytest.fixture(scope="module")
def image() -> dc.WorkerImage:
    return worker_image()


@pytest.fixture(scope="module")
def daemons(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Path]]:
    tmp = tmp_path_factory.mktemp("sec")
    procs = {arm: start_ratchetd(tmp, arm) for arm in ("P1", "B0")}
    yield {arm: run for arm, (_, run) in procs.items()}
    for proc, _ in procs.values():
        proc.kill()
        proc.wait()


@pytest.fixture
def sandbox(image: dc.WorkerImage) -> Iterator[dc.TaskSandbox]:
    with dc.TaskSandbox(image, "sec", size_bytes=16 * 1024 * 1024) as sb:
        yield sb


_n = iter(range(10_000))


def run_py(
    daemons: dict[str, Path],
    sb: dc.TaskSandbox,
    arm: str,
    body: str,
    policy: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    g = Gate(daemons[arm], f"sec-{arm.lower()}-{next(_n)}", policy or PY_POLICY)
    res = dc.DockerExecutor(sb).execute(
        g.py(LIB + textwrap.dedent(body) + "\nprint(json.dumps(R))")
    )
    lines = [ln for ln in res["stdout"].splitlines() if ln.startswith("{")]
    assert lines, res
    out: dict[str, Any] = json.loads(lines[-1])
    return out, res


def test_sec_001_002_installed_with_no_new_privs(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    r, res = run_py(
        daemons,
        sandbox,
        "P1",
        """
        R["seccomp_mode"] = libc.prctl(PR_GET_SECCOMP, 0, 0, 0, 0)
        R["nnp"] = libc.prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
    """,
    )
    c = res["confinement"]
    assert c["installed"] and c["seccomp_installed"], c
    assert c["seccomp"]["profile"] == "python-build-v1" and c["seccomp"]["mode"] == "denylist"
    assert c["seccomp"]["instructions"] > 0
    assert r["seccomp_mode"] == 2 and r["nnp"] == 1


def test_sec_003_to_010_high_risk_denied(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r, _ = run_py(daemons, sandbox, "P1", HIGH_RISK_PROBES)
    for name, v in r.items():
        assert v["ret"] == -1 and v["errno"] == EPERM, (name, v)


def test_project_filter_attribution(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    # ptrace(TRACEME) is allowed by Docker's default profile, denied by ours.
    body = """
        sc("ptrace_traceme", 101, 0, 0, 0, 0)
        R["seccomp_mode"] = libc.prctl(PR_GET_SECCOMP, 0, 0, 0, 0)
    """
    p1, _ = run_py(daemons, sandbox, "P1", body)
    b0, _ = run_py(daemons, sandbox, "B0", body)
    assert p1["ptrace_traceme"]["errno"] == EPERM
    assert b0["ptrace_traceme"]["ret"] == 0, b0  # outer boundary alone permits it
    # Extra policy denial: uname works in B0, EPERM in P1.
    pol = copy.deepcopy(PY_POLICY)
    pol["syscalls"]["deny_high_risk"] = ["uname"]
    body = 'call("uname", lambda: os.uname().sysname)'
    assert run_py(daemons, sandbox, "P1", body, pol)[0]["uname"]["errno"] == EPERM
    assert run_py(daemons, sandbox, "B0", body, pol)[0]["uname"]["ret"] == "Linux"


def test_sec_011_012_013_legitimate_workload(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    src = tmp_path / "proj"
    (src / "tests").mkdir(parents=True)
    (src / "calc.py").write_text("def add(a, b):\n    return a + b\n")
    (src / "tests/test_calc.py").write_text(
        textwrap.dedent("""
        import sys, subprocess, pathlib, threading
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        from calc import add
        def test_add(tmp_path):
            (tmp_path / "x").write_text("1")
            assert add(2, 3) == 5
        def test_child():
            out = subprocess.run([sys.executable, "-c", "print(7)"], capture_output=True, text=True)
            assert out.stdout.strip() == "7"
        def test_thread():
            t = threading.Thread(target=lambda: None); t.start(); t.join()
    """)
    )
    sandbox.stage(build_stage_archive(src))
    for profile in ("python-build-v1", "python-strict-v1"):
        pol = copy.deepcopy(PY_POLICY)
        pol["syscalls"]["profile"] = profile
        if profile == "python-strict-v1":
            pol["commands"]["allowed_executables"] = ["/usr/local/bin/python3"]
            pol["commands"]["shell"] = "deny"
        g = Gate(daemons["P1"], f"sec-legit-{profile}", pol)
        res = dc.DockerExecutor(sandbox).execute(
            g.dispatch({"type": "run_tests", "target": "python-pytest"})
        )
        assert res["status"] == "completed", (profile, res["stdout"][-2000:], res["stderr"][-2000:])
        assert "3 passed" in res["stdout"], res["stdout"]
        assert res["confinement"]["seccomp"]["profile"] == profile


def test_sec_014_015_child_and_grandchild_inherit(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    child = LIB + 'sc("p", 101, 0, 0, 0, 0); print(R["p"]["errno"])'
    body = f"""
        import subprocess
        code = {child!r}
        c = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
        R["child_errno"] = int(c.stdout.strip())
        g = subprocess.run(["/usr/bin/sh", "-c", f"{{sys.executable}} -c '{{code}}'"],
                           capture_output=True, text=True)
        R["grandchild_errno"] = int(g.stdout.strip())
    """
    r, _ = run_py(daemons, sandbox, "P1", body)
    assert r["child_errno"] == EPERM and r["grandchild_errno"] == EPERM, r


def test_sec_016_stacking_cannot_relax(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r, _ = run_py(
        daemons,
        sandbox,
        "P1",
        """
        # Install an "allow everything" filter on top, then retry a denied call.
        class SockFilter(ctypes.Structure):
            _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                        ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]
        class SockFprog(ctypes.Structure):
            _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]
        prog = (SockFilter * 1)(SockFilter(0x06, 0, 0, 0x7fff0000))  # BPF_RET|K, SECCOMP_RET_ALLOW
        fp = SockFprog(1, prog)
        R["stack"] = libc.prctl(22, 2, ctypes.byref(fp), 0, 0)  # PR_SET_SECCOMP, FILTER
        sc("ptrace_after_stack", 101, 0, 0, 0, 0)
        sc("mount_after_stack", 165, 0, 0, 0, 0, 0)
    """,
    )
    assert r["stack"] == 0, r
    assert r["ptrace_after_stack"]["errno"] == EPERM
    assert r["mount_after_stack"]["errno"] == EPERM


def test_sec_017_install_failure_fails_closed(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    prof = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [{"names": ["seccomp"], "action": "SCMP_ACT_ERRNO", "errnoRet": 38}],
    }
    pf = tmp_path / "no-seccomp.json"
    pf.write_text(json.dumps(prof))
    g = Gate(daemons["P1"], "sec-fail", PY_POLICY)
    d = g.py("open('/workspace/task/ran','w').write('x')")
    flags = dc.worker_flags(json.loads(d["canonical_policy"])["limits"], sandbox.volume)
    proc = subprocess.run(
        [
            "docker",
            "run",
            "-i",
            "--rm",
            *flags,
            "--security-opt",
            f"seccomp={pf}",
            sandbox.image.tag,
        ],
        input=json.dumps(d).encode(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    res = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    assert res["status"] == "confinement_failed", res
    r, _ = run_py(
        daemons, sandbox, "B0", 'call("ran", lambda: os.path.exists("/workspace/task/ran"))'
    )
    assert r["ran"]["ret"] is False


def test_sec_018_profile_mismatch_rejected(daemons: dict[str, Path]) -> None:
    pol = template("c-build")
    pol["syscalls"]["profile"] = "python-strict-v1"
    with pytest.raises(RatchetError) as e:
        Gate(daemons["P1"], "sec-mismatch", pol)
    assert any(i["code"] == "PROFILE_EXECUTABLE_MISMATCH" for i in e.value.detail["issues"])


def test_sec_019_default_deny_profile(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    pol = copy.deepcopy(PY_POLICY)
    pol["syscalls"]["profile"] = "python-strict-v1"
    pol["commands"]["allowed_executables"] = ["/usr/local/bin/python3"]
    pol["commands"]["shell"] = "deny"
    r, res = run_py(
        daemons,
        sandbox,
        "P1",
        """
        call("normal_io", lambda: len(open("/usr/local/bin/python3", "rb").read(16)))
        sc("personality", 135, 0xffffffff)      # not listed
        sc("socketpair", 53, 1, 1, 0, 0)        # not listed
        sc("getcpu", 309, 0, 0, 0)              # not listed
        sc("x32_getpid", 0x40000000 | 39)
    """,
        pol,
    )
    assert res["confinement"]["seccomp"]["mode"] == "allowlist"
    assert r["normal_io"]["ret"] == 16
    for k in ("personality", "socketpair", "getcpu"):
        assert r[k]["errno"] == EPERM, (k, r[k])
    assert r["x32_getpid"]["ret"] == -1


def test_sec_020_denylist_profile_is_default_allow(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    r, res = run_py(
        daemons,
        sandbox,
        "P1",
        """
        sc("getcpu", 309, 0, 0, 0)               # unlisted -> allowed (default allow)
        sc("ptrace", 101, 0, 0, 0, 0)            # listed -> EPERM
        sc("clone3", 435, 0, 0)                  # fixed guard -> ENOSYS
        sc("x32_getpid", 0x40000000 | 39)
    """,
    )
    assert res["confinement"]["seccomp"]["mode"] == "denylist"
    assert r["getcpu"]["ret"] == 0
    assert r["ptrace"]["errno"] == EPERM
    assert r["clone3"]["errno"] == ENOSYS
    assert r["x32_getpid"]["ret"] == -1


def test_minimal_run_blocks_sockets(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    pol = copy.deepcopy(PY_POLICY)
    pol["syscalls"]["profile"] = "minimal-run-v1"
    body = 'sc("socket", 41, 1, 1, 0)'  # AF_UNIX stream: Docker allows it
    assert run_py(daemons, sandbox, "P1", body, pol)[0]["socket"]["errno"] == EPERM
    assert run_py(daemons, sandbox, "B0", body, pol)[0]["socket"]["ret"] >= 0
