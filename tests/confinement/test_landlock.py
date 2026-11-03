"""Landlock filesystem enforcement in the real worker: LL-001 … LL-022.

Every denial probe also runs in B0 (same image, same policy, no project
Landlock) to show the operation *would* succeed without the kernel rule, so
the denial is attributable to Landlock (EACCES / EXDEV), not to DAC, the
read-only root (EROFS) or a missing file.
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
from controller.workspace import build_stage_archive
from tests.helpers import Gate, start_ratchetd, template, worker_image

pytestmark = [pytest.mark.docker, pytest.mark.rust]
EACCES, EXDEV, EPERM = 13, 18, 1
CANARY = "/opt/argus-canary/secret.txt"

# Workspace root read-only, only src/ writable; no /tmp.
STRICT = template()
STRICT["filesystem"] = {
    "read_only": ["/usr", "/etc/ld.so.cache", "/dev/urandom", "/workspace/task"],
    "read_write": ["/workspace/task/src", "/dev/null"],
}
STRICT["commands"]["allowed_executables"] = ["/usr/local/bin/python3", "/usr/bin/sh"]
STRICT["commands"]["shell"] = "allow"

PROBE_LIB = textwrap.dedent("""
    import json, os, sys
    R = {}
    def attempt(name, fn):
        try:
            v = fn()
            R[name] = {"ok": True, "value": v if isinstance(v, (str, int, list, type(None))) else str(v)}
        except OSError as e:
            R[name] = {"ok": False, "errno": e.errno}
""")


@pytest.fixture(scope="module")
def image() -> dc.WorkerImage:
    return worker_image()


@pytest.fixture(scope="module")
def daemons(tmp_path_factory: pytest.TempPathFactory) -> Iterator[dict[str, Path]]:
    tmp = tmp_path_factory.mktemp("ll")
    procs = {arm: start_ratchetd(tmp, arm) for arm in ("P1", "B0")}
    yield {arm: run for arm, (_, run) in procs.items()}
    for proc, _ in procs.values():
        proc.kill()
        proc.wait()


@pytest.fixture
def sandbox(image: dc.WorkerImage, tmp_path: Path) -> Iterator[dc.TaskSandbox]:
    src = tmp_path / "ws"
    (src / "src").mkdir(parents=True)
    (src / "protected").mkdir()
    (src / "src/a.py").write_text("print('hi')\n")
    (src / "protected/p.txt").write_text("PROTECTED-CONTENT\n")
    with dc.TaskSandbox(image, "ll", size_bytes=16 * 1024 * 1024) as sb:
        sb.stage(build_stage_archive(src))
        yield sb


_counter = iter(range(10_000))


def probe(
    daemons: dict[str, Path],
    sb: dc.TaskSandbox,
    arm: str,
    body: str,
    policy: dict[str, Any] | None = None,
) -> dict[str, Any]:
    g = Gate(daemons[arm], f"ll-{arm.lower()}-{next(_counter)}", policy or STRICT)
    res = dc.DockerExecutor(sb).execute(
        g.py(PROBE_LIB + textwrap.dedent(body) + "\nprint(json.dumps(R))")
    )
    assert res["status"] in ("completed", "failed"), res
    if arm == "P1":
        c = res["confinement"]
        assert c["mode"] == "kernel" and c["installed"] is True, res
    lines = [ln for ln in res["stdout"].splitlines() if ln.startswith("{")]
    assert lines, res
    out: dict[str, Any] = json.loads(lines[-1])
    return out


def denied(r: dict[str, Any], name: str, errnos: tuple[int, ...] = (EACCES,)) -> None:
    assert r[name]["ok"] is False and r[name]["errno"] in errnos, (name, r[name])


def allowed(r: dict[str, Any], name: str) -> None:
    assert r[name]["ok"] is True, (name, r[name])


def both(
    daemons: dict[str, Path], sb: dc.TaskSandbox, body: str, policy: dict[str, Any] | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    return probe(daemons, sb, "P1", body, policy), probe(daemons, sb, "B0", body, policy)


def test_aud_005_confinement_reported(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    g = Gate(daemons["P1"], "ll-report", STRICT)
    res = dc.DockerExecutor(sandbox).execute(g.py("print(1)"))
    ll = res["confinement"]["landlock"]
    assert res["confinement"]["installed"] is True
    assert ll["kernel_abi"] >= 1 and ll["handled_abi"] == min(ll["kernel_abi"], 9)
    assert "Truncate" in ll["handled_fs"] and ll["scoped"] is True
    assert {r["path"] for r in ll["rules"]} == {
        "/usr",
        "/etc/ld.so.cache",
        "/dev/urandom",
        "/workspace/task",
        "/workspace/task/src",
        "/dev/null",
    }


def test_ll_001_002_010_workspace_rights(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r = probe(
        daemons,
        sandbox,
        "P1",
        """
        attempt("read_ro", lambda: open("/workspace/task/protected/p.txt").read())
        attempt("read_rw", lambda: open("/workspace/task/src/a.py").read())
        attempt("write_rw", lambda: open("/workspace/task/src/new.py", "w").write("x"))
        attempt("write_ro", lambda: open("/workspace/task/protected/p.txt", "a").write("x"))
    """,
    )
    allowed(r, "read_ro")
    allowed(r, "read_rw")
    allowed(r, "write_rw")
    denied(r, "write_ro")


def test_ll_003_004_005_006_outside_operations(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    body = f"""
        attempt("read_canary", lambda: open("{CANARY}").read())
        attempt("read_etc", lambda: open("/etc/argus-canary.txt").read())
        attempt("write_tmp", lambda: open("/tmp/outside.txt", "w").write("x"))
        attempt("unlink_protected", lambda: os.unlink("/workspace/task/protected/p.txt"))
        attempt("mkdir_ws_root", lambda: os.mkdir("/workspace/task/newdir"))
    """
    p1, b0 = both(daemons, sandbox, body)
    for k in ("read_canary", "read_etc", "write_tmp", "unlink_protected", "mkdir_ws_root"):
        denied(p1, k)
        allowed(b0, k)  # same image, same DAC: only Landlock differs
    assert b0["read_canary"]["value"].startswith("ARGUS-CANARY-OPT")


def test_ll_007_008_rename_and_link_across_boundary(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    body = f"""
        open("/workspace/task/src/mv.txt", "w").write("m")
        attempt("rename_out", lambda: os.rename("/workspace/task/src/mv.txt", "/workspace/task/protected/mv.txt"))
        attempt("rename_in", lambda: os.rename("/workspace/task/protected/p.txt", "/workspace/task/src/p.txt"))
        attempt("hardlink_canary", lambda: os.link("{CANARY}", "/workspace/task/src/hl"))
        attempt("symlink_in_ro", lambda: os.symlink("/etc", "/workspace/task/protected/sl"))
    """
    p1, b0 = both(daemons, sandbox, body)
    for k in ("rename_out", "rename_in", "hardlink_canary", "symlink_in_ro"):
        denied(p1, k, (EACCES, EXDEV))
    allowed(b0, "symlink_in_ro")


def test_ll_009_truncate_protected(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    p1, b0 = both(
        daemons,
        sandbox,
        """
        attempt("truncate", lambda: os.truncate("/workspace/task/protected/p.txt", 0))
    """,
    )
    denied(p1, "truncate")
    allowed(b0, "truncate")


def test_ll_011_runtimes_still_work(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r = probe(
        daemons,
        sandbox,
        "P1",
        """
        import subprocess, json as j, sqlite3, hashlib
        attempt("stdlib", lambda: hashlib.sha256(b"x").hexdigest()[:8])
        attempt("subprocess", lambda: subprocess.run(["/usr/bin/sh", "-c", "echo child"],
                capture_output=True, text=True).stdout.strip())
        attempt("devnull", lambda: subprocess.run(["/usr/bin/sh", "-c", "true"],
                stdout=subprocess.DEVNULL).returncode)
    """,
    )
    allowed(r, "stdlib")
    assert r["subprocess"]["value"] == "child"
    assert r["devnull"]["value"] == 0


def test_ll_011_c_toolchain_works(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    c = template("c-build")
    c["filesystem"]["read_write"] = ["/workspace/task", "/tmp", "/dev/null"]
    g = Gate(daemons["P1"], "ll-c", c)
    ex = dc.DockerExecutor(sandbox)
    w = ex.execute(
        g.dispatch(
            {
                "type": "write_file",
                "path": "hello.c",
                "content": '#include <stdio.h>\nint main(){puts("built");return 0;}\n',
            }
        )
    )
    assert w["status"] == "completed", w
    b = ex.execute(
        g.dispatch(
            {
                "type": "run_command",
                "executable": "/usr/bin/gcc",
                "argv": ["/usr/bin/gcc", "-o", "/workspace/task/hello", "/workspace/task/hello.c"],
            }
        )
    )
    assert b["status"] == "completed", b
    py = "import subprocess;print(subprocess.run(['/workspace/task/hello'],capture_output=True,text=True).stdout)"
    r = ex.execute(
        g.dispatch(
            {
                "type": "run_command",
                "executable": "/usr/local/bin/python3",
                "argv": ["/usr/local/bin/python3", "-c", py],
            }
        )
    )
    assert "built" in r["stdout"], r


def test_ll_012_013_014_symlink_alias_traversal(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    body = f"""
        if not os.path.lexists("/workspace/task/src/link"):
            os.symlink("{CANARY}", "/workspace/task/src/link")
        attempt("follow_symlink", lambda: open("/workspace/task/src/link").read())
        attempt("dotdot_alias", lambda: open("/workspace/task/src/../../../opt/argus-canary/secret.txt").read())
        attempt("proc_root_alias", lambda: open("/proc/self/root{CANARY}").read())
        attempt("list_opt", lambda: os.listdir("/opt/argus-canary"))
        attempt("list_etc", lambda: os.listdir("/etc"))
        attempt("list_usr", lambda: len(os.listdir("/usr")))
    """
    p1, b0 = both(daemons, sandbox, body)
    for k in ("follow_symlink", "dotdot_alias", "list_opt", "list_etc"):
        denied(p1, k)
        allowed(b0, k)
    assert p1["proc_root_alias"]["ok"] is False
    allowed(p1, "list_usr")


def test_ll_015_no_inherited_descriptors(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r = probe(
        daemons,
        sandbox,
        "P1",
        """
        def open_fds():
            found = []
            for fd in range(3, 256):
                try:
                    os.fstat(fd)
                    found.append(fd)
                except OSError:
                    pass
            return found
        attempt("fds", open_fds)
    """,
    )
    assert r["fds"]["value"] == [], r


def test_ll_016_special_paths_documented(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    p1, b0 = both(
        daemons,
        sandbox,
        """
        import socket
        attempt("proc_status", lambda: len(open("/proc/self/status").read()) > 0)
        attempt("dev_zero", lambda: len(open("/dev/zero", "rb").read(4)))
        attempt("dev_null_write", lambda: open("/dev/null", "w").write("x"))
        attempt("kill_supervisor", lambda: os.kill(1, 15))
    """,
    )
    # Documented behaviour on kernel ABI >= 6 (see docs/confinement.md):
    denied(p1, "proc_status")  # procfs is not granted
    denied(p1, "dev_zero")  # only /dev/null and /dev/urandom are granted
    allowed(p1, "dev_null_write")
    denied(p1, "kill_supervisor", (EPERM,))  # signal scoping (ABI 6)
    allowed(b0, "dev_zero")


def test_ll_018_landlock_unavailable_fails_closed(
    image: dc.WorkerImage, daemons: dict[str, Path], sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    # Fault injection outside the controller path: a seccomp profile that makes
    # the Landlock syscalls fail with ENOSYS, as on a kernel without Landlock.
    prof = {
        "defaultAction": "SCMP_ACT_ALLOW",
        "syscalls": [
            {
                "names": ["landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self"],
                "action": "SCMP_ACT_ERRNO",
                "errnoRet": 38,
            }
        ],
    }
    pf = tmp_path / "no-landlock.json"
    pf.write_text(json.dumps(prof))
    g = Gate(daemons["P1"], "ll-unavail", STRICT)
    d = g.py("open('/workspace/task/src/ran','w').write('x')")
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
    assert "unavailable" in res["confinement"]["detail"]
    probe_b0 = probe(
        daemons,
        sandbox,
        "B0",
        """
        attempt("ran", lambda: os.path.exists("/workspace/task/src/ran"))
    """,
    )
    assert probe_b0["ran"]["value"] is False


def test_ll_019_planted_symlink_rule_root_fails_closed(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    # An earlier (B0) action replaces a rule root with a symlink to /etc.
    probe(
        daemons,
        sandbox,
        "B0",
        """
        import shutil
        shutil.rmtree("/workspace/task/src")
        os.symlink("/etc", "/workspace/task/src")
    """,
    )
    g = Gate(daemons["P1"], "ll-planted", STRICT)
    res = dc.DockerExecutor(sandbox).execute(g.py("open('/workspace/task/src/pwned','w')"))
    assert res["status"] == "confinement_failed", res
    assert res["exit_code"] is None


def test_ll_020_021_child_and_grandchild_inherit(
    daemons: dict[str, Path], sandbox: dc.TaskSandbox
) -> None:
    body = f"""
        import subprocess
        def run(cmd):
            p = subprocess.run(["/usr/bin/sh", "-c", cmd], capture_output=True, text=True)
            if p.returncode != 0:
                raise PermissionError(13, p.stderr.strip())
            return p.stdout.strip()
        attempt("child_read", lambda: run("cat {CANARY}"))
        attempt("grandchild_read", lambda: run("sh -c 'cat {CANARY}'"))
        attempt("grandchild_write", lambda: run("sh -c 'echo x > /tmp/gc.txt'"))
        attempt("setsid_child", lambda: run("setsid sh -c 'cat {CANARY}'"))
    """
    p1, b0 = both(daemons, sandbox, body)
    for k in ("child_read", "grandchild_read", "grandchild_write", "setsid_child"):
        denied(p1, k)
        allowed(b0, k)


def test_ll_022_threads_are_confined(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    r = probe(
        daemons,
        sandbox,
        "P1",
        f"""
        import threading
        box = {{}}
        def worker():
            try:
                box["v"] = open("{CANARY}").read()
            except OSError as e:
                box["errno"] = e.errno
        t = threading.Thread(target=worker); t.start(); t.join()
        attempt("thread", lambda: box.get("errno") or box.get("v"))
    """,
    )
    assert r["thread"]["value"] == EACCES, r


def test_file_ops_are_confined_too(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    # Built-in file operations run in a confined child: a read_file of a
    # workspace path that is a symlink to the canary is refused.
    probe(
        daemons,
        sandbox,
        "B0",
        f"""
        os.symlink("{CANARY}", "/workspace/task/src/sneaky")
    """,
    )
    g = Gate(daemons["P1"], "ll-fileop", STRICT)
    res = dc.DockerExecutor(sandbox).execute(
        g.dispatch({"type": "read_file", "path": "src/sneaky"})
    )
    assert res["confinement"]["installed"] is True
    assert res["file_result"]["ok"] is False
    assert "ARGUS-CANARY" not in json.dumps(res)


def test_narrower_policy_variants(daemons: dict[str, Path], sandbox: dc.TaskSandbox) -> None:
    pol = copy.deepcopy(STRICT)
    pol["filesystem"]["read_write"] = ["/dev/null"]  # whole workspace read-only
    r = probe(
        daemons,
        sandbox,
        "P1",
        """
        attempt("write_src", lambda: open("/workspace/task/src/x", "w").write("x"))
    """,
        pol,
    )
    denied(r, "write_src")
