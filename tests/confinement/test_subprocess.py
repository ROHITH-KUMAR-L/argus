"""Subprocess-aware enforcement and narrowing between actions: SUB-001 … SUB-018, AUD-006/007.

Cases proven elsewhere are referenced, not duplicated:
SUB-013 timeout with descendants → test_docker::test_res_007_timeout_kills_worker;
SUB-014 cancellation → test_docker::test_res_012_worker_killed_is_not_success;
LL-020/021/022 and SEC-014/015 cover child/grandchild/thread inheritance per layer.
"""

from __future__ import annotations

import copy
import json
import textwrap
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from controller import docker_client as dc
from controller.audit import bridge
from controller.audit.events import EventType
from controller.audit.writer import AuditWriter, verify
from controller.workspace import safe_extract
from tests.helpers import Gate, start_ratchetd, template, worker_image

pytestmark = [pytest.mark.docker, pytest.mark.rust]
CANARY = "/opt/argus-canary/secret.txt"
POLICY = template()
POLICY["commands"]["allowed_executables"] = ["/usr/local/bin/python3", "/usr/bin/sh"]
POLICY["commands"]["shell"] = "allow"


@pytest.fixture(scope="module")
def image() -> dc.WorkerImage:
    return worker_image()


@pytest.fixture(scope="module")
def p1(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    proc, run = start_ratchetd(tmp_path_factory.mktemp("sub"), "P1")
    yield run
    proc.kill()
    proc.wait()


@pytest.fixture
def sandbox(image: dc.WorkerImage) -> Iterator[dc.TaskSandbox]:
    with dc.TaskSandbox(image, "sub", size_bytes=16 * 1024 * 1024) as sb:
        yield sb


_n = iter(range(10_000))


def gate(p1: Path, policy: dict[str, Any] | None = None) -> Gate:
    return Gate(p1, f"sub-{next(_n)}", policy or POLICY)


def sh(g: Gate, script: str, timeout: int = 30) -> dict[str, Any]:
    return g.dispatch(
        {
            "type": "run_command",
            "executable": "/usr/bin/sh",
            "argv": ["/usr/bin/sh", "-c", script],
            "timeout_seconds": timeout,
        }
    )


def files(sb: dc.TaskSandbox, tmp: Path) -> dict[str, str]:
    dest = tmp / f"exp-{next(_n)}"
    arts = safe_extract(sb.export(), dest, strip_prefix="task")
    return {a.path: (dest / a.path).read_text() for a in arts}


def test_sub_001_to_005_010_delegated_violations_denied(p1: Path, sandbox: dc.TaskSandbox) -> None:
    probe = textwrap.dedent(f"""
        import ctypes, json, os, subprocess, sys
        libc = ctypes.CDLL(None, use_errno=True)
        def fs():
            try:
                open("{CANARY}").read(); return "READ"
            except OSError as e:
                return e.errno
        def sc():
            return libc.syscall(101, 0, 0, 0, 0), ctypes.get_errno()  # ptrace TRACEME
        R = {{}}
        pid = os.fork()
        if pid == 0:
            os.write(1, (json.dumps({{"fork": [fs(), sc()]}}) + "\\n").encode()); os._exit(0)
        os.waitpid(pid, 0)
        py = subprocess.run([sys.executable, "-c", "import json;" + "exec(open('/workspace/task/p.py').read())"],
                            capture_output=True, text=True)
        print(py.stdout.strip())
    """)
    inner = (
        f"import ctypes,json;libc=ctypes.CDLL(None,use_errno=True)\n"
        f"try:\n open('{CANARY}').read(); r='READ'\nexcept OSError as e: r=e.errno\n"
        f"print(json.dumps({{'python_child': [r, libc.syscall(101,0,0,0,0), ctypes.get_errno()]}}))"
    )
    g = gate(p1)
    ex = dc.DockerExecutor(sandbox)
    ex.execute(g.dispatch({"type": "write_file", "path": "p.py", "content": inner}))
    ex.execute(g.dispatch({"type": "write_file", "path": "probe.py", "content": probe}))
    res = ex.execute(
        sh(
            g,
            f"cat {CANARY} 2>&1; echo shell_rc=$?; "
            "sh -c 'cat /etc/argus-canary.txt' 2>&1; echo grandchild_rc=$?; "
            "/usr/local/bin/python3 /workspace/task/probe.py",
        )
    )
    out = res["stdout"]
    assert "ARGUS-CANARY" not in out, out
    assert "shell_rc=1" in out and "grandchild_rc=1" in out, out
    rows = [json.loads(ln) for ln in out.splitlines() if ln.startswith("{")]
    fork = next(r["fork"] for r in rows if "fork" in r)
    child = next(r["python_child"] for r in rows if "python_child" in r)
    assert fork == [13, [-1, 1]], fork  # SUB-005: EACCES, ptrace EPERM
    assert child == [13, -1, 1], child  # SUB-004


def test_sub_007_008_background_and_setsid_do_not_survive(
    p1: Path, sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    g = gate(p1)
    ex = dc.DockerExecutor(sandbox)
    res = ex.execute(
        sh(
            g,
            "(sleep 1; echo late > /workspace/task/bg.txt) & "
            "setsid sh -c 'sleep 1; echo late > /workspace/task/sid.txt' & "
            "nohup sh -c 'sleep 1; echo late > /workspace/task/nohup.txt' >/dev/null 2>&1 & "
            "echo parent-exits",
        )
    )
    assert res["status"] == "completed" and res["descendants_killed"] >= 3, res
    time.sleep(2)
    left = files(sandbox, tmp_path)
    assert not {"bg.txt", "sid.txt", "nohup.txt"} & set(left), left


def test_sub_009_aud_006_process_tree_recorded(
    p1: Path, sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    g = gate(p1)
    d = sh(g, "sleep 0.4 & /usr/local/bin/python3 -c 'import time; time.sleep(0.4)'; wait")
    res = dc.DockerExecutor(sandbox).execute(d)
    tree = {p["pid"]: p for p in res["process_tree"]}
    comms = sorted(p["comm"] for p in tree.values())
    assert "sh" in comms and "sleep" in comms and any(c.startswith("python") for c in comms), comms
    root = next(p for p in tree.values() if p["comm"] == "sh")
    kids = [p for p in tree.values() if p["ppid"] == root["pid"]]
    assert {k["comm"] for k in kids} >= {"sleep"}, tree
    w = AuditWriter(tmp_path / "a/events.jsonl", run_id="run-test", task_id=d["task_id"], arm="P1")
    bridge.worker_result(w, dispatch=d, result=res)
    ev = verify(w.path)
    spawned = [e for e in ev if e.event_type == EventType.PROCESS_SPAWNED]
    assert len(spawned) == len(tree)
    assert all(e.parent_process_id is not None and e.action_id == d["action_id"] for e in spawned)
    assert any(e.event_type == EventType.CONFINEMENT_INSTALLED for e in ev)  # AUD-005 via bridge


def test_aud_007_resource_event(p1: Path, sandbox: dc.TaskSandbox, tmp_path: Path) -> None:
    pol = copy.deepcopy(POLICY)
    pol["limits"]["cpu_seconds"] = 1
    g = gate(p1, pol)
    d = g.py("while True: pass", timeout=20)
    res = dc.DockerExecutor(sandbox).execute(d)
    assert res["limit_hit"] == "cpu_seconds", res
    w = AuditWriter(tmp_path / "b/events.jsonl", run_id="run-test", task_id=d["task_id"], arm="P1")
    bridge.worker_result(w, dispatch=d, result=res)
    lim = [e for e in verify(w.path) if e.event_type == EventType.RESOURCE_LIMIT_HIT]
    assert (
        len(lim) == 1
        and lim[0].reason_code == "CPU_SECONDS"
        and lim[0].enforcement_layer == "rlimit"
    )


def test_sub_011_012_child_environment_and_descriptors(p1: Path, sandbox: dc.TaskSandbox) -> None:
    g = gate(p1)
    code = (
        "import json,subprocess,sys;"
        "c=subprocess.run([sys.executable,'-c','import os,json;print(json.dumps(sorted(os.environ)))'],"
        "capture_output=True,text=True);print(c.stdout)"
    )
    res = dc.DockerExecutor(sandbox).execute(g.py(code))
    env = json.loads(res["stdout"].strip().splitlines()[-1])
    assert set(env) <= {
        "PATH",
        "HOME",
        "TMPDIR",
        "LANG",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONUNBUFFERED",
        "LC_CTYPE",
    }, env
    fds = dc.DockerExecutor(sandbox).execute(
        g.py(
            "import os,subprocess,sys;"
            "print(subprocess.run([sys.executable,'-c','import os\\nr=[]\\nfor f in range(3,256):\\n try:\\n  os.fstat(f); r.append(f)\\n except OSError: pass\\nprint(r)'],"
            "capture_output=True,text=True,close_fds=False).stdout.strip())"
        )
    )
    assert fds["stdout"].strip() == "[]", fds


def test_sub_015_pid_limit_under_p1(p1: Path, sandbox: dc.TaskSandbox) -> None:
    pol = copy.deepcopy(POLICY)
    pol["limits"]["process_count"] = 12
    g = gate(p1, pol)
    res = dc.DockerExecutor(sandbox).execute(
        g.py(
            "import os,time\nn=0\nwhile True:\n try:\n  if os.fork()==0:\n   time.sleep(20); os._exit(0)\n"
            "  n+=1\n except OSError:\n  print('stopped at', n); break\n",
            timeout=15,
        )
    )
    n = int(res["stdout"].split()[-1])
    assert n <= 12 and res["descendants_killed"] >= 1, res


def test_sub_016_concurrent_tasks_isolated(image: dc.WorkerImage, p1: Path, tmp_path: Path) -> None:
    results: dict[str, Any] = {}

    def task(name: str) -> None:
        with dc.TaskSandbox(image, f"conc-{name}") as sb:
            g = gate(p1)
            ex = dc.DockerExecutor(sb)
            ex.execute(
                g.dispatch({"type": "write_file", "path": "mine.txt", "content": f"secret-{name}"})
            )
            time.sleep(0.5)
            r = ex.execute(sh(g, "cat /workspace/task/mine.txt; ls /workspace/task"))
            results[name] = r["stdout"]

    ts = [threading.Thread(target=task, args=(n,)) for n in ("a", "b", "c")]
    [t.start() for t in ts]
    [t.join() for t in ts]
    for n in ("a", "b", "c"):
        assert results[n].startswith(f"secret-{n}"), results
        assert all(f"secret-{o}" not in results[n] for o in "abc" if o != n), results


def test_sub_017_narrowing_applies_to_next_action(p1: Path, sandbox: dc.TaskSandbox) -> None:
    g = gate(p1)
    ex = dc.DockerExecutor(sandbox)
    assert (
        ex.execute(g.dispatch({"type": "write_file", "path": "a.txt", "content": "1"}))["status"]
        == "completed"
    )
    narrowed = copy.deepcopy(POLICY)
    narrowed["task_id"] = g.ctx["task_id"]
    narrowed["filesystem"]["read_only"].append("/workspace/task")
    narrowed["filesystem"]["read_write"] = ["/tmp", "/dev/null"]
    r = g.c.apply_narrowing(
        task_id=g.ctx["task_id"],
        epoch_id=g.ctx["epoch_id"],
        expected_policy_hash=g.ctx["policy_hash"],
        proposed_policy_json=json.dumps(narrowed),
        reason="verification stage",
    )
    g.ctx["policy_hash"] = r["policy_hash"]
    # Policy gate refuses the broker write ...
    d = g.c.evaluate_action(
        **g.ctx,
        run_id="run-test",
        action_id="after-1",
        action={"type": "write_file", "path": "a.txt", "content": "2"},
    )
    assert d["decision"] == "DENY" and d["reason_code"] == "PATH_NOT_PERMITTED"
    # ... and code that writes directly is stopped by the kernel in the new container.
    res = ex.execute(sh(g, "echo 2 > /workspace/task/a.txt; echo rc=$?"))
    assert res["confinement"]["landlock"]["rules"], res
    assert "rc=1" in res["stdout"] or "Permission denied" in res["stderr"], res
    assert res["policy_hash"] == r["policy_hash"]


def test_sub_018_no_process_survives_into_narrowed_epoch(
    p1: Path, sandbox: dc.TaskSandbox, tmp_path: Path
) -> None:
    g = gate(p1)
    ex = dc.DockerExecutor(sandbox)
    # Action 1 (broad policy) starts a detached writer meant to outlive it.
    ex.execute(
        sh(
            g,
            "setsid sh -c 'for i in $(seq 1 60); do echo $i >> /workspace/task/log; sleep 0.1; done' "
            ">/dev/null 2>&1 & sleep 0.3",
        )
    )
    narrowed = copy.deepcopy(POLICY)
    narrowed["task_id"] = g.ctx["task_id"]
    narrowed["filesystem"]["read_only"].append("/workspace/task")
    narrowed["filesystem"]["read_write"] = ["/tmp", "/dev/null"]
    r = g.c.apply_narrowing(
        task_id=g.ctx["task_id"],
        epoch_id=g.ctx["epoch_id"],
        expected_policy_hash=g.ctx["policy_hash"],
        proposed_policy_json=json.dumps(narrowed),
        reason="narrow",
    )
    g.ctx["policy_hash"] = r["policy_hash"]
    before = files(sandbox, tmp_path).get("log", "")
    time.sleep(1.0)
    after = files(sandbox, tmp_path).get("log", "")
    assert before == after, "a process from the earlier action kept writing after narrowing"
    assert 0 < len(before.split()) < 60
