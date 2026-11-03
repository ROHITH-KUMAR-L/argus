"""Docker outer boundary: DKR-001…017, STK-016, container-side RES and SUB lifecycle.

Dispatches come from a real ratchetd. B0 (Docker boundary only, no project
Landlock/seccomp) is what the outer-isolation tests examine; B1/P1 must fail
closed until Phases 6-7. Hostile probes (fork bomb, memory, disk fill) run
only inside the disposable worker.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from controller import docker_client as dc
from controller import preflight
from controller.rust_client import RatchetClient
from controller.workspace import build_stage_archive, safe_extract

ROOT = Path(__file__).resolve().parents[2]
RATCHETD = ROOT / "target/debug/ratchetd"
pytestmark = [pytest.mark.docker, pytest.mark.rust]
PY = "/usr/local/bin/python3"


def _image() -> dc.WorkerImage:
    try:
        dc.ping()
        img = dc.WorkerImage.from_lock()
        img.verify_present()
        return img
    except (dc.DockerUnavailable, dc.ConfigDrift) as exc:
        pytest.skip(f"docker/worker image unavailable: {exc}")


@pytest.fixture(scope="module")
def image() -> dc.WorkerImage:
    return _image()


def _start_ratchetd(tmp: Path, arm: str) -> tuple[subprocess.Popen[bytes], Path]:
    if not RATCHETD.exists():
        pytest.skip("ratchetd not built")
    run = tmp / f"run-{arm}"
    proc = subprocess.Popen(
        [
            str(RATCHETD),
            "--runtime-dir",
            str(run),
            "--state-dir",
            str(tmp / f"state-{arm}"),
            "--arm",
            arm,
        ],
        stderr=subprocess.DEVNULL,
    )
    deadline = time.monotonic() + 10
    while not (run / "ratchetd.ready").exists():
        assert proc.poll() is None and time.monotonic() < deadline
        time.sleep(0.02)
    return proc, run


class Gate:
    """Open one task on ratchetd and turn actions into dispatches."""

    def __init__(self, run: Path, task: str, overrides: dict[str, Any] | None = None) -> None:
        p = json.loads((ROOT / "config/templates/python-task.json").read_text())
        p["task_id"] = task
        p["commands"]["allowed_executables"] = [PY, "/usr/bin/sh"]
        p["commands"]["shell"] = "allow"
        for k, v in (overrides or {}).items():
            p[k] = {**p[k], **v}
        self.c = RatchetClient(run)
        t = self.c.open_task(task, json.dumps(p))
        self.ctx = {"task_id": task, "epoch_id": t["epoch_id"], "policy_hash": t["policy_hash"]}
        self.n = 0

    def dispatch(self, action: dict[str, Any]) -> dict[str, Any]:
        self.n += 1
        d = self.c.evaluate_action(
            **self.ctx, run_id="run-dkr", action_id=f"a{self.n}", action=action
        )
        assert d["decision"] == "ALLOW", d
        out: dict[str, Any] = d["dispatch"]
        return out


@pytest.fixture(scope="module")
def b0(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    proc, run = _start_ratchetd(tmp_path_factory.mktemp("rd"), "B0")
    yield run
    proc.kill()
    proc.wait()


@pytest.fixture
def sandbox(image: dc.WorkerImage) -> Iterator[dc.TaskSandbox]:
    with dc.TaskSandbox(image, "dkr", size_bytes=16 * 1024 * 1024) as sb:
        yield sb


def _py(gate: Gate, code: str, timeout: int = 30) -> dict[str, Any]:
    return gate.dispatch(
        {
            "type": "run_command",
            "executable": PY,
            "argv": [PY, "-c", code],
            "timeout_seconds": timeout,
        }
    )


def _run(sb: dc.TaskSandbox, d: dict[str, Any]) -> dict[str, Any]:
    return dc.DockerExecutor(sb).execute(d)


# ---------------------------------------------------------------- preflight


def test_preflight_passes_on_this_host(image: dc.WorkerImage) -> None:
    rep = preflight.run(image)
    assert rep.ok, {"failures": rep.failures(), "details": rep.details}


def test_dkr_001_to_012_from_inside(
    image: dc.WorkerImage, b0: Path, sandbox: dc.TaskSandbox
) -> None:
    os.environ["ARGUS_TEST_CANARY_TOKEN"] = "canary-should-never-reach-worker"
    g = Gate(b0, "dkr-inside")
    probe = (
        "import os,json,socket\n"
        "st=open('/proc/self/status').read()\n"
        "def f(k): return [l.split(':',1)[1].strip() for l in st.splitlines() if l.startswith(k+':')][0]\n"
        "r={'uid':f('Uid'),'cap':f('CapEff'),'nnp':f('NoNewPrivs'),'env':dict(os.environ)}\n"
        "try:\n open('/etc/x','w'); r['rootw']=True\nexcept OSError as e: r['rootw']=e.errno\n"
        "try:\n s=socket.create_connection(('1.1.1.1',53),timeout=2); r['net']='connected'\n"
        "except OSError as e: r['net']=e.errno\n"
        "r['sock']=os.path.exists('/var/run/docker.sock') or os.path.exists('/run/docker.sock')\n"
        f"r['canary']=os.path.exists({str(Path.home())!r})\n"
        "print(json.dumps(r))"
    )
    res = _run(sandbox, _py(g, probe))
    assert res["status"] == "completed", res
    r = json.loads(res["stdout"])
    assert r["uid"].split()[0] == "10001"  # DKR-001
    assert r["cap"] == "0000000000000000"  # DKR-002
    assert r["nnp"] == "1"  # DKR-003
    assert r["rootw"] == 30  # DKR-004 (EROFS)
    assert r["net"] != "connected"  # DKR-005
    assert r["sock"] is False  # DKR-007
    assert r["canary"] is False  # DKR-008/009 host home
    assert "ARGUS_TEST_CANARY_TOKEN" not in r["env"]  # DKR-010 / STK-016
    assert not any("KEY" in k and k != "GPG_KEY" for k in r["env"])


def test_dkr_006_011_012_inspect(image: dc.WorkerImage, b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "dkr-inspect")
    ex = dc.DockerExecutor(sandbox)
    ex.execute(_py(g, "print(1)"))
    i = ex.last_inspect
    assert i is not None
    h = i["HostConfig"]
    assert h["Privileged"] is False  # DKR-011
    assert h["NetworkMode"] == "none" and h["PidMode"] == "" and h["IpcMode"] == "private"
    assert h["PidsLimit"] == 32 + dc.PIDS_OVERHEAD  # DKR-006
    assert h["Memory"] == 536870912 + dc.MEMORY_OVERHEAD and h["NanoCpus"] == 10**9
    assert i["Image"] == image.image_id  # DKR-014


def test_dkr_013_and_res_010_no_leaks(image: dc.WorkerImage, b0: Path) -> None:
    before = dc.leaked_resources()
    g = Gate(b0, "dkr-leak")
    with dc.TaskSandbox(image, "leak") as sb:
        for _ in range(5):
            assert _run(sb, _py(g, "print('ok')"))["status"] == "completed"
    after = dc.leaked_resources()
    assert after == before, (before, after)


def test_dkr_014_image_mismatch_refused(image: dc.WorkerImage) -> None:
    wrong = dc.WorkerImage(tag=image.tag, image_id="sha256:" + "0" * 64)
    with pytest.raises(dc.ConfigDrift):
        wrong.verify_present()


def test_dkr_015_rootless_status() -> None:
    info = subprocess.run(
        ["docker", "info", "--format", "{{json .SecurityOptions}}"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    if "rootless" not in info:
        pytest.skip("UNSUPPORTED on this host: Docker daemon is rootful (documented limitation)")


def test_dkr_016_docker_unavailable_no_fallback(
    monkeypatch: pytest.MonkeyPatch, image: dc.WorkerImage
) -> None:
    monkeypatch.setenv("DOCKER_HOST", "unix:///nonexistent/docker.sock")
    with pytest.raises(dc.DockerUnavailable):
        dc.ping()
    with pytest.raises(dc.DockerUnavailable):
        dc.TaskSandbox(image, "nodocker").create()
    assert preflight.run(image).ok is False


def test_dkr_017_config_drift_rejected(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, b0: Path, sandbox: dc.TaskSandbox
) -> None:
    g = Gate(b0, "dkr-drift")
    good = dc.worker_flags
    for drop in ["--read-only", "--cap-drop", "--security-opt", "--network", "--pids-limit"]:

        def weakened(limits: dict[str, int], volume: str, drop: str = drop) -> list[str]:
            f = good(limits, volume)
            i = f.index(drop)
            return f[:i] + f[i + (1 if drop == "--read-only" else 2) :]

        monkeypatch.setattr(dc, "worker_flags", weakened)
        with pytest.raises(dc.ConfigDrift):
            dc.DockerExecutor(sandbox).execute(_py(g, "open('/workspace/task/ran','w')"))
    monkeypatch.setattr(dc, "worker_flags", good)
    arch = safe_extract(sandbox.export(), tmp_path / "export", strip_prefix="task")
    assert "ran" not in [a.path for a in arch], "a drifted container must never start"


def test_check_config_unit() -> None:
    base = {
        "Image": "sha256:x",
        "Config": {"User": "10001:10001"},
        "HostConfig": {
            "Privileged": False,
            "ReadonlyRootfs": True,
            "NetworkMode": "none",
            "CapDrop": ["ALL"],
            "CapAdd": None,
            "SecurityOpt": ["no-new-privileges:true"],
            "PidMode": "",
            "IpcMode": "private",
            "Binds": None,
            "Devices": [],
            "PidsLimit": 36,
            "Memory": 1,
            "MemorySwap": 1,
            "NanoCpus": 1,
            "Tmpfs": {"/tmp": "x"},
        },
        "Mounts": [{"Type": "volume", "Name": "v", "Destination": "/workspace/task"}],
    }
    assert dc.check_config(base, image_id="sha256:x", volume="v") == []
    for path, value in [
        (("HostConfig", "Privileged"), True),
        (("HostConfig", "CapAdd"), ["SYS_ADMIN"]),
        (("HostConfig", "PidMode"), "host"),
        (("HostConfig", "Binds"), ["/:/host"]),
        (("HostConfig", "SecurityOpt"), ["seccomp=unconfined"]),
        (("Config", "User"), "0:0"),
    ]:
        bad = json.loads(json.dumps(base))
        bad[path[0]][path[1]] = value
        assert dc.check_config(bad, image_id="sha256:x", volume="v"), path


# ------------------------------------------------- B1/P1 fail closed (FAIL-*)


def test_kernel_arms_fail_closed_in_container(
    tmp_path: Path, image: dc.WorkerImage, sandbox: dc.TaskSandbox
) -> None:
    proc, run = _start_ratchetd(tmp_path, "P1")
    try:
        g = Gate(run, "dkr-p1")
        res = _run(sandbox, g.dispatch({"type": "write_file", "path": "ran.txt", "content": "x"}))
        assert res["status"] == "confinement_failed", res
        names = [
            a.path for a in safe_extract(sandbox.export(), tmp_path / "x", strip_prefix="task")
        ]
        assert "ran.txt" not in names
    finally:
        proc.kill()
        proc.wait()


# -------------------------------------------- staging/export through Docker


def test_stage_run_export_roundtrip(tmp_path: Path, b0: Path, sandbox: dc.TaskSandbox) -> None:
    src = tmp_path / "repo"
    (src / "pkg").mkdir(parents=True)
    (src / "pkg/mod.py").write_text("def f():\n    return 41\n")
    (src / "README.md").write_text("not approved\n")
    sandbox.stage(build_stage_archive(src, include=["pkg/mod.py"]))
    g = Gate(b0, "dkr-stage")
    patch = "@@ -2,1 +2,1 @@\n-    return 41\n+    return 42\n"
    assert (
        _run(
            sandbox,
            g.dispatch(
                {"type": "apply_patch", "path": "/workspace/task/pkg/mod.py", "patch": patch}
            ),
        )["status"]
        == "completed"
    )
    res = _run(
        sandbox,
        _py(
            g, "import sys; sys.path.insert(0,'/workspace/task'); import pkg.mod as m; print(m.f())"
        ),
    )
    assert res["stdout"].strip() == "42", res
    arts = safe_extract(sandbox.export(), tmp_path / "out", strip_prefix="task")
    assert [a.path for a in arts] == ["pkg/mod.py"]
    assert "return 42" in (tmp_path / "out/pkg/mod.py").read_text()


# ------------------------------------- resources and lifecycle in container


def test_res_002_memory_bounded(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "res-mem", {"limits": {"memory_bytes": 134217728}})
    res = _run(sandbox, _py(g, "x = bytearray(1024*1024*1024); print('allocated')"))
    assert res["status"] in ("failed", "error"), res
    assert "allocated" not in res.get("stdout", "")


def test_res_003_fork_bomb_bounded(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "res-fork", {"limits": {"process_count": 16}})
    bomb = (
        "import os,time\nn=0\nwhile True:\n try:\n  if os.fork()==0:\n   time.sleep(30); os._exit(0)\n"
        "  n+=1\n except OSError:\n  print('limit after', n); break\n"
    )
    t0 = time.monotonic()
    res = _run(sandbox, _py(g, bomb, timeout=20))
    assert time.monotonic() - t0 < 30
    assert "limit after" in res["stdout"], res
    n = int(res["stdout"].split()[-1])
    assert n <= 16, n
    assert res["descendants_killed"] >= 1  # nothing survives the action


def test_res_006_scratch_exhaustion_bounded(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "res-disk", {"limits": {"file_size_bytes": 1073741824}})
    res = _run(
        sandbox,
        _py(
            g,
            "import errno\ntry:\n open('/workspace/task/fill','wb').write(b'0'*64*1024*1024)\n"
            "except OSError as e: print('errno', e.errno)",
        ),
    )
    assert "errno 28" in res["stdout"], res  # ENOSPC at the 16 MiB volume cap


def test_res_007_timeout_kills_worker(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "res-time")
    t0 = time.monotonic()
    res = _run(
        sandbox,
        g.dispatch(
            {
                "type": "run_command",
                "executable": "/usr/bin/sh",
                "argv": ["/usr/bin/sh", "-c", "sleep 100 & setsid sleep 100 & sleep 100"],
                "timeout_seconds": 2,
            }
        ),
    )
    assert res["status"] == "timeout" and time.monotonic() - t0 < 20, res
    assert dc._docker(["ps", "-q", "--filter", "label=argus.role=worker"]).stdout.strip() == b""


def test_res_008_output_flood_bounded(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "res-flood")
    res = _run(sandbox, _py(g, "import sys\nfor _ in range(200): sys.stdout.write('A'*65536)"))
    assert res["stdout_truncated"] is True and len(res["stdout"]) <= 256 * 1024


def test_res_012_worker_killed_is_not_success(b0: Path, sandbox: dc.TaskSandbox) -> None:
    import threading

    g = Gate(b0, "res-crash")
    ex = dc.DockerExecutor(sandbox)
    threading.Timer(1.5, ex.cancel_all).start()  # cancellation / crash mid-run
    res = ex.execute(_py(g, "import time; time.sleep(30); print('finished')", timeout=40))
    assert res["status"] != "completed", res
    assert "finished" not in res.get("stdout", "")


def test_sub_daemon_does_not_outlive_action_in_container(b0: Path, sandbox: dc.TaskSandbox) -> None:
    g = Gate(b0, "sub-daemon")
    res = _run(
        sandbox,
        g.dispatch(
            {
                "type": "run_command",
                "executable": "/usr/bin/sh",
                "argv": [
                    "/usr/bin/sh",
                    "-c",
                    "setsid sh -c 'sleep 60' & (sleep 60 &); echo started",
                ],
            }
        ),
    )
    assert res["status"] == "completed" and res["descendants_killed"] >= 1, res
