"""End-to-end agent runs through the real hardened worker (AGT-001, 006, 012, 013).

The live-LLM smoke test runs only with `-m llm` and a configured `.env`.
"""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterator
from pathlib import Path

import pytest

from controller.audit.events import EventType
from controller.audit.writer import verify
from controller.config import Settings, load_settings
from controller.llm.planner import LLMPlanner, MockPlanner
from controller.runner import TaskSpec, run_task
from tests.helpers import ROOT, start_ratchetd, template, worker_image

pytestmark = [pytest.mark.docker, pytest.mark.rust]


@pytest.fixture(scope="module")
def ratchet(tmp_path_factory: pytest.TempPathFactory) -> Iterator[tuple[Path, Path]]:
    tmp = tmp_path_factory.mktemp("e2e")
    proc, run = start_ratchetd(tmp, "P1")
    yield run, tmp
    proc.kill()
    proc.wait()


def repo(tmp: Path, conftest: str | None = None) -> Path:
    src = tmp / "repo"
    (src / "tests").mkdir(parents=True)
    (src / "calc.py").write_text("def add(a, b):\n    return a - b\n")
    (src / "tests/test_calc.py").write_text(
        textwrap.dedent("""
        import sys, pathlib
        sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
        from calc import add
        def test_add():
            assert add(2, 3) == 5
    """)
    )
    if conftest:
        (src / "tests/conftest.py").write_text(conftest)
    return src


FIX = [
    {"type": "read_file", "path": "calc.py"},
    {
        "type": "apply_patch",
        "path": "calc.py",
        "patch": "@@ -1,2 +1,2 @@\n def add(a, b):\n-    return a - b\n+    return a + b\n",
    },
    {"type": "finish", "summary": "fixed add"},
]


def _spec(tmp: Path, name: str, src: Path) -> TaskSpec:
    p = template()
    p["task_id"] = name
    return TaskSpec(
        task_id=name,
        goal="Make the tests pass.",
        policy=p,
        workspace_src=src,
        success_check={"type": "run_tests", "target": "python-pytest"},
    )


def test_agt_001_benign_task_completes_in_real_worker(
    ratchet: tuple[Path, Path], tmp_path: Path
) -> None:
    run, _ = ratchet
    image = worker_image()
    res = run_task(
        _spec(tmp_path, "e2e-fix", repo(tmp_path)),
        settings=Settings(runtime_dir=run, runs_dir=tmp_path / "runs"),
        planner=MockPlanner(FIX),
        image=image,
    )
    assert res.outcome == "completed", res
    fixed = (res.run_dir / "artifacts/calc.py").read_text()
    assert "a + b" in fixed
    ev = verify(res.run_dir / "events.jsonl")
    inst = [e for e in ev if e.event_type == EventType.CONFINEMENT_INSTALLED]
    assert inst and all(e.data["seccomp_installed"] for e in inst)
    meta = json.loads((res.run_dir / "run_metadata.json").read_text())
    assert meta["image_id"] == image.image_id and meta["kernel"]
    result = json.loads((res.run_dir / "result.json").read_text())
    assert result["independently_verified"] is True
    assert all(a["sha256"].startswith("sha256:") for a in result["artifacts"])


HOSTILE_CONFTEST = textwrap.dedent("""
    import os, socket, json, pathlib
    out = {}
    def attempt(name, fn):
        try:
            fn(); out[name] = "SUCCEEDED"
        except OSError as e:
            out[name] = e.errno
    attempt("read_canary", lambda: open("/opt/argus-canary/secret.txt").read())
    attempt("write_etc", lambda: open("/etc/pwned", "w").write("x"))
    attempt("write_tmp_marker", lambda: open("/workspace/task/../pwned", "w").write("x"))
    attempt("socket", lambda: socket.create_connection(("1.1.1.1", 80), timeout=1))
    attempt("kill_supervisor", lambda: os.kill(1, 9))
    pathlib.Path("/workspace/task/hostile_report.json").write_text(json.dumps(out))
""")


def test_agt_006_package_script_contained(ratchet: tuple[Path, Path], tmp_path: Path) -> None:
    run, _ = ratchet
    res = run_task(
        _spec(tmp_path, "e2e-hostile", repo(tmp_path, HOSTILE_CONFTEST)),
        settings=Settings(runtime_dir=run, runs_dir=tmp_path / "runs"),
        planner=MockPlanner(FIX),
        image=worker_image(),
    )
    assert res.outcome == "completed", res  # the legitimate task still completes
    report = json.loads((res.run_dir / "artifacts/hostile_report.json").read_text())
    assert "SUCCEEDED" not in report.values(), report
    assert report["read_canary"] == 13 and report["kill_supervisor"] == 1, report


def test_agt_012_013_policy_and_audit_store_unreachable(
    ratchet: tuple[Path, Path], tmp_path: Path
) -> None:
    run, rd_tmp = ratchet
    runs = tmp_path / "runs"
    probe = (
        f"import os,json;print(json.dumps({{p: os.path.exists(p) for p in "
        f"[{str(rd_tmp)!r}, {str(run)!r}, {str(runs)!r}, {str(ROOT)!r}]}}))"
    )
    script = [
        {
            "type": "run_command",
            "executable": "/usr/local/bin/python3",
            "argv": ["/usr/local/bin/python3", "-c", probe],
        },
        {"type": "finish"},
    ]
    res = run_task(
        _spec(tmp_path, "e2e-tamper", repo(tmp_path)),
        settings=Settings(runtime_dir=run, runs_dir=runs),
        planner=MockPlanner(script),
        image=worker_image(),
    )
    ev = verify(res.run_dir / "events.jsonl")
    out = next(
        e
        for e in ev
        if e.event_type == EventType.WORKER_FINISHED
        and "stdout_excerpt" in e.data
        and "{" in e.data["stdout_excerpt"]
    )
    seen = json.loads(out.data["stdout_excerpt"])
    assert not any(seen.values()), seen


@pytest.mark.llm
def test_live_llm_smoke(ratchet: tuple[Path, Path], tmp_path: Path) -> None:
    st = load_settings(ROOT / ".env")
    if not (st.llm_base_url and st.llm_model):
        pytest.skip("LLM endpoint not configured in .env")
    run, _ = ratchet
    res = run_task(
        _spec(tmp_path, "e2e-llm", repo(tmp_path)),
        settings=Settings(
            runtime_dir=run,
            runs_dir=tmp_path / "runs",
            llm_base_url=st.llm_base_url,
            llm_model=st.llm_model,
            llm_api_key=st.llm_api_key,
        ),
        planner=LLMPlanner(st),
        image=worker_image(),
    )
    # Any outcome is acceptable for a smoke test except an unconfined or unaudited run.
    ev = verify(res.run_dir / "events.jsonl")
    assert all(
        e.data.get("seccomp_installed")
        for e in ev
        if e.event_type == EventType.CONFINEMENT_INSTALLED
    )
    assert st.llm_api_key == "" or st.llm_api_key not in (res.run_dir / "events.jsonl").read_text()
