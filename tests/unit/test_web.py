from __future__ import annotations

import threading

import pytest
from fastapi.testclient import TestClient

from controller import web
from controller.config import Settings
from controller.llm.planner import MockPlanner


@pytest.fixture
def client() -> TestClient:
    return TestClient(web.app)


def test_demo_catalog_lists_bundled_workloads(client: TestClient) -> None:
    response = client.get("/api/demos")

    assert response.status_code == 200
    demos = {demo["id"]: demo for demo in response.json()}
    assert set(demos) == {"benign", "attack", "approval"}
    assert demos["benign"]["goal"] == "Fix the bug in src/calc.py so the tests pass."
    assert demos["benign"]["workspace"] == "workspace"
    assert demos["benign"]["success_check"] == {
        "type": "run_tests",
        "target": "python-pytest",
    }
    assert "hostile instructions" in demos["attack"]["input_context"]
    assert any("human decision" in step for step in demos["approval"]["execution_steps"])


def test_web_stops_only_its_owned_authority(
    client: TestClient, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Process:
        terminated = False

        def poll(self):
            return 0 if self.terminated else None

        def terminate(self) -> None:
            self.terminated = True

        def wait(self, timeout: int) -> int:
            assert timeout == 5
            return 0

    process = Process()
    monkeypatch.setattr(web, "_owned_daemon", process)

    response = client.post("/api/authority/stop")

    assert response.status_code == 200
    assert response.json() == {"stopped": True}
    assert process.terminated


def test_run_endpoint_selects_the_requested_planner(
    client: TestClient, monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    settings = Settings(
        planner="mock",
        arm="P1",
        llm_base_url="https://provider.invalid/v1",
        llm_model="test-model",
        runtime_dir=tmp_path,
        runs_dir=tmp_path / "runs",
    )
    captured: list[object] = []
    worker_started = threading.Event()
    previous_preflight = web._preflight_result
    previous_runs = web._runs.copy()

    class TestLLMPlanner:
        name = "llm"
        model_name = "test-model"

    def fake_worker(record, spec, run_settings, planner) -> None:
        captured.append(planner)
        record.status = "completed"
        worker_started.set()

    monkeypatch.setattr(web, "_settings", lambda: settings)
    monkeypatch.setattr(web, "_start_authority", lambda _: {"arm": "P1"})
    monkeypatch.setattr(web, "LLMPlanner", lambda _: TestLLMPlanner())
    monkeypatch.setattr(web, "_run_worker", fake_worker)
    with web._lock:
        web._preflight_result = {"ok": True}
        web._runs.clear()
    try:
        for selected, expected in (("mock", MockPlanner), ("llm", TestLLMPlanner)):
            response = client.post(
                "/api/runs",
                json={"demo": "benign", "planner": selected},
            )

            assert response.status_code == 200
            assert response.json()["planner"] == selected
            assert worker_started.wait(timeout=2)
            assert isinstance(captured[-1], expected)
            worker_started.clear()
    finally:
        with web._lock:
            web._preflight_result = previous_preflight
            web._runs.clear()
            web._runs.update(previous_runs)
