"""Configuration and privacy defaults (STK-013, STACK-007)."""

from pathlib import Path

import pytest

from controller.config import enforce_tracing_default_off, load_settings


def test_tracing_forced_off_without_review() -> None:
    env = {"LANGSMITH_TRACING": "true", "LANGCHAIN_TRACING_V2": "true"}
    assert enforce_tracing_default_off(env) is False
    assert env["LANGSMITH_TRACING"] == "false"
    assert env["LANGCHAIN_TRACING_V2"] == "false"


def test_tracing_allowed_only_with_explicit_review() -> None:
    env = {"LANGSMITH_TRACING": "true", "ARGUS_TRACING_PRIVACY_REVIEWED": "true"}
    assert enforce_tracing_default_off(env) is True


def test_default_settings_are_mock_and_p1(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    for var in ("PLANNER", "ARGUS_ARM", "LLM_API_KEY", "LLM_BASE_URL", "LLM_MODEL"):
        monkeypatch.delenv(var, raising=False)
    s = load_settings(env_file=tmp_path / "missing.env")
    assert s.planner == "mock"
    assert s.arm == "P1"
    assert s.tracing_enabled is False


def test_api_key_never_in_redacted_view(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    envf = tmp_path / ".env"
    envf.write_text("LLM_API_KEY=sk-secret-value\nLLM_MODEL=m\n")
    monkeypatch.delenv("LLM_API_KEY", raising=False)
    s = load_settings(env_file=envf)
    assert s.llm_api_key == "sk-secret-value"
    assert "sk-secret-value" not in repr(s)
    assert "sk-secret-value" not in str(s.redacted())


def test_invalid_planner_rejected(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PLANNER", "shell")
    with pytest.raises(ValueError):
        load_settings(env_file=tmp_path / "missing.env")
