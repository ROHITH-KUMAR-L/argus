"""STK-002: Python defensive checks and the Rust validator agree on the shared vectors.

* Every vector Rust accepts must pass the Python shape pre-check (no false
  rejections from the defensive layer).
* Every vector whose expected failure is a *shape* error must also be rejected
  by the Python pre-check.
* With the ``rust`` marker, the real ``argus-policy`` binary is run on every
  vector and must produce the expected result.
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any

import pytest

from controller.policy import PolicyShapeError, precheck_policy_text

ROOT = Path(__file__).resolve().parents[2]
VECTORS = json.loads((ROOT / "tests/fixtures/policy_vectors.json").read_text())["vectors"]
SHAPE_CODES = {
    "MISSING_FIELD",
    "UNKNOWN_FIELD",
    "WRONG_TYPE",
    "INVALID_VALUE",
    "INVALID_JSON",
    "DUPLICATE_FIELD",
    "UNSUPPORTED_SCHEMA_VERSION",
    "APPROVAL_MODE_UNSUPPORTED",
    "LIMIT_INVALID",
    "INVALID_TASK_ID",
}


def _text(v: dict[str, Any]) -> str:
    return v["raw"] if "raw" in v else json.dumps(v["policy"])


@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_python_precheck_consistent_with_expectation(vector: dict[str, Any]) -> None:
    text = _text(vector)
    if vector["expect"] == "ACCEPT":
        precheck_policy_text(text)
    elif vector["expect"] in SHAPE_CODES:
        with pytest.raises(PolicyShapeError):
            precheck_policy_text(text)


def test_templates_pass_precheck() -> None:
    for name in ("python-task", "c-build", "test-only"):
        precheck_policy_text((ROOT / f"config/templates/{name}.json").read_text())


def _argus_policy() -> Path:
    exe = ROOT / "target/debug/argus-policy"
    if not exe.exists():
        pytest.skip("argus-policy not built (run `cargo build`)")
    return exe


@pytest.mark.rust
@pytest.mark.parametrize("vector", VECTORS, ids=[v["id"] for v in VECTORS])
def test_rust_cli_matches_vectors(vector: dict[str, Any]) -> None:
    proc = subprocess.run(
        [str(_argus_policy()), "validate", "-"],
        input=_text(vector),
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    report = json.loads(proc.stdout)
    if vector["expect"] == "ACCEPT":
        assert proc.returncode == 0, report
        assert report["policy_hash"].startswith("sha256:")
    else:
        assert proc.returncode == 1, report
        assert vector["expect"] in {e["code"] for e in report["errors"]}, report
