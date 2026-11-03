"""STK-001 (responsibility boundary) and STK-017 (dependency reproducibility)."""

from __future__ import annotations

import ast
import importlib.metadata as md
import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CONTROLLER = ROOT / "controller"


def _functions() -> dict[str, str]:
    out = {}
    for f in CONTROLLER.rglob("*.py"):
        for node in ast.walk(ast.parse(f.read_text())):
            if isinstance(node, ast.FunctionDef):
                out[f"{f.relative_to(ROOT)}::{node.name}"] = node.name
    return out


def test_stk_001_python_does_not_implement_the_authority() -> None:
    names = _functions()
    forbidden = re.compile(
        r"(is_subset|expansion_delta|subset|ratchet|authorize|grant|"
        r"canonical(ize|_json)|policy_hash|validate_policy(?!_)|approve)",
        re.I,
    )
    allowed = {"controller/rust_client.py", "controller/cli.py", "controller/audit/bridge.py"}
    offenders = [
        k for k, n in names.items() if forbidden.search(n) and k.split("::")[0] not in allowed
    ]
    assert offenders == [], offenders
    # Only ratchetd produces dispatches: the controller never builds a WorkerRequest.
    for f in CONTROLLER.rglob("*.py"):
        text = f.read_text()
        assert '"request_version":' not in text or f.name == "executor.py", f
        # Policy hashes come from Rust only; sha256 in Python is used for the audit
        # chain, artifact hashes and proposal digests, never over a policy.
        assert not re.search(r"sha256\([^)]*polic", text), f


def test_stk_001_rust_owns_policy_crates() -> None:
    members = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["members"]
    for crate in (
        "policy-validator",
        "privilege-ratchet",
        "linux-confinement",
        "execution-launcher",
        "process-supervisor",
        "protocol",
        "ratchetd",
    ):
        assert f"crates/{crate}" in members


def test_stk_017_installed_versions_match_lockfile() -> None:
    lock = tomllib.loads((ROOT / "uv.lock").read_text())
    pinned = {p["name"]: p["version"] for p in lock["package"] if "version" in p}
    for pkg in ("langgraph", "langchain-core", "langchain-openai", "pydantic", "jsonschema"):
        assert md.version(pkg) == pinned[pkg], pkg
    cargo_lock = (ROOT / "Cargo.lock").read_text()
    for crate in ("landlock", "seccompiler", "serde_json"):
        assert re.search(rf'name = "{crate}"\nversion = "[0-9.]+"', cargo_lock), crate
