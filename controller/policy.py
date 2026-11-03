"""Defensive, *non-authoritative* policy checks on the Python side.

The controller checks the shape of a policy before sending it to ``ratchetd``,
so that obviously malformed input fails early with a clear message. This is
defense in depth only: a policy that passes here may still be rejected by the
Rust validator, and Python never treats its own check as a grant (STK-001).
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

SCHEMA_PATH = Path(__file__).resolve().parent.parent / "schemas" / "policy.schema.json"
MAX_POLICY_BYTES = 256 * 1024


class PolicyShapeError(ValueError):
    """The policy document is malformed (pre-check failed)."""

    def __init__(self, issues: list[str]) -> None:
        super().__init__("; ".join(issues))
        self.issues = issues


def _reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise PolicyShapeError([f"duplicate key {key!r}"])
        out[key] = value
    return out


@cache
def _validator() -> Draft202012Validator:
    schema = json.loads(SCHEMA_PATH.read_text())
    Draft202012Validator.check_schema(schema)
    return Draft202012Validator(schema)


def precheck_policy_text(text: str) -> dict[str, Any]:
    """Parse and shape-check a policy. Raises :class:`PolicyShapeError`."""
    if len(text.encode()) > MAX_POLICY_BYTES:
        raise PolicyShapeError([f"policy exceeds {MAX_POLICY_BYTES} bytes"])
    try:
        doc = json.loads(text, object_pairs_hook=_reject_duplicates)
    except json.JSONDecodeError as exc:
        raise PolicyShapeError([f"invalid JSON: {exc}"]) from exc
    return precheck_policy(doc)


def precheck_policy(doc: Any) -> dict[str, Any]:
    """Shape-check an already-parsed policy. Raises :class:`PolicyShapeError`."""
    errors = sorted(_validator().iter_errors(doc), key=lambda e: list(e.absolute_path))
    if errors:
        raise PolicyShapeError(
            [f"$.{'.'.join(str(p) for p in e.absolute_path) or ''}: {e.message}" for e in errors]
        )
    assert isinstance(doc, dict)
    return doc
