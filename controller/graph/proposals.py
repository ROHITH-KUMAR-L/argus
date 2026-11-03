"""Planner output schema and the narrow LangChain proposal tools.

Everything the planner produces is untrusted data. It is parsed into exactly
one of these Pydantic models (unknown fields, unknown types and oversized
values are rejected) and then sent to ``ratchetd`` for the authoritative
decision. The tools below only *describe* proposals; none of them executes
anything, and the registry deliberately has no shell, Docker, policy, host
filesystem or network tool (STK-008).
"""

from __future__ import annotations

import json
import re
from typing import Annotated, Any, Literal

from langchain_core.tools import StructuredTool
from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, ValidationError

MAX_PROPOSAL_BYTES = 256 * 1024
MAX_CONTENT = 200_000
REL_PATH = Field(default="", max_length=1024)


class _P(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    reason: str = Field(default="", max_length=1000)


class ListFiles(_P):
    type: Literal["list_files"]
    path: str = REL_PATH


class ReadFile(_P):
    type: Literal["read_file"]
    path: str = Field(min_length=1, max_length=1024)
    offset: int = Field(default=0, ge=0)
    length: int | None = Field(default=None, ge=1, le=1024 * 1024)


class WriteFile(_P):
    type: Literal["write_file"]
    path: str = Field(min_length=1, max_length=1024)
    content: str = Field(max_length=MAX_CONTENT)


class ApplyPatch(_P):
    type: Literal["apply_patch"]
    path: str = Field(min_length=1, max_length=1024)
    patch: str = Field(min_length=1, max_length=MAX_CONTENT)


class RunCommand(_P):
    type: Literal["run_command"]
    executable: str = Field(min_length=1, max_length=4096)
    # argv must be a JSON array of strings: a single shell string is rejected.
    argv: list[Annotated[str, Field(max_length=4096)]] = Field(min_length=1, max_length=256)
    cwd: str | None = Field(default=None, max_length=1024)
    timeout_seconds: int | None = Field(default=None, ge=1, le=600)


class RunTests(_P):
    type: Literal["run_tests"]
    target: str = Field(pattern=r"^[a-z0-9-]{1,64}$")


class RequestPermission(_P):
    type: Literal["request_permission"]
    reason: str = Field(min_length=1, max_length=1000)
    add_read_only: list[Annotated[str, Field(max_length=4096)]] = Field(default=[], max_length=16)
    add_read_write: list[Annotated[str, Field(max_length=4096)]] = Field(default=[], max_length=16)
    add_executables: list[Annotated[str, Field(max_length=4096)]] = Field(default=[], max_length=16)
    add_tools: list[Annotated[str, Field(max_length=64)]] = Field(default=[], max_length=8)


class Finish(_P):
    type: Literal["finish"]
    summary: str = Field(default="", max_length=4000)


ActionProposal = Annotated[
    ListFiles
    | ReadFile
    | WriteFile
    | ApplyPatch
    | RunCommand
    | RunTests
    | RequestPermission
    | Finish,
    Field(discriminator="type"),
]
_ADAPTER: TypeAdapter[Any] = TypeAdapter(ActionProposal)


class ProposalError(ValueError):
    """Planner output could not be parsed into exactly one valid proposal."""


_JSON_OBJ = re.compile(r"\{.*\}", re.S)


def parse_proposal(raw: Any) -> _P:
    """Parse untrusted planner output (dict or text containing one JSON object)."""
    if isinstance(raw, str):
        if len(raw.encode()) > MAX_PROPOSAL_BYTES:
            raise ProposalError("planner output exceeds size limit")
        m = _JSON_OBJ.search(raw)
        if not m:
            raise ProposalError("no JSON object in planner output")
        try:
            raw = json.loads(m.group(0))
        except json.JSONDecodeError as exc:
            raise ProposalError(f"invalid JSON: {exc.msg}") from exc
    if not isinstance(raw, dict):
        raise ProposalError("proposal must be a JSON object")
    if len(json.dumps(raw).encode()) > MAX_PROPOSAL_BYTES:
        raise ProposalError("planner output exceeds size limit")
    try:
        p: _P = _ADAPTER.validate_python(raw)
    except ValidationError as exc:
        raise ProposalError(
            "; ".join(f"{'.'.join(map(str, e['loc']))}: {e['msg']}" for e in exc.errors()[:5])
        ) from exc
    return p


def to_action(p: _P) -> dict[str, Any] | None:
    """Normalize a proposal into the ratchetd Action shape (None for finish).

    ``reason`` is planner commentary; only ``request_permission`` carries it
    to ratchetd (its schema has the field, the others reject unknown fields).
    """
    if isinstance(p, Finish):
        return None
    d = p.model_dump(exclude_none=True)
    if not isinstance(p, RequestPermission):
        d.pop("reason", None)
    return d


def _type_of(model: type[_P]) -> str:
    ann = model.model_fields["type"].annotation
    return str(getattr(ann, "__args__", [""])[0])


def _propose(model: type[_P]) -> Any:
    kind = _type_of(model)

    def fn(**kwargs: Any) -> dict[str, Any]:
        out = {"type": kind, **kwargs}
        parse_proposal(out)  # validates only; a proposal tool never executes anything
        return out

    return fn


_DOCS: dict[type[_P], str] = {
    ListFiles: "Propose listing files under a workspace-relative path.",
    ReadFile: "Propose reading a workspace-relative file (bounded).",
    WriteFile: "Propose creating or replacing a workspace-relative file.",
    ApplyPatch: "Propose applying a unified diff to one workspace-relative file.",
    RunCommand: "Propose running a registered executable with an argv array (no shell string).",
    RunTests: "Propose running a registered symbolic test target.",
    RequestPermission: "Ask a human for additional permissions (never granted by the model).",
    Finish: "Declare the task finished; the controller still verifies it independently.",
}


def proposal_tools() -> list[StructuredTool]:
    """The complete tool registry exposed to the model: proposals only."""
    tools = []
    for model, doc in _DOCS.items():
        schema = {k: v for k, v in model.model_json_schema().items()}
        props = {k: v for k, v in schema.get("properties", {}).items() if k != "type"}
        args_schema = {
            "type": "object",
            "properties": props,
            "required": [r for r in schema.get("required", []) if r != "type"],
            "additionalProperties": False,
        }
        tools.append(
            StructuredTool.from_function(
                func=_propose(model), name=_type_of(model), description=doc, args_schema=args_schema
            )
        )
    return tools
