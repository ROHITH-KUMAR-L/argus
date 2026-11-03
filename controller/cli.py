"""Command-line entry point (``argus``). Subcommands are added phase by phase."""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from pathlib import Path

from controller import __version__
from controller.config import load_settings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="argus", description="Argus controller CLI")
    parser.add_argument("--version", action="version", version=f"argus {__version__}")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("config", help="print the effective (redacted) controller settings")
    sub.add_parser("preflight", help="check that protected execution is available on this host")
    d = sub.add_parser("daemon", help="start ratchetd with the configured runtime/state dirs")
    d.add_argument("--arm", default=None, choices=["B0", "B1", "P1"])
    r = sub.add_parser("run", help="run one task spec (JSON) in a disposable Docker sandbox")
    r.add_argument("task", type=Path)
    r.add_argument("--planner", choices=["mock", "llm"], default=None)
    a = sub.add_parser(
        "approve", help="TRUSTED HUMAN CHANNEL: decide a pending privilege expansion"
    )
    a.add_argument("--task-id", required=True)
    a.add_argument("--expansion-id", required=True)
    a.add_argument("--approver", required=True)
    a.add_argument("--deny", action="store_true")
    args = parser.parse_args(argv)

    if args.command == "config":
        print(json.dumps(load_settings().redacted(), indent=2))
        return 0
    if args.command == "preflight":
        from controller import preflight

        rep = preflight.run()
        print(json.dumps({"ok": rep.ok, "checks": rep.checks, "details": rep.details}, indent=2))
        return 0 if rep.ok else 1
    if args.command == "daemon":
        st = load_settings()
        root = Path(__file__).resolve().parent.parent
        state_dir = Path(
            os.environ.get("ARGUS_STATE_DIR", Path.home() / ".local/state/argus/ratchetd")
        )
        os.execv(  # noqa: S606 - fixed trusted binary, argv array
            str(root / "target/debug/ratchetd"),
            [
                "ratchetd",
                "--runtime-dir",
                str(st.runtime_dir),
                "--state-dir",
                str(state_dir),
                "--arm",
                args.arm or st.arm,
            ],
        )
    if args.command == "approve":
        from controller.rust_client import ApprovalClient

        out = ApprovalClient(load_settings().runtime_dir).decide(
            task_id=args.task_id,
            expansion_id=args.expansion_id,
            approver=args.approver,
            approve=not args.deny,
        )
        print(json.dumps(out, indent=2))
        return 0
    if args.command == "run":
        return _run(args)
    parser.print_help()
    return 0


def _run(args: argparse.Namespace) -> int:
    from controller.llm.planner import LLMPlanner, MockPlanner, Planner
    from controller.runner import TaskSpec, run_task
    from controller.rust_client import RatchetClient

    st = load_settings()
    root = Path(__file__).resolve().parent.parent
    spec = TaskSpec.from_file(args.task, root)
    kind = args.planner or st.planner
    planner: Planner
    if kind == "llm":
        planner = LLMPlanner(st)
    else:
        planner = MockPlanner(json.loads(args.task.read_text()).get("mock_script", []))

    def wait_for_human(payload: dict[str, object]) -> None:
        print(json.dumps({"approval_required": payload}, indent=2), file=sys.stderr)
        print(
            "Decide in another terminal with:\n  argus approve --task-id "
            f"{payload['task_id']} --expansion-id {payload['expansion_id']} --approver <you>"
            " [--deny]",
            file=sys.stderr,
        )
        client = RatchetClient(st.runtime_dir)
        deadline = time.monotonic() + 900
        while time.monotonic() < deadline:
            s = client.get_state(str(payload["task_id"]))
            if str(payload["expansion_id"]) not in s["pending_expansions"]:
                return
            time.sleep(1)

    res = run_task(spec, settings=st, planner=planner, on_interrupt=wait_for_human)
    print(
        json.dumps(
            {
                "run_id": res.run_id,
                "outcome": res.outcome,
                "reason": res.outcome_reason,
                "run_dir": str(res.run_dir),
            },
            indent=2,
        )
    )
    return 0 if res.outcome == "completed" else 1


if __name__ == "__main__":
    sys.exit(main())
