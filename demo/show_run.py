"""Print a run's audit log as a readable timeline (for demos).

uv run python demo/show_run.py            # latest run in runs/
uv run python demo/show_run.py runs/<run_id>
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from controller.audit.writer import verify  # noqa: E402

C = {"ok": "\033[32m", "bad": "\033[31m", "warn": "\033[33m", "dim": "\033[2m", "end": "\033[0m"}


def main() -> None:
    if len(sys.argv) > 1:
        run = Path(sys.argv[1])
    else:
        runs = sorted((ROOT / "runs").glob("run-*"), key=lambda p: p.stat().st_mtime)
        if not runs:
            sys.exit("no runs yet")
        run = runs[-1]
    events = verify(run / "events.jsonl")  # also proves the hash chain is intact
    result = json.loads((run / "result.json").read_text()) if (run / "result.json").exists() else {}
    print(f"\nRun {run.name}  ·  task {events[0].task_id}  ·  arm {events[0].arm}")
    print(f"{C['dim']}{len(events)} audit events, hash chain verified{C['end']}\n")
    for e in events:
        t, d = e.event_type, e.data
        if t == "ACTION_PROPOSED":
            p = d["proposal"]
            what = p.get("path") or " ".join(p.get("argv", [])[:3]) or p.get("target") or ""
            print(f"  planner proposes  {p['type']:<18} {str(what)[:70]}")
        elif t == "ACTION_ALLOWED":
            print(
                f"    {C['ok']}ALLOW{C['end']} {e.action} {(e.resource or '')[:60]}  (ratchetd policy gate)"
            )
        elif t == "ACTION_DENIED":
            print(
                f"    {C['bad']}DENY {C['end']} {e.action} {(e.resource or '')[:60]}  by {e.enforcement_layer}: {e.reason_code}"
            )
        elif t == "ACTION_APPROVAL_REQUIRED":
            print(f"    {C['warn']}APPROVAL REQUIRED{C['end']}: paused for a human decision")
        elif t == "PRIVILEGE_EXPANSION_APPROVED":
            print(f"    {C['warn']}APPROVED by human → new epoch {e.epoch}{C['end']}")
        elif t == "CONFINEMENT_INSTALLED":
            print(
                f"    {C['dim']}worker confined: Landlock ABI {d.get('landlock_handled_abi')} + "
                f"seccomp {d.get('seccomp_profile')} ({d.get('seccomp_mode')}){C['end']}"
            )
        elif t == "FILESYSTEM_DENIAL":
            print(f"    {C['bad']}KERNEL DENY{C['end']} ({e.enforcement_layer}): {e.resource}")
        elif t == "WORKER_FINISHED":
            out = (d.get("stdout_excerpt") or "").strip().replace("\n", " | ")
            err = (d.get("stderr_excerpt") or "").strip().replace("\n", " | ")
            line = f"    worker {d.get('status')} (exit {d.get('exit_code')})"
            if out:
                line += f"  stdout: {out[:110]}"
            if "permission denied" in (err + out).lower() or "errno 13" in (err + out).lower():
                line += f"\n    {C['bad']}KERNEL DENIED (Landlock){C['end']}: the code ran, the file access was refused"
            print(line)
        elif t in ("TASK_COMPLETED", "TASK_FAILED", "TASK_REJECTED"):
            colour = C["ok"] if t == "TASK_COMPLETED" else C["bad"]
            print(f"\n  {colour}{t}{C['end']} ({e.reason_code})")
    if result:
        print(
            f"\nOutcome: {result['outcome']} · independently verified: "
            f"{result['independently_verified']} · denials: {result['denials']}"
        )
        for a in result.get("artifacts", [])[:5]:
            if "path" in a:
                print(f"  artifact {a['path']}  {a['sha256'][:23]}…")
    print()


if __name__ == "__main__":
    main()
