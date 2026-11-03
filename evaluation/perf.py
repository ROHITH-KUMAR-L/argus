"""Performance measurements PERF-001 … PERF-010.

    uv run python -m evaluation.perf --batch evaluation/results/<batch> [--n 30]

Writes <batch>/perf.json and <batch>/perf.md. PERF-005/006/009 reuse the batch's
raw run records; the others are measured here on the same host and image.
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import threading
import time
from pathlib import Path
from typing import Any

from controller import docker_client as dc
from controller.workspace import build_stage_archive
from evaluation.harness import ARMS, start_daemons
from evaluation.metrics import pct
from tests.helpers import Gate, template

PY = "/usr/local/bin/python3"


def summary(xs: list[float]) -> dict[str, Any]:
    return {
        "n": len(xs),
        "median": round(statistics.median(xs), 2) if xs else None,
        "p95": pct(xs, 0.95),
        "raw": [round(x, 2) for x in xs],
    }


def perf_001_container_start(image: dc.WorkerImage, sb: dc.TaskSandbox, n: int) -> dict[str, Any]:
    flags = dc.worker_flags(template()["limits"], sb.volume)
    xs = []
    for _ in range(n):
        t = time.monotonic()
        dc._docker(["run", "--rm", *flags, image.tag, "--version"])
        xs.append((time.monotonic() - t) * 1000)
    return {"what": "docker run --rm of the hardened worker (--version), ms", **summary(xs)}


def perf_002_003_confinement_setup(
    image: dc.WorkerImage, sb: dc.TaskSandbox, n: int
) -> dict[str, Any]:
    out = {}
    for profile in ("python-build-v1", "python-strict-v1"):
        p = template()
        p["task_id"] = "bench"
        p["syscalls"]["profile"] = profile
        if profile == "python-strict-v1":
            p["commands"]["allowed_executables"] = [PY]
        flags = dc.worker_flags(p["limits"], sb.volume)
        proc = dc._docker(
            ["run", "-i", "--rm", *flags, image.tag, "--bench-confinement", str(n)],
            input=json.dumps(p).encode(),
            timeout=300,
        )
        out[profile] = json.loads(proc.stdout.decode().strip().splitlines()[-1])
    return {"what": "in-child install time (µs) measured inside the worker", **out}


def perf_004_noop(daemons: dict[str, Any], sb: dc.TaskSandbox, n: int) -> dict[str, Any]:
    pol = template()
    pol["commands"]["allowed_executables"] = [PY, "/usr/bin/true"]
    out = {}
    ex = dc.DockerExecutor(sb)
    for arm in ARMS:
        g = Gate(daemons[arm].runtime, f"perf-noop-{arm.lower()}", pol)
        worker, total = [], []
        for _ in range(n):
            d = g.dispatch(
                {"type": "run_command", "executable": "/usr/bin/true", "argv": ["/usr/bin/true"]}
            )
            t = time.monotonic()
            r = ex.execute(d)
            total.append((time.monotonic() - t) * 1000)
            worker.append(float(r["duration_ms"]))
        out[arm] = {"in_worker_ms": summary(worker), "per_action_container_ms": summary(total)}
    return {"what": "no-op command (/usr/bin/true)", **out}


def perf_007_multiprocess(daemons: dict[str, Any], sb: dc.TaskSandbox) -> dict[str, Any]:
    code = (
        "import subprocess,sys\nps=[subprocess.Popen([sys.executable,'-c','import time;time.sleep(0.3)'])"
        " for _ in range(10)]\n[p.wait() for p in ps]\nprint('ok')"
    )
    out = {}
    for arm in ARMS:
        g = Gate(daemons[arm].runtime, f"perf-mp-{arm.lower()}", template())
        r = dc.DockerExecutor(sb).execute(g.py(code))
        out[arm] = {
            "status": r["status"],
            "in_worker_ms": r["duration_ms"],
            "observed_processes": len(r.get("process_tree") or []),
            "peak_process_count_cgroup": (r.get("resource_usage") or {}).get("peak_process_count"),
            "pid_limit": 32 + dc.PIDS_OVERHEAD,
        }
    return {"what": "11-process task (parent + 10 children)", **out}


def perf_008_large_listing(
    daemons: dict[str, Any], image: dc.WorkerImage, tmp: Path
) -> dict[str, Any]:
    src = tmp / "big"
    for i in range(3000):
        d = src / f"d{i // 100:02d}"
        d.mkdir(parents=True, exist_ok=True)
        (d / f"f{i}.txt").write_text("x")
    with dc.TaskSandbox(image, "perf-big") as sb:
        sb.stage(build_stage_archive(src))
        g = Gate(daemons["P1"].runtime, "perf-list", template())
        t = time.monotonic()
        r = dc.DockerExecutor(sb).execute(g.dispatch({"type": "list_files", "path": ""}))
        wall = (time.monotonic() - t) * 1000
    data = r["file_result"]["data"]
    return {
        "what": "list_files over 3,030 entries (P1)",
        "status": r["status"],
        "entries_returned": len(data["entries"]),
        "truncated": data["truncated"],
        "result_bytes": len(json.dumps(r)),
        "wall_ms": round(wall, 1),
        "in_worker_ms": r["duration_ms"],
        "peak_memory_bytes": (r.get("resource_usage") or {}).get("peak_memory_bytes"),
    }


def perf_010_concurrent(daemons: dict[str, Any], image: dc.WorkerImage) -> dict[str, Any]:
    res: dict[str, Any] = {}

    def task(name: str) -> None:
        t = time.monotonic()
        with dc.TaskSandbox(image, f"perf-c-{name}") as sb:
            g = Gate(daemons["P1"].runtime, f"perf-conc-{name}", template())
            ex = dc.DockerExecutor(sb)
            ex.execute(g.dispatch({"type": "write_file", "path": "mine.txt", "content": name}))
            r = ex.execute(g.dispatch({"type": "list_files", "path": ""}))
        res[name] = {
            "ms": round((time.monotonic() - t) * 1000, 1),
            "sees": sorted(e["path"] for e in r["file_result"]["data"]["entries"]),
        }

    t0 = time.monotonic()
    ts = [threading.Thread(target=task, args=(f"t{i}",)) for i in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    isolated = all(v["sees"] == ["mine.txt"] for v in res.values())
    return {
        "what": "4 concurrent P1 tasks",
        "total_ms": round((time.monotonic() - t0) * 1000, 1),
        "per_task": res,
        "isolated": isolated,
    }


def from_batch(batch: Path) -> dict[str, Any]:
    runs = [json.loads(x) for x in (batch / "runs.jsonl").read_text().splitlines()]
    scored = [r for r in runs if r["status"] == "SCORED"]
    out: dict[str, Any] = {}
    for key, sid in (("PERF-005", "LEG-PY-FIX"), ("PERF-006", "LEG-C-MAKE")):
        out[key] = {"scenario": sid}
        for arm in ARMS:
            rs = [r for r in scored if r["scenario_id"] == sid and r["arm"] == arm]
            out[key][arm] = {
                "end_to_end_ms": summary([r["wall_ms"] for r in rs]),
                "worker_ms_total": summary([r["worker_ms_total"] for r in rs]),
                "peak_memory_bytes_median": statistics.median([r["peak_memory_bytes"] for r in rs])
                if rs
                else None,
            }
    first = batch / "runs"
    dur = None
    if scored:
        dur = sum(r["wall_ms"] for r in scored) / 1000
    out["PERF-009"] = {
        "what": "repeated tasks over the whole batch",
        "runs": len(runs),
        "scored": len(scored),
        "sum_run_seconds": round(dur or 0, 1),
        "runs_per_minute": round(len(scored) / (dur / 60), 2) if dur else None,
        "leaked_after_batch": dc.leaked_resources(),
        "run_dirs": len(list(first.iterdir())) if first.exists() else 0,
    }
    return out


def write_md(batch: Path, p: dict[str, Any]) -> None:
    L = [
        "# Performance (PERF-001 … PERF-010)",
        "",
        f"Measured on the batch host; raw values in `perf.json`. n = {p['n']}.",
        "",
        "| ID | Measurement | Result |",
        "|---|---|---|",
        f"| PERF-001 | Hardened container start (ms) | median {p['PERF-001']['median']}, p95 {p['PERF-001']['p95']} |",
    ]
    for prof, b in p["PERF-002/003"].items():
        if prof == "what":
            continue
        L.append(
            f"| PERF-002 | Landlock install, {prof} (µs) | median {b['landlock_install']['median_us']:.1f}, "
            f"p95 {b['landlock_install']['p95_us']:.1f} |"
        )
        L.append(
            f"| PERF-003 | seccomp install, {prof} (µs) | median {b['seccomp_install']['median_us']:.1f}, "
            f"p95 {b['seccomp_install']['p95_us']:.1f}; plan (compile) {b['plan_us']:.0f} µs |"
        )
    for arm in ARMS:
        v = p["PERF-004"][arm]
        L.append(
            f"| PERF-004 | No-op command, {arm} | in-worker median {v['in_worker_ms']['median']} ms; "
            f"per-action container median {v['per_action_container_ms']['median']} ms |"
        )
    for key in ("PERF-005", "PERF-006"):
        for arm in ARMS:
            v = p[key][arm]
            L.append(
                f"| {key} | {p[key]['scenario']} end-to-end, {arm} | median "
                f"{v['end_to_end_ms']['median']} ms, p95 {v['end_to_end_ms']['p95']} ms; "
                f"peak RSS {v['peak_memory_bytes_median']} B |"
            )
    for arm in ARMS:
        v = p["PERF-007"][arm]
        L.append(
            f"| PERF-007 | 11-process task, {arm} | {v['status']}, {v['in_worker_ms']} ms, "
            f"cgroup pids.peak {v['peak_process_count_cgroup']} (limit {v['pid_limit']}) |"
        )
    v8 = p["PERF-008"]
    L.append(
        f"| PERF-008 | Listing 3,030 entries (P1) | {v8['entries_returned']} returned, truncated="
        f"{v8['truncated']}, {v8['result_bytes']} B result, {v8['in_worker_ms']} ms |"
    )
    v9 = p["PERF-009"]
    L.append(
        f"| PERF-009 | Repeated tasks | {v9['scored']}/{v9['runs']} runs, {v9['runs_per_minute']} runs/min, "
        f"leaked after batch: {v9['leaked_after_batch']} |"
    )
    v10 = p["PERF-010"]
    L.append(
        f"| PERF-010 | 4 concurrent P1 tasks | total {v10['total_ms']} ms, isolated={v10['isolated']} |"
    )
    (batch / "perf.md").write_text("\n".join(L) + "\n")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--batch", type=Path, required=True)
    ap.add_argument("--n", type=int, default=30)
    a = ap.parse_args()
    image = dc.WorkerImage.from_lock()
    image.verify_present()
    tmp = a.batch / "perf-work"
    tmp.mkdir(exist_ok=True)
    daemons = start_daemons(tmp)
    try:
        with dc.TaskSandbox(image, "perf") as sb:
            p: dict[str, Any] = {"n": a.n, "image_id": image.image_id}
            p["PERF-001"] = perf_001_container_start(image, sb, a.n)
            p["PERF-002/003"] = perf_002_003_confinement_setup(image, sb, 50)
            p["PERF-004"] = perf_004_noop(daemons, sb, a.n)
            p["PERF-007"] = perf_007_multiprocess(daemons, sb)
        p["PERF-008"] = perf_008_large_listing(daemons, image, tmp)
        p["PERF-010"] = perf_010_concurrent(daemons, image)
        p.update(from_batch(a.batch))
    finally:
        for d in daemons.values():
            d.proc.kill()
            d.proc.wait()
        subprocess.run(["rm", "-rf", str(tmp)], check=False)  # noqa: S607
    (a.batch / "perf.json").write_text(json.dumps(p, indent=2))
    write_md(a.batch, p)
    print((a.batch / "perf.md").read_text())


if __name__ == "__main__":
    main()
