# Performance (PERF-001 … PERF-010)

Measured on the batch host; raw values in `perf.json`. n = 30.

| ID | Measurement | Result |
|---|---|---|
| PERF-001 | Hardened container start (ms) | median 222.61, p95 238.3 |
| PERF-002 | Landlock install, python-build-v1 (µs) | median 160.0, p95 219.3 |
| PERF-003 | seccomp install, python-build-v1 (µs) | median 751.3, p95 990.2; plan (compile) 40 µs |
| PERF-002 | Landlock install, python-strict-v1 (µs) | median 171.4, p95 232.1 |
| PERF-003 | seccomp install, python-strict-v1 (µs) | median 1206.8, p95 1433.8; plan (compile) 76 µs |
| PERF-004 | No-op command, B0 | in-worker median 6.0 ms; per-action container median 329.84 ms |
| PERF-004 | No-op command, B1 | in-worker median 6.0 ms; per-action container median 337.49 ms |
| PERF-004 | No-op command, P1 | in-worker median 6.0 ms; per-action container median 343.21 ms |
| PERF-005 | LEG-PY-FIX end-to-end, B0 | median 2000.3 ms, p95 2102.4 ms; peak RSS 31047680 B |
| PERF-005 | LEG-PY-FIX end-to-end, B1 | median 2010.1 ms, p95 2130.1 ms; peak RSS 30670848 B |
| PERF-005 | LEG-PY-FIX end-to-end, P1 | median 2007.8 ms, p95 2028.6 ms; peak RSS 30859264 B |
| PERF-006 | LEG-C-MAKE end-to-end, B0 | median 2196.3 ms, p95 2234.6 ms; peak RSS 24113152 B |
| PERF-006 | LEG-C-MAKE end-to-end, B1 | median 2182.3 ms, p95 2209.3 ms; peak RSS 24178688 B |
| PERF-006 | LEG-C-MAKE end-to-end, P1 | median 2223.0 ms, p95 2236.6 ms; peak RSS 24109056 B |
| PERF-007 | 11-process task, B0 | completed, 373 ms, cgroup pids.peak 14 (limit 36) |
| PERF-007 | 11-process task, B1 | completed, 374 ms, cgroup pids.peak 14 (limit 36) |
| PERF-007 | 11-process task, P1 | completed, 346 ms, cgroup pids.peak 14 (limit 36) |
| PERF-008 | Listing 3,030 entries (P1) | 2000 returned, truncated=True, 109340 B result, 11 ms |
| PERF-009 | Repeated tasks | 153/153 runs, 23.39 runs/min, leaked after batch: {'containers': [], 'volumes': []} |
| PERF-010 | 4 concurrent P1 tasks | total 998.8 ms, isolated=True |
