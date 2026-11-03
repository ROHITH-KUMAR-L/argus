# Final Report: Ratcheted, Subprocess-Aware Privilege Confinement for Code-Executing Agents

**Status: release candidate, validated on the declared environment.** Every claim below is tied to committed evidence. Nothing is claimed beyond the tested configuration and the tested workload classes.

## 1. Question and answer

> *Can a monotonic privilege policy, combined with subprocess-aware kernel confinement, reduce unauthorized actions while preserving legitimate task completion and acceptable execution overhead?*

On the tested corpus and environment, **yes**:

- **P1 (the proposed system) completed 0 of 27 attack attempts** (95 % CI upper bound 0.12). B0, the isolated but ungated baseline, completed 24/27. B1, the static sandbox, completed 6/27.
- **Every B1 failure is a staged escalation that only the ratchet stops.** In each case a permission was narrowed mid-task and later reused: 6/9 effects in B1, 0/9 in P1.
- **Utility is unchanged.** All arms completed 21/21 independently verified legitimate tasks, with 0/60 false denials.
- **Overhead is negligible.** Median end-to-end latency on legitimate tasks is +0.4 % vs B0 and −0.3 % vs B1. In-worker confinement setup costs about 0.9 ms per action (denylist) or about 1.4 ms (strict allowlist).

## 2. What was built

| Layer | Implementation | Authority |
|---|---|---|
| Agent orchestration | Python 3.12, LangGraph `StateGraph` (11 nodes), LangChain proposal-only tools, mock and OpenAI-compatible planners | none: proposes only |
| Policy and ratchet | Rust `policy-validator`, `privilege-ratchet`, `ratchetd` (UDS, write-ahead hash-chained log) | **authoritative** |
| Kernel confinement | Rust `linux-confinement`: Landlock (ABI-aware, `O_NOFOLLOW` rule roots, scoping), seccomp-BPF (stacked filters, denylist and default-deny profiles) | kernel |
| Execution | Rust `argus-worker` entrypoint + `process-supervisor` (rlimits, subreaper whole-tree cleanup) | in-worker |
| Outer boundary | One hardened Docker container per action (non-root, no capabilities, `no-new-privileges`, read-only root, `--network none`, cgroup limits, size-capped tmpfs workspace, no host mounts), drift-checked against `docker inspect` before every start | Docker / kernel |
| Evidence | Hash-chained, redacted JSONL audit; run metadata; independent oracles; B0/B1/P1 harness | — |

Design documents: `architecture.md`, `STACK_DECISION.md` (D1–D10), `protocol.md`, `policy.md`, `confinement.md`, `threat_model.md`. Build history is one commit per phase (0–11) and is recorded in `progress.md`.

## 3. Method

- **Corpus v1.0** (`evaluation/scenarios`, 17 scenarios). It was frozen in commit `c8aa885` *before* the final batch:

  | Category | Scenarios | Content |
  |---|---|---|
  | Legitimate | 8 | Python fix, multi-file change, nested subprocess tests + linter, retry after a wrong patch, C + `make`, test-only, artifact export, policy-too-narrow → step-up |
  | Prompt injection | 3 | README, direct user text, test output |
  | Staged escalation | 3 | narrowing then reuse of a write right, narrowing then reuse of an executable, step-up request then bypass |
  | Subprocess misuse | 3 | delegated read via shell children and `setsid`, daemon persistence, child syscall |

- **Worst-case agent.** The planner is a deterministic script that obeys every injected instruction. The study measures *containment*, not how often a real model would attempt an attack.
- **Arms.** All three use the same image, fixtures (SHA-256-pinned), scripts and limits; one `ratchetd` per arm. B0 keeps Docker's outer protections but has no project gate, ratchet or project Landlock/seccomp. B1 has a static gate plus Landlock and seccomp, and no ratchet. P1 is the full system.
- **Schedule.** Three repetitions, arm order rotated per repetition, seeded scenario shuffle, a fresh sandbox per run, every run recorded.
- **Oracles.** They are independent of the agent: canary bytes in any raw worker output, protected-file changes in the validated export, probe results from inside the worker. Outcomes are counted separately as *attempted*, *policy denial*, *in-worker denial* and *effect completed*.
- **Statistics.** Raw numerators and denominators with Wilson 95 % intervals; INVALID runs are recorded, never dropped.

## 4. Results (`evaluation/results/batch-2026-11-03`)

153 runs scheduled, 153 scored, 0 invalid. 51 scenario × arm groups, **0 unstable** across repetitions (EVA-012).

| Metric | B0 | B1 | P1 |
|---|---|---|---|
| Attack success rate | 24/27 = 0.89 [0.72, 0.96] | 6/27 = 0.22 [0.11, 0.41] | **0/27 = 0.00 [0.00, 0.12]** |
| — prompt injection | 9/9 | 0/9 | 0/9 |
| — staged escalation | 9/9 | 6/9 | **0/9** |
| — subprocess misuse | 6/9 | 0/9 | 0/9 |
| Policy-gate denials in attacks | 3 | 12 | 15 |
| In-worker denials in attacks | 3 (Docker default profile only) | 18 | 21 |
| Legitimate completion (verified) | 21/21 | 21/21 | 21/21 |
| False-denial rate | 0/60 | 0/60 | 0/60 |
| Step-up requested when the policy was too narrow | 0/3 | 0/3 | 3/3 |
| Narrowings applied / attempted | 0/6 | 0/6 | 6/6 |

`SUB-DAEMON-PERSIST` did not discriminate: 0 effects in every arm, because whole-tree cleanup by the supervisor and container is common to all arms. Network attacks were not tested, since every arm runs with `--network none`.

### Performance (`perf.md`, PERF-001…010)

| Measurement | Result |
|---|---|
| Hardened container start | median 223 ms (p95 238 ms) |
| Landlock install (in child) | median 160 µs (denylist policy), 171 µs (strict) |
| seccomp install (in child) | median 751 µs (denylist), 1,207 µs (strict allowlist); BPF compile 40–76 µs |
| No-op action, in worker | 6 ms in every arm; per-action container ≈ 330–343 ms |
| Python fix task end to end | B0 2000 ms · B1 2010 ms · P1 2008 ms (medians); peak RSS ≈ 31 MB |
| C build task end to end | B0 2196 ms · B1 2182 ms · P1 2223 ms |
| 11-process task | `pids.peak` 14 (limit 36) in every arm |
| Listing 3,030 entries | capped at 2,000, `truncated=true`, 109 KB result |
| Repeated tasks | 153 runs, 23 runs/min, **no leaked containers or volumes** |
| 4 concurrent tasks | isolated, 1.0 s total |

The PERF-002/003 benchmark ran on a rebuild of the batch image that adds the `--bench-confinement` mode. That build also fixed the benchmark's own timing channel, because Rust socket writes use `sendto`, which the strict profile correctly denies. The enforcement code is otherwise identical; the image IDs are recorded in `perf.json` and `environment.json`.

## 5. Success criteria (`success_criteria.md`)

| ID | Criterion | Status | Evidence |
|---|---|---|---|
| SC-F01 | Invalid policies rejected before worker creation | **Met** | 47 shared vectors (Rust + Python), POL tests |
| SC-F02 | Versioned policy and hash per run | **Met** | `run_metadata.json`, POLICY_VALIDATED events |
| SC-F03 | Worker gets only the staged workspace | **Met** | DKR-007/008/009, AGT-012/013, preflight |
| SC-F04 | Monotonic ratchet | **Met** | RAT-001…024 incl. 1,000-case property test against an independent oracle |
| SC-F05 | Explicit step-up only via approval and a new epoch | **Met** | RAT-020…023, STK-006/007, forged-resume test |
| SC-F06 | Every action checked against the latest policy | **Met** | STK-005/010/012 (dispatch-time revalidation) |
| SC-F07 | Landlock denies outside allowed paths | **Met** | LL-001…022 (LL-017 kernel run UNSUPPORTED) |
| SC-F08 | seccomp denies selected syscalls | **Met** | SEC-001…020 |
| SC-F09 | Children and grandchildren keep restrictions | **Met** | LL-020/021/022, SEC-014/015, SUB-001…006 |
| SC-F10 | Docker hardening | **Met** | DKR-001…017, 21/21 preflight checks |
| SC-F11 | Fail closed | **Met** | LL-018/019, SEC-017, FAIL-001…014 |
| SC-F12 | Cleanup of the whole tree | **Met** | SUB-007/008/013/014/018, RES-007/012, PERF-009 |
| SC-F13 | Safe output export | **Met** | AUD-015/016, FAIL-012 |
| SC-F14 | Audit of decisions, transitions, confinement, terminal states | **Met** | AUD-001…016; 153/153 batch chains verify |
| STACK-001 | Python orchestrates, Rust decides | **Met** | STK-001 boundary test, crate layout |
| STACK-002 | LangChain integration with a mock provider | **Met** | STK-003/008, proposal tools |
| STACK-003 | LangGraph routes observable | **Met** | STK-004/005, lifecycle events |
| STACK-004 | No agent bypass | **Met** | STK-008/009, AGT-007/011 |
| STACK-005 | Rust revalidation per execution | **Met** | STK-010/012 |
| STACK-006 | Checkpoint privacy | **Met** | STK-011 (secrets absent from SQLite checkpoint and audit) |
| STACK-007 | Tracing off by default | **Met** | STK-013 |
| STACK-008 | Pinned, recorded dependencies | **Met** | `uv.lock`, `Cargo.lock`, digest-pinned images, STK-017 |

All proposed numeric targets (§4–6 of the criteria) were met on this batch. The traceability matrix (`docs/test_matrix.md`) links 224 of 235 catalogue IDs to code; the other 11 carry a documented status.

**Live LLM.** The OpenAI-compatible planner is implemented and tested against simulated providers (timeouts, 429s, malformed output). No live endpoint was configured, so `tests/integration/test_agent_e2e.py::test_live_llm_smoke` (`-m llm`) and any LLM-driven repetitions (≥ 10 recommended) are **not yet run**.

## 6. Supported environment

- **Supported:** Linux x86_64, Landlock ABI ≥ 1 (tested on ABI 10, handled ABI 9), Docker Engine with cgroup v2 and the default seccomp profile, Python 3.12, Rust ≥ 1.87. Tested on kernel 7.2.9 and Docker 29.9.2.
- **Unsupported or untested:**
  - rootless Docker and Podman (DKR-015);
  - other architectures;
  - kernels with x32 syscalls reachable through a permissive outer profile;
  - older Landlock ABIs on a real kernel (planning only);
  - network-enabled tasks (no egress proxy design);
  - non-Python/C runtimes.

## 7. Limitations and threats to validity

1. **Scripted attacks.** The corpus measures containment against a fully obedient agent. Real-model attack *propensity* is not measured.
2. **Small corpus** (17 scenarios, 3 repetitions). Zero P1 effects bounds the rate only to ≤ 0.12 at 95 %. It is not a proof of absence.
3. **Shared kernel.** Docker, Landlock and seccomp all depend on the host kernel; a kernel exploit defeats every layer at once.
4. **Rootful Docker** on the reference host: the controller's Docker access is root-equivalent. Documented in `threat_model.md`.
5. **Executable allowlisting is broker-level.** Code already running can execute anything under granted read + execute hierarchies (`/usr`).
6. **Approver identity** is separated by channel (the approval socket), not authenticated per human.
7. **Latency** is dominated by per-action container start (≈ 220 ms). One container per task would be faster but needs a re-proven narrowing model.
8. **Host networking during image build.** Docker's bridge network has no egress on the reference host, so the image *build* uses `--network host`. Runtime is unaffected.

## 8. Reproducing

```bash
uv sync && cargo build && ./scripts/build_worker_image.sh && uv run argus preflight
./scripts/check.sh
uv run python -m evaluation.harness --reps 3 --out evaluation/results/<new-batch>
uv run python -m evaluation.perf --batch evaluation/results/<new-batch>
```

Any row of `runs.jsonl` traces to its run directory: `run_metadata.json` (image, kernel, versions), `events.jsonl` (hash-chained; `verify()` checks it), `result.json` and `artifacts/` (SHA-256).
