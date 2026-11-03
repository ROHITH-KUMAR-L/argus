# Progress

Tracks which phase of `docs/implementation_plan.md` the build is in, what is done, and what is still pending. Updated and committed at the end of every phase.

**Current phase:** Phase 1 — Policy DSL and Rust validator (in progress)

## Environment of record

| Item | Value |
|---|---|
| Host kernel | 7.2.9-2-cachyos, x86_64 |
| LSMs | capability, landlock, lockdown, yama, bpf |
| Landlock ABI (inside Docker, default seccomp) | 10 |
| Docker | 29.9.2, rootful, cgroup v2 (systemd driver) |
| Rust | rustc / cargo 1.99.1 (Arch package, no rustup) |
| Python | 3.12 via uv 0.13.6 (host has 3.14; not used) |

## Phase status

| Phase | Title | Milestone | Status |
|---|---|---|---|
| 0 | Repository, threat model, toolchains, protocol contract | M1 | **done** |
| 1 | Policy DSL and Rust validator | M1 | in progress |
| 2 | Permission model and monotonic ratchet (`ratchetd`) | M1 | pending |
| 3 | Structured audit and task state | M2 | pending |
| 4 | Execution supervisor and process lifecycle | M2 | pending |
| 5 | Docker worker image and outer sandbox | M3 | pending |
| 6 | Landlock integration | M4 | pending |
| 7 | seccomp-BPF integration | M4 | pending |
| 8 | Subprocess-aware enforcement and narrowing | M5 | pending |
| 9 | LangGraph agent loop (mock planner, then OpenAI-compatible LLM) | M6 | pending |
| 10 | Evaluation harness (B0 / B1 / P1) | M7 | pending |
| 11 | Performance, hardening, final report | M7 | pending |

## Completed work

### Phase 0: Repository, threat model, toolchains, protocol contract (2026-11-03)
- Repository layout: `crates/` (8 crates), `controller/`, `evaluation/`, `tests/`, `.github/workflows/ci.yml`
- `pyproject.toml` + `uv.lock` (Python 3.12 pinned; LangChain, LangGraph, langchain-openai, Pydantic, docker SDK); `Cargo.toml` workspace + `Cargo.lock`
- `.env.example` (OpenAI-compatible `LLM_BASE_URL` / `LLM_API_KEY` / `LLM_MODEL`, `PLANNER=mock`); `.env` git-ignored
- `controller/config.py`: settings loader; LangSmith tracing forced off unless explicitly opted in after privacy review; API key excluded from repr and redacted views
- `crates/protocol`: v1 envelope, error codes, 1 MiB length-prefixed framing, request-id rules
- Docs: `docs/protocol.md`, `docs/threat_model.md`, decisions D1–D9 in `docs/STACK_DECISION.md`; spec fixes (README links, Dockerfile template, Rust-only worker layout, `workflow.md` typo, layout root)
- Verified on host: Landlock ABI 10 is reachable inside Docker under the default seccomp profile; named-volume staging via `docker cp` preserves UID 10001

**Tests / evidence:** clean copy (git-tracked files only, no `.env`, Docker unreachable): `uv sync --locked`, `uv run pytest` 5 passed, `ruff check` clean, `mypy --strict` clean, `cargo fmt --check` clean, `cargo clippy -D warnings` clean, `cargo test --locked` 5 passed. Covers STK-013 (tracing default-off).

## Pending work (current phase)

- [ ] `schemas/policy.schema.json` (strict) and Rust `policy-model` types
- [ ] Canonical serialization + SHA-256 policy hash
- [ ] Path normalization, traversal / prefix-confusion / symlink / overlap / deny-shadowing checks
- [ ] Executable, tool and syscall-profile catalogs; network and limit validation against deployment maxima
- [ ] Policy templates (python-task, c-build, test-only)
- [ ] `argus-policy validate` CLI
- [ ] Tests POL-001 … POL-020, STK-002

## Known limitations / open items

- The `rust:1.99-slim` image pull failed with a network reset on 2026-11-03; retry in Phase 5.
- Docker is rootful on the development host. Controller access to the Docker daemon is root-equivalent; see `docs/threat_model.md`.
