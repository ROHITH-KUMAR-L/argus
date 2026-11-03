# Ratcheted, Subprocess-Aware Privilege Confinement for Code-Executing Agents

This repository (**Argus**) contains the build specification and the implementation for the RVCE 2026-27 project. The specification in `docs/` is the source of truth for both the implementation team and any AI coding agent working on the repository. Build status is tracked in **[progress.md](progress.md)**.

> **Safety:** adversarial fixtures run only inside disposable, hardened Docker workers. Never run them on a developer host.

## Quick start (development)

```bash
cp .env.example .env          # controller-only settings; PLANNER=mock by default
uv sync                       # Python 3.12 controller + evaluation deps
uv run pytest                 # Python unit tests
cargo test                    # Rust policy/ratchet/confinement crates
```

Supporting documents: [protocol.md](docs/protocol.md) is the controller ↔ `ratchetd` wire contract, and [threat_model.md](docs/threat_model.md) is the threat model.

## Documents and recommended reading order

Read **[STACK_DECISION.md](docs/STACK_DECISION.md)** first for the chosen language/framework split. **[STACK_MIGRATION_PROMPT.md](docs/STACK_MIGRATION_PROMPT.md)** is the reusable instruction for applying the same decision to another working copy or asking a coding agent to re-check stack consistency.

1. **[architecture.md](docs/architecture.md)** - System components, trust boundaries, task policy, ratchet invariant, kernel enforcement and experimental architecture.
2. **[workflow.md](docs/workflow.md)** - End-to-end task lifecycle, process/subprocess handling, approval flow and B0/B1/P1 experiment workflows.
3. **[implementation_plan.md](docs/implementation_plan.md)** - Phased, step-wise build plan with deliverables and exit criteria.
4. **[success_criteria.md](docs/success_criteria.md)** - Measurable functional, security, utility, performance and reproducibility targets.
5. **[test_criteria.md](docs/test_criteria.md)** - Comprehensive test catalogue with test IDs, procedures and expected results.
6. **[code_execution_agent.md](docs/code_execution_agent.md)** - Detailed build contract for the code-execution agent and its Docker worker, including Dockerfile/Compose templates and launcher requirements.

## Instructions for the AI coding agent

Before changing code, read all six documents. Treat `architecture.md` as the system design source of truth, `workflow.md` as the runtime behavior contract, `implementation_plan.md` as the required build order, `success_criteria.md` as the release gate, `test_criteria.md` as the test catalogue, and `code_execution_agent.md` as the worker implementation contract.

Implement the system phase by phase. Do not skip exit criteria. Do not replace kernel enforcement with prompt instructions. Do not silently fall back to host execution. Do not run adversarial fixtures on a developer host. Do not mount the Docker socket, host root, host home or credentials into the task worker.

## Adopted technology stack

- **Python 3.12+ + LangChain:** AI model adapters, structured planning, narrow tool definitions and controller integration.
- **LangGraph:** explicit stateful task graph, deterministic gates, human approval interrupts and optional redacted checkpointing.
- **Rust:** authoritative policy validator, monotonic privilege ratchet, Landlock/seccomp launcher and process supervisor.
- **Python:** evaluation harness and reporting; Python may also be an untrusted code runtime inside disposable workers.
- **Docker:** disposable execution boundary. No Docker socket or LLM credentials inside workers.

LangSmith tracing is disabled by default pending privacy review. The LLM never receives direct privileged execution tools; every action must pass through the Rust policy/ratchet boundary.

## Experimental arms

- **B0 - Isolated unconstrained baseline:** no project task-policy/ratchet/project-specific Landlock/seccomp controls, while retaining an outer disposable Docker test boundary and ordinary container protections.
- **B1 - Sandbox-only baseline:** static Docker, Landlock and seccomp controls, without the monotonic ratchet.
- **P1 - Proposed system:** task policy, monotonic ratchet, Landlock, seccomp, Docker and subprocess-aware monitoring.

The B0 baseline is never unrestricted execution on the developer host.

## Important scope note

The documents are a build specification, not a claim that the application or native launcher has already been implemented. `code_execution_agent.md` contains Docker build templates and implementation contracts that the coding agent must complete, compile, run and test. Final experimental claims must be based on measured results and the exact host/kernel/image configuration.

## Source basis

The project objectives and proposed methodology are based on the supplied *Ratcheted, Subprocess-Aware Privilege Confinement for Code-Executing Agents* RVCE Experiential Learning Synopsis 2026-27. Current Linux and Docker implementation references are linked in the relevant documents.
