# Stack Migration Prompt — Python + LangChain/LangGraph + Rust

You are modifying the existing project **Ratcheted, Subprocess-Aware Privilege Confinement for Code-Executing Agents**. The repository already contains `architecture.md`, `workflow.md`, `implementation_plan.md`, `success_criteria.md`, `test_criteria.md`, `code_execution_agent.md`, and `README.md`.

## Objective

Adopt this mandatory hybrid stack throughout the project. Do not interpret this as replacing Python everywhere:

- **Python 3.12+ + LangChain:** AI model integration, prompts, structured planner outputs, narrow tool schemas, controller/API/CLI adapters and experiment orchestration.
- **LangGraph:** explicit stateful agent workflow with deterministic gates, conditional routing, human approval interrupts and optional privacy-safe checkpointing.
- **Rust:** authoritative JSON policy validation, canonicalization, monotonic privilege ratchet, authorization decisions, Landlock/seccomp-BPF installation, native execution launcher and process supervision.
- **Python evaluation harness:** baseline execution, scenario orchestration, metrics, analysis and reporting.
- **Docker:** disposable worker boundary. The worker receives no LLM credentials, Docker socket, host home, SSH agent or controller secrets. Python may remain one of the untrusted workload runtimes inside the worker image.

## Non-negotiable security architecture

1. The LLM only proposes plans/actions. It never grants permissions.
2. LangChain tools exposed to the model must be narrow proposal tools. Do not expose generic host shell, arbitrary Docker, policy mutation, unrestricted host filesystem or unrestricted network tools.
3. Every action must pass through deterministic validation and the Rust policy/ratchet authority immediately before execution.
4. Python may perform defensive input validation, but it must not independently override or reimplement the authoritative Rust ratchet decision.
5. A policy expansion is never allowed within an execution epoch. It requires trusted human approval, termination of the old epoch and a new policy snapshot/worker.
6. Rust must install and verify Landlock and seccomp before untrusted code starts. Failure to install required controls means fail closed.
7. Child and grandchild processes must remain under kernel restrictions and Docker/cgroup lifecycle controls. Verify this experimentally; do not infer it from parent PID monitoring.
8. Do not silently fall back to host execution or weaken Docker/kernel controls to make a test pass.

## Required LangGraph workflow

Implement explicit nodes at minimum:

`intake -> context_loader -> planner -> plan_validator -> action_normalizer -> policy_decision -> worker_dispatch -> result_collector -> completion_check -> finalize`

Add an `approval_interrupt` route for privilege expansion. Denials route back to a bounded replan path or terminate. The `policy_decision` node calls Rust. Only a Rust `ALLOW` result can reach `worker_dispatch`.

Use LangChain for model-provider adapters, prompt templates, structured output/Pydantic schemas and tool definitions. Begin with a deterministic mock planner so all security tests run without API keys and model variability. Add a real provider only after deterministic enforcement tests pass.

For the first implementation, prefer a custom LangGraph `StateGraph` with explicit deterministic security nodes over a generic autonomous shell-agent loop. LangChain may provide the planner's chat model and structured-output interface; all tool calls remain proposals and must pass through the Rust authority. A LangChain `create_agent` subgraph is optional future work, not a reason to weaken or bypass the explicit policy gate.

## Rust workspace

Create separate crates (or clearly separated modules) for:

- `policy-model`
- `policy-validator`
- `privilege-ratchet`
- `linux-confinement`
- `execution-launcher`
- `process-supervisor`
- `protocol`

Prefer safe maintained Rust abstractions for Landlock. Isolate raw syscalls/FFI and `unsafe` blocks. Select a maintained seccomp/libseccomp binding only after checking API support, kernel compatibility, maintenance and testability. Record the exact crate versions and kernel ABI assumptions. Do not claim security merely because a crate compiles.

Use a versioned, typed JSON protocol over a local Unix-domain socket or bounded stdin/stdout interface between Python and Rust. Authenticate the local endpoint through filesystem permissions; validate request IDs, protocol version, policy hash and epoch ID. Rust is authoritative.

## Privacy and token/context discipline

- Keep `CLAUDE.md` concise and point to the relevant specification instead of copying all documents into it.
- Load only task-relevant files and bounded code excerpts.
- Keep graph state minimal. Never checkpoint credentials, API keys, raw secrets or unnecessary full file contents.
- LangSmith tracing is disabled by default. Do not enable hosted tracing until a privacy review and redaction configuration are complete.
- Never send private repository contents, secrets or worker output containing sensitive data to third-party tracing/documentation services.
- Pin Python dependencies with a lockfile and Rust dependencies with `Cargo.lock`; record versions in experiment metadata.

## Required document updates

Update all existing project documents consistently:

1. `architecture.md`: hybrid stack, trust boundaries, LangGraph graph, Rust authority, IPC protocol and privacy controls.
2. `workflow.md`: map each agent lifecycle step to the LangGraph nodes and Rust policy decision.
3. `implementation_plan.md`: step-by-step Python/LangChain/LangGraph and Rust phases; deterministic mock planner first; no live LLM before enforcement tests.
4. `success_criteria.md`: measurable acceptance criteria for graph routes, no-bypass behavior, Rust authority, checkpoint privacy and dependency reproducibility.
5. `test_criteria.md`: tests for malformed structured output, graph allow/deny/approval paths, tool bypass attempts, stale checkpoint replay, Rust revalidation and tracing default-off.
6. `code_execution_agent.md`: Python controller modules, Rust crates, Docker multi-stage build for Rust launcher, worker/controller separation and protocol contracts.
7. `README.md`: new stack summary and reading order.

Remove contradictory instructions that say the authoritative ratchet or native launcher is Python/C. Do not remove Python workload test cases: Python is still a valid untrusted language executed inside the sandbox. Do not remove C compilation workloads if they remain part of the supported benchmark matrix.

## Deliverables and validation

- Update all seven Markdown files; keep terminology, component names, paths and responsibilities consistent.
- Add `Cargo.toml`, `Cargo.lock`, `pyproject.toml`, Python lockfile and a documented controller/Rust protocol to the implementation plan (do not fabricate successful build outputs).
- Add a short `STACK_DECISION.md` explaining why responsibilities are split.
- Run a consistency scan for contradictory stack references, stale file paths and incorrect Docker build instructions.
- Do not claim the application is implemented. These are specifications until code is built and tests pass.
- Return a summary of changed files, unresolved design decisions and the exact tests that remain to be implemented.
