# Step-by-Step Implementation Plan

## 1. Mission

Build a Linux-based code-executing agent framework that can run legitimate coding tasks while enforcing a task-specific privilege boundary across the full process tree. The project must be evaluated experimentally against an isolated unconstrained baseline and a conventional sandbox-only baseline.

The implementation should follow this order: establish a safe reproducible test environment, implement policy and ratchet logic, build and verify the execution boundary, add the agent loop, then run the comparative evaluation. Do not integrate a live language model before the Rust policy/ratchet and executor can be tested deterministically. Build the LangGraph flow initially with a deterministic mock planner.

## 2. Recommended initial technology choices

| Area | Initial choice | Reason / constraint |
|---|---|---|
| AI controller and evaluation harness | Python 3.12+ | Strong AI ecosystem; keeps model integration and experiment analysis productive |
| Agent framework | LangChain + LangGraph | LangChain for model/structured-output/tool abstractions; LangGraph for explicit stateful, interruptible, auditable orchestration |
| Policy format | JSON + JSON Schema | Versioned, machine-validated policy DSL |
| API | FastAPI (optional for first milestone); CLI first | A CLI makes deterministic local testing easier before introducing an API |
| Trusted enforcement core and launcher | Rust (Cargo workspace) | Memory-safe systems implementation for policy/ratchet, Linux confinement, launcher and process supervision; isolate and review any unsafe syscall bindings |
| Filesystem confinement | Landlock | Kernel-enforced filesystem restrictions with descendant inheritance |
| Syscall confinement | seccomp-BPF / libseccomp | Reduces the syscall surface and is inherited by descendants when configured correctly |
| Outer isolation | Docker Engine | Repeatable worker image, namespaces, cgroups, resource caps and no-network execution |
| Agent adapter | LangChain chat-model interface behind LangGraph; deterministic mock planner first | Keeps security tests independent of API credentials and model variability |
| Logs | JSONL events + JSON run metadata | Simple reproducibility and offline analysis |
| Tests | pytest + scenario fixtures + shell/C integration probes | Unit, integration, adversarial and benchmark coverage |

Pin the base image by digest in reproducible experiments. Do not assume the host's latest Python or kernel automatically matches the container/runtime requirements.

## 2A. Mandatory agent-framework design

- Use **LangChain** for model-provider adapters, prompt templates, structured outputs and narrowly scoped tool definitions.
- Use **LangGraph** as the control-flow runtime. Implement an explicit graph with nodes for intake, context loading, planning, schema validation, deterministic action normalization, Rust policy decision, human approval interrupt, worker dispatch, result collection and completion.
- The graph must not contain a direct host-shell tool, direct Docker client tool, policy-file write tool, unrestricted filesystem tool or unrestricted network tool.
- All tool calls must be proposals routed to the trusted Python controller and then to the Rust policy/ratchet service. The Rust service is authoritative and revalidates the current policy at dispatch time.
- Use Pydantic/JSON schemas for planner outputs. Treat model output, repository files and tool output as untrusted.
- Use a deterministic mock planner until policy, ratchet and confinement tests pass. Then add the chosen LLM provider through LangChain without changing the enforcement boundary.
- LangGraph checkpointing is optional for the first local prototype. If enabled, use a local development checkpointer and persist only redacted, minimal state. Hosted LangSmith tracing is disabled by default pending a privacy review.

## 3. Repository layout target

```text
argus/                             # repository root
├── README.md
├── pyproject.toml                 # Python controller/evaluation dependencies
├── uv.lock
├── Cargo.toml                     # Rust workspace
├── Cargo.lock
├── controller/                    # Python + LangChain + LangGraph
│   ├── graph/                     # state, nodes, routes, graph builder
│   ├── llm/                       # LangChain model adapters and prompts
│   ├── tools/                     # narrow proposal tools only
│   ├── api/
│   ├── worker_client/
│   └── audit/
├── crates/                        # Rust trusted enforcement workspace
│   ├── policy-model/
│   ├── policy-validator/
│   ├── privilege-ratchet/
│   ├── linux-confinement/
│   ├── execution-launcher/
│   ├── process-supervisor/
│   └── protocol/
├── worker/                        # worker request adapter; untrusted runtime remains isolated
├── evaluation/                    # Python scenarios, baselines, metrics and reports
├── schemas/
├── config/
├── docker/
│   ├── Dockerfile.controller
│   ├── Dockerfile.executor
│   ├── compose.yaml
│   └── seccomp/
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── confinement/
│   ├── adversarial/
│   ├── workloads/
│   └── performance/
└── docs/
    ├── architecture.md
    ├── workflow.md
    ├── implementation_plan.md
    ├── success_criteria.md
    ├── test_criteria.md
    └── code_execution_agent.md
```

## 4. Global engineering rules for the AI implementation agent

The AI agent that builds this repository must follow these rules throughout development:

1. Read `architecture.md`, `workflow.md`, `success_criteria.md`, `test_criteria.md` and `code_execution_agent.md` before coding.
2. Work phase by phase. Do not skip a phase or mark an item complete without tests and evidence.
3. Never run hostile test payloads directly on the developer host. Run them only in disposable test containers/VMs.
4. Never add `--privileged`, host PID/network/IPC, broad host mounts, Docker socket mounts, or extra capabilities to “fix” a failing test.
5. Never silently fall back from Docker/Landlock/seccomp execution to host execution.
6. Treat model output and repository content as untrusted. Use strict schemas, argv arrays and `shell=False` by default.
7. Add a regression test for every security bug found.
8. Keep a clear distinction in code and reports between application-level policy decisions and kernel-enforced denials.
9. Record OS, kernel, Docker, image digest, Landlock ABI, syscall profile version and policy hash for every experiment.
10. Do not claim protection for a capability that is not enforced by the selected kernel control.

## 5. Phased implementation

### Phase 0 - Repository and threat-model setup

**Goal:** Establish the threat model, project structure and a reproducible development environment.

Tasks:

- [ ] Create the repository and target directory structure.
- [ ] Add README with purpose, scope, safety warning and quick-start placeholder.
- [ ] Document assets and assumptions: Linux-only first release, supported architecture, kernel baseline, Docker version and image digest strategy.
- [ ] Define attacker capabilities and protected assets.
- [ ] Define trust boundaries and non-goals from `architecture.md`.
- [ ] Add `.gitignore` for secrets, virtual environments, generated data and task outputs.
- [ ] Add pinned Python dependencies and development tooling, including LangChain, LangGraph, Pydantic and the selected model-provider integration.
- [ ] Create the Cargo workspace and pin Rust dependencies/toolchain.
- [ ] Define versioned JSON protocol between Python controller and Rust enforcement service.
- [ ] Add a CI workflow for formatting, static checks and unit tests.

**Deliverables:** repository skeleton, threat model, reproducible Python environment, Rust Cargo workspace, CI smoke test.

**Exit criteria:** clean clone can install dependencies and run an empty test suite without access to secrets or Docker daemon privileges.

### Phase 1 - Policy DSL and Rust schema validator

**Goal:** Build the canonical representation of what a task may do.

Tasks:

- [ ] Define `policy.schema.json` with schema versioning and strict unknown-field rejection.
- [ ] Implement policy loading, canonical serialization and SHA-256 policy hashing.
- [ ] Normalize filesystem paths and reject traversal, empty roots and invalid path overlap.
- [ ] Validate command/tool identifiers and syscall profile names against registered catalogs.
- [ ] Validate network policy and numeric resource ceilings.
- [ ] Implement policy templates for Python, Rust/C compilation and test execution workloads. The policy validator and ratchet authority are Rust; Python controller validation is defense in depth.
- [ ] Add a CLI command to validate and print a normalized policy without executing anything.
- [ ] Add tests for malformed JSON, unknown keys, wrong types, negative limits, unsupported rights, path traversal, symlink edge cases and policy hash stability.

**Deliverables:** JSON Schema, policy model, validator, templates, policy CLI.

**Exit criteria:** all policy validation tests pass; invalid policies never reach the worker supervisor.

### Phase 2 - Permission model and monotonic ratchet

**Goal:** Make permission changes deterministic and monotonic.

Tasks:

- [ ] Represent each permission class in a normalized form: filesystem rights, tool/executable identities, syscalls, network, and resource ceilings.
- [ ] Implement canonical path-containment checks.
- [ ] Implement `is_subset(new_policy, current_policy)` with documented semantics for every permission class.
- [ ] Implement ratchet state with task ID, epoch, current policy hash, transition history and reason codes.
- [ ] Accept unchanged or narrower policy updates.
- [ ] Reject every in-epoch expansion.
- [ ] Implement approval-required events and new-epoch creation without implicit permission inheritance.
- [ ] Add property-based tests proving that accepted updates never add permissions.
- [ ] Add tests for path-prefix confusion, symlink changes, executable additions, network enablement, syscall profile weakening and limit increases.

**Deliverables:** ratchet package, state persistence interface, event types and comprehensive tests.

**Exit criteria:** the subset invariant passes unit/property tests and every rejected expansion is auditable.

### Phase 3 - Structured audit and task state

**Goal:** Make decisions and execution measurable before implementing hostile execution.

Tasks:

- [ ] Define task/run/epoch lifecycle states.
- [ ] Define versioned event schema and JSONL writer.
- [ ] Add correlation IDs for task, run, action and process.
- [ ] Add redaction for common secret patterns and bounded output capture.
- [ ] Add policy-decision, ratchet-transition, task-status and error events.
- [ ] Add test utilities to assert event order and required fields.
- [ ] Implement basic report aggregation from raw events.

**Deliverables:** audit/event package, task state machine, redaction and event tests.

**Exit criteria:** a simulated task can be replayed from logs and all required transitions can be reconstructed without logging secrets.

### Phase 4 - Execution supervisor and process lifecycle

**Goal:** Build safe task isolation and process/resource supervision before enabling the full kernel layer.

Tasks:

- [ ] Build task workspace creation with unique IDs and strict containment.
- [ ] Build input staging that copies only approved repository files into the worker.
- [ ] Build argv-based command invocation with `shell=False`.
- [ ] Add wall-clock timeout, process-group handling and cancellation.
- [ ] Add CPU, address-space/memory, file-size, open-file and process-count limits where supported.
- [ ] Add bounded stdout/stderr and output byte limits.
- [ ] Build output collection that rejects unsafe archive paths and special files.
- [ ] Ensure a terminated task has no surviving descendants in its worker.
- [ ] Add a mock executor so supervisor tests do not require Docker.

**Deliverables:** supervisor, workspace manager, resource limit layer, safe artifact exporter.

**Exit criteria:** timeouts and cancellation reliably terminate a process tree in test containers; unsafe outputs are rejected.

### Phase 5 - Docker worker image and outer sandbox

**Goal:** Make every test execution disposable and reproducible.

Tasks:

- [ ] Build a minimal pinned Docker image with the supported runtimes and confined launcher dependencies.
- [ ] Run as a non-root user.
- [ ] Set read-only root filesystem, drop all capabilities, enable no-new-privileges and retain Docker's default seccomp profile unless a tested custom profile is required.
- [ ] Disable networking by default.
- [ ] Configure bounded scratch storage, memory, CPU, PID and ulimit settings.
- [ ] Ensure no Docker socket, host root, home directory, credentials or unnecessary devices are mounted.
- [ ] Add image and runtime preflight checks.
- [ ] Add integration tests for the actual Compose/run configuration.
- [ ] Capture the image digest and effective security configuration in run metadata.

**Deliverables:** `Dockerfile.executor`, Compose/run configuration, build script and container integration tests.

**Exit criteria:** the worker runs as non-root, cannot access the host workspace except through intentionally staged inputs/outputs, has no network by default and is destroyed after a run.

### Phase 6 - Landlock integration

**Goal:** Enforce task filesystem boundaries at the kernel layer.

Tasks:

- [ ] Probe Landlock availability and ABI version at runtime.
- [ ] Implement a small auditable launcher helper or a reviewed binding layer.
- [ ] Build ABI-aware handled-access masks; do not request rights unsupported by the detected kernel.
- [ ] Implement workspace read/write rules and minimum runtime read/execute rules.
- [ ] Apply Landlock in the final task process before untrusted code runs.
- [ ] Record installed rights and ABI in audit metadata.
- [ ] Add canary files outside the allowed workspace and verify they cannot be read or modified.
- [ ] Test path aliasing, symlinks, rename/link behavior, truncation rights, directory traversal and subprocess inheritance.
- [ ] Fail closed if required Landlock rules cannot be applied.

**Deliverables:** Landlock helper, policy-to-Landlock mapping, ABI capability tests and integration suite.

**Exit criteria:** protected filesystem tests pass on the documented target kernel; unsupported required operations cause a clear fail-closed result.

### Phase 7 - seccomp-BPF integration

**Goal:** Reduce the available system-call surface and preserve restrictions in child processes.

Tasks:

- [ ] Define versioned syscall profiles per supported runtime/workload.
- [ ] Start with a documented compatibility profile; distinguish denylist and default-deny profiles explicitly.
- [ ] Install `PR_SET_NO_NEW_PRIVS` and seccomp filter before untrusted `exec`.
- [ ] Deny high-risk or unnecessary system-call families for the selected profile.
- [ ] Verify expected normal operations remain available (runtime startup, file access, process creation, test execution).
- [ ] Verify denied syscalls fail with the expected errno/action.
- [ ] Test child, grandchild, fork/clone/exec and shell subprocess inheritance.
- [ ] Measure filter installation and execution overhead.
- [ ] Fail closed if the required profile cannot be installed.

**Deliverables:** seccomp profile catalog, launcher integration and syscall compatibility tests.

**Exit criteria:** expected syscall restrictions hold for the documented kernel/runtime; legitimate workload compatibility is measured.

### Phase 8 - Subprocess-aware enforcement and dynamic narrowing

**Goal:** Prove that the whole task process tree remains within the task boundary and that narrowing is respected.

Tasks:

- [ ] Integrate Landlock and seccomp into one final launcher sequence.
- [ ] Ensure all task code starts only after successful confinement.
- [ ] Test shell -> child -> grandchild paths and interpreter -> subprocess paths.
- [ ] Test daemonization and background children; stop the entire task container/cgroup on exit, timeout or cancellation.
- [ ] Implement policy narrowing between actions.
- [ ] For changes that cannot safely apply to an already-running process, restart in a new narrower worker/epoch.
- [ ] Correlate policy transitions with child-process events.
- [ ] Add adversarial tests where the parent intentionally delegates prohibited work to a child.

**Deliverables:** integrated confinement launcher, subprocess-monitoring layer and descendant test suite.

**Exit criteria:** no tested child/grandchild bypasses a parent's applied restrictions; task termination removes all descendants.

### Phase 9 - Code-executing agent loop

**Goal:** Connect a planner to the controlled executor without granting the planner direct host authority.

Tasks:

- [ ] Implement a custom **LangGraph `StateGraph`** with typed state and explicit nodes: `intake`, `context_loader`, `planner`, `plan_validator`, `action_normalizer`, `policy_decision`, `approval_interrupt`, `worker_dispatch`, `result_collector`, `completion_check` and `finalize`.
- [ ] Implement the planner node with **LangChain** chat-model/provider adapters and Pydantic structured output (for example, a typed `ActionProposal` / `ActionPlan` schema). Treat every model response as untrusted input.
- [ ] Define narrow LangChain tool schemas for task-scoped proposals such as `read_workspace_file`, `propose_patch`, `run_approved_test` and `request_permission`. Tools must not directly invoke host shell, Docker, policy mutation or unrestricted filesystem/network access.
- [ ] Implement a deterministic mock planner for test scenarios so security and baseline runs do not require an API key or nondeterministic model behavior.
- [ ] Implement the LangGraph conditional routes: valid proposal -> Rust policy decision; Rust `ALLOW` -> worker dispatch; `DENY` -> bounded replan or terminate; `APPROVAL_REQUIRED` -> trusted human interrupt; completion -> finalize.
- [ ] Make the policy-decision node call the Rust authority and revalidate the latest policy hash, epoch and action immediately before dispatch. LangGraph routing and LangChain tools must never override the Rust decision.
- [ ] Implement tool broker methods: bounded list/read/write/apply_patch/run_command/run_tests/request_permission operations, each backed by the trusted controller and Rust authorization.
- [ ] Ensure command arguments are arrays and shell execution is disabled by default.
- [ ] Limit planner context and tool outputs to the task workspace; return bounded excerpts rather than whole repositories or large command logs.
- [ ] Add retry logic for safe, recoverable failures without relaxing policy.
- [ ] Add the selected live LLM provider through LangChain only after deterministic mock-based enforcement and graph-routing tests pass.
- [ ] Use a local checkpointer for tests and approval/resume flows when persistence is enabled; persist only minimal, redacted graph state. Keep hosted LangSmith tracing disabled by default pending privacy review.
- [ ] Never let the LLM directly alter policy state, Docker settings or host paths.

**Deliverables:** agent loop, tool broker, mock planner, optional provider interface and end-to-end tests.

**Exit criteria:** a mock agent completes benign coding tasks and cannot bypass the policy gate via a direct tool call.

### Phase 10 - Evaluation harness and scenarios

**Goal:** Produce repeatable experimental evidence.

Tasks:

- [ ] Implement B0 isolated unconstrained, B1 sandbox-only and P1 full-system modes.
- [ ] Build scenario manifests with prompts, fixtures, expected effects, allowed behavior and scoring rules.
- [ ] Implement prompt-injection scenarios for direct user text and indirect repository content.
- [ ] Implement staged escalation scenarios for file, command, syscall, network and resource permissions.
- [ ] Implement subprocess misuse scenarios.
- [ ] Implement legitimate coding workloads for each supported runtime.
- [ ] Randomize or counterbalance run order where practical.
- [ ] Reset workspace and external state between each experimental run.
- [ ] Repeat scenarios and record denominators, outcomes and environment metadata.
- [ ] Add a results comparison script with confidence intervals or appropriate uncertainty summaries when sample sizes support them.

**Deliverables:** scenario corpus, run harness, raw run records and comparison report.

**Exit criteria:** a complete scenario batch can be executed reproducibly across all three arms, with every result traceable to its fixture and environment.

### Phase 11 - Performance, hardening and final report

**Goal:** Establish measured security-utility trade-offs and document limitations.

Tasks:

- [ ] Measure baseline and protected latency for matched workloads.
- [ ] Measure CPU and memory overhead where available.
- [ ] Measure legitimate completion rate and false denials.
- [ ] Measure attack success rate, unauthorized effects, blocked operations and attempted/denied policy expansions.
- [ ] Investigate failures and add regression tests.
- [ ] Run the full test suite against the pinned release image.
- [ ] Review Docker configuration and ensure no privileged flags or unnecessary mounts exist.
- [ ] Review logs for secret leakage.
- [ ] Document supported and unsupported kernels, runtimes, filesystem types and Docker modes.
- [ ] Generate reproducible charts/tables from raw measurement data.
- [ ] Write the final report without claiming protection beyond the tested cases.

**Deliverables:** release candidate, full test report, comparative results and limitations section.

**Exit criteria:** all mandatory success criteria are met or explicitly marked unmet with evidence and explanation.

## 6. Suggested milestone order

| Milestone | Phases | Demonstration |
|---|---|---|
| M1 - Policy core | 0-2 | JSON policy validation and a ratchet that rejects a permission expansion |
| M2 - Audited supervisor | 3-4 | Safe process execution with timeout, output limits and structured events |
| M3 - Docker execution | 5 | Non-root ephemeral worker with no network and resource limits |
| M4 - Kernel boundary | 6-7 | Landlock and seccomp block protected operations |
| M5 - Subprocess proof | 8 | Child/grandchild attempts remain confined |
| M6 - Agent integration | 9 | Mock planner completes a legitimate coding task through the tool broker |
| M7 - Comparative evaluation | 10-11 | B0/B1/P1 results, security/utility metrics and final report |

## 7. Definition of done for every feature

A feature is complete only when:

- Implementation is present and enabled in the intended mode.
- Unit tests cover valid and invalid behavior.
- Integration tests prove the real system path, not only a mock.
- Relevant adversarial tests are included when the feature affects security.
- Structured events identify its outcome.
- Documentation explains its security guarantee and limitations.
- Failure behavior is explicit and does not silently weaken confinement.
- The code has been reviewed for path traversal, unsafe shell use, race conditions and secret leakage where relevant.

## 8. Order of work for an autonomous coding agent

The implementation agent should process this plan as a dependency graph, not as permission to improvise the architecture:

1. Read all project specification files.
2. Inspect the repository and report existing code before making changes.
3. Implement only Phase 0 and Phase 1.
4. Run their tests and report exact commands/results.
5. Commit or checkpoint the working state.
6. Continue to the next phase only when exit criteria pass.
7. If a kernel feature is unsupported, report the limitation and add a capability-detection test; do not bypass the feature silently.
8. If a design change is necessary, update the architecture and test criteria first, explain its experimental impact, and preserve baseline comparability.
9. At the end of each phase, update a `progress.md` checklist with completed tasks, tests, known limitations and next phase.
10. At release, produce the evidence bundle described in `success_criteria.md`.

