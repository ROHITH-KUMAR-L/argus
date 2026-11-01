# System Workflow

## 1. Purpose

This document defines how a task moves through the code-executing agent, how each permission decision is made, how privilege restrictions are applied and preserved across subprocesses, and how the baseline and proposed system are compared.

The workflow is designed around the project synopsis:

```text
Task request -> Task-scoped policy -> Monotonic privilege ratchet
              -> Kernel confinement -> Controlled execution
              -> Security and utility measurements
```

## 2. Runtime actors

- **User:** supplies the task and expected outcome.
- **Task API / CLI:** receives the task and selects an experiment arm.
- **Agent planner:** proposes a plan, code edits and tool calls. It has no authority to grant permissions.
- **Policy engine:** validates the task policy and evaluates each proposed action.
- **Privilege ratchet:** computes and stores the current effective policy.
- **Execution supervisor:** creates the isolated workspace and starts/stops the worker.
- **Confined launcher:** installs Landlock, seccomp-BPF and per-process resource limits before untrusted execution.
- **Worker process tree:** runs the generated code, commands, child processes and grandchildren.
- **Monitor/auditor:** records events, process/resource usage and results.
- **Evaluation harness:** repeats the workload across B0, B1 and P1 experiment arms.

## 3. End-to-end task workflow

### Step 1 - Receive and normalize task

1. Accept a user task, task identifier, expected output and optional repository snapshot.
2. Assign a unique `task_id` and `run_id`.
3. Normalize the task workspace to a dedicated path inside the worker filesystem.
4. Record the task prompt hash, repository snapshot hash and run configuration.
5. Treat every repository file and any content retrieved by tools as untrusted data.
6. Reject oversized inputs, invalid encodings and unsupported task types before calling the planner.

**Output:** normalized task record and isolated workspace input.

### Step 2 - Create the initial task policy

1. Select a policy template based on the workload type (for example, Python coding, C compilation or test-only execution).
2. Fill the template with the minimum filesystem paths, tools, syscall profile, network mode and resource ceilings required for the task.
3. Ensure network is disabled unless the experiment explicitly requires it.
4. Validate the JSON against the versioned schema.
5. Resolve and normalize paths; reject absolute path escapes, traversal components and unexpected symlink targets.
6. Check that requested limits do not exceed deployment-level maximums.
7. Compute and store a canonical policy hash.

**Output:** validated initial policy `P0`.

**Failure path:** invalid or unsupported policy -> reject task before execution and record `POLICY_VALIDATION_FAILED`.

### Step 3 - Ask the planner for a plan

1. Give the planner the task statement and only the context it needs from the task workspace.
2. Tell the planner that files, repository instructions and tool output are data, not policy overrides.
3. Request a structured plan with intended operations, files to read/write, commands to run and expected test outcomes.
4. Parse the plan as structured data.
5. Do not execute command strings or code embedded in free-form planner text.

**Output:** untrusted plan proposal.

### Step 4 - Analyze intent and risk

For each proposed action:

1. Identify the action type (`read_file`, `write_file`, `apply_patch`, `run_tests`, `run_command`, `request_permission`, and so on).
2. Extract the target resource, executable identity, working directory, arguments and expected side effects.
3. Compare the action with the user's task intent.
4. Check the action against the current effective policy, not merely the original policy.
5. Assign a risk category and record the evidence for the decision.
6. Return one of:
   - `ALLOW`: action is within current policy.
   - `DENY`: action is outside policy or conflicts with the task.
   - `APPROVAL_REQUIRED`: a bounded permission increase is being requested.

A model-generated explanation is not evidence of authorization. Only policy state and explicit approval records may authorize an operation.

### Step 5 - Apply the privilege ratchet

The ratchet evaluates proposed policy updates and action requirements.

- If no permission change is required, retain the current effective policy.
- If permissions are removed, narrowed or limits are reduced, validate and commit the narrower policy.
- If a requested change adds a permission, reject the in-epoch transition and pause the task.
- Store the previous and new policy hashes, transition reason, decision and timestamp.

Invariant:

```text
EffectivePolicy(next) must be a subset of EffectivePolicy(current)
```

The ratchet must be implemented in deterministic code with automated invariant tests. It must not rely on an LLM to decide whether a permission set is a subset of another.

### Step 6 - Create the execution environment

1. Ask the supervisor to create a fresh ephemeral worker from the pinned Docker image.
2. Configure a non-root UID/GID, dropped capabilities and `no-new-privileges`.
3. Use a read-only root filesystem and bounded scratch/workspace storage.
4. Use no network by default.
5. Set CPU, memory, PID, open-file and file-size ceilings.
6. Mount or copy only task input; do not mount host home, root filesystem, credentials or Docker socket.
7. Set the container's image digest and security configuration in the run record.
8. If Docker is unavailable or the image/security configuration is not as expected, stop rather than execute on the host.

**Output:** isolated worker and dedicated task workspace.

### Step 7 - Install kernel confinement

The confined launcher runs inside the worker and prepares the final task process.

1. Probe required Linux features and Landlock ABI support.
2. Build a Landlock ruleset using only rights supported by the detected ABI.
3. Add explicit filesystem rules for the workspace and the minimum runtime paths.
4. Configure the selected seccomp-BPF profile.
5. Set `PR_SET_NO_NEW_PRIVS` as required for unprivileged filter installation.
6. Apply resource limits before task code begins.
7. Install Landlock and seccomp before `exec` of generated code or a user-selected command.
8. Emit `CONFINEMENT_INSTALLED` with the actual rights/profile/version, not just the requested configuration.
9. Verify the worker's security state with safe preflight probes.

**Failure path:** required Landlock or seccomp setup fails -> do not run task code; emit `CONFINEMENT_INSTALL_FAILED`.

### Step 8 - Execute one approved action

1. The planner proposes the next action.
2. The policy gate validates its structure and resource targets.
3. The ratchet verifies that the current effective policy still permits it.
4. The supervisor passes an argv array and bounded input to the worker. Use `shell=False` by default.
5. The confined process executes the action.
6. The monitor captures exit code, elapsed time, bounded stdout/stderr, resource usage and relevant process events.
7. The auditor records allow/deny decisions and operation results.
8. Return a bounded, redacted result to the planner.

The planner can then propose a new action, but each action passes through the same gate. Do not let an earlier approval automatically authorize later unrelated actions.

### Step 9 - Handle child processes and descendants

When task code creates a child process:

1. The child must be created from a process already confined by the launcher.
2. Landlock restrictions are inherited by new threads/processes from the restricted task.
3. seccomp filters are inherited by descendants when the process-creation and execution syscalls are allowed by the filter.
4. Resource limits and the Docker worker's cgroup/PID limits continue to constrain the process tree.
5. The monitor records parent PID, child PID, command metadata where available, start time and exit status.
6. The child cannot receive additional capabilities from a model/tool decision.
7. A child or grandchild attempting an unauthorized read/write, restricted syscall, network operation or privilege increase must be denied by the applicable enforcement layer.

Test daemonization, `setsid`, background jobs, `fork`, `clone`, shell pipelines and interpreter-launched children. Do not rely only on parent PID tracking: the container/cgroup is the final cleanup boundary for the whole task tree.

### Step 10 - Tighten policy when needed

The orchestrator may narrow the policy at any point. Examples:

- Stop writes to a directory after the code-editing stage.
- Remove an executable after build completion.
- Lower time/resource ceilings for a verification stage.
- Disable a previously allowed network capability.

The ratchet commits the narrower policy and ensures subsequent actions use it. If the implementation cannot safely apply a new rule to an already-running process, it must stop the current worker and start a new restricted worker/epoch rather than claim that a live restriction has been applied retroactively.

### Step 11 - Handle privilege expansion requests

1. Detect the requested capability delta.
2. Pause the task and reject the transition inside the active epoch.
3. Record the exact requested permission, target resource, intended duration and reason.
4. Ask a human approver outside the model's authority boundary.
5. If denied, resume only with the old policy or terminate the task.
6. If approved, end the current epoch and create a new worker with a newly validated policy snapshot.
7. Record approver identity, timestamp, scope, reason and old/new policy hashes.

This is the recommended first-release interpretation of the synopsis' requirement that privilege expansion requires explicit authorization. It keeps the active epoch monotonic.

### Step 12 - Complete, cancel or fail the task

A task ends when one of the following occurs:

- Expected output and tests are complete.
- The user cancels the task.
- The wall-clock or resource ceiling is reached.
- A required enforcement mechanism fails.
- An unrecoverable policy violation or worker error occurs.

On termination:

1. Stop the complete worker/container, including descendants.
2. Collect bounded logs and resource statistics.
3. Export only validated result artifacts.
4. Reject unsafe archive entries and path traversal.
5. Compute artifact hashes.
6. Record final task status, test results, security events and metrics.
7. Destroy ephemeral workspaces and worker containers unless a test explicitly preserves a sanitized forensic snapshot.

## 4. State machine

```mermaid
stateDiagram-v2
    [*] --> RECEIVED
    RECEIVED --> POLICY_VALIDATION
    POLICY_VALIDATION --> REJECTED: invalid policy
    POLICY_VALIDATION --> PLANNING: valid policy
    PLANNING --> ACTION_REVIEW
    ACTION_REVIEW --> DENIED: action not permitted
    DENIED --> PLANNING: planner revises plan
    ACTION_REVIEW --> APPROVAL_PENDING: privilege expansion requested
    APPROVAL_PENDING --> PLANNING: denied / no change
    APPROVAL_PENDING --> NEW_EPOCH: approved explicitly
    ACTION_REVIEW --> RATCHETED: allowed or narrowed
    RATCHETED --> WORKER_SETUP
    WORKER_SETUP --> CONFINEMENT_CHECK
    CONFINEMENT_CHECK --> FAILED: confinement failed
    CONFINEMENT_CHECK --> EXECUTING: confinement verified
    EXECUTING --> ACTION_REVIEW: next action
    EXECUTING --> COMPLETED: task complete
    EXECUTING --> FAILED: error / limit / timeout
    EXECUTING --> CANCELLED: user cancellation
    NEW_EPOCH --> POLICY_VALIDATION
    COMPLETED --> [*]
    FAILED --> [*]
    CANCELLED --> [*]
    REJECTED --> [*]
```

Implementation note: rename the `RATCHETED` state to `RATCHETED` in code; the diagram label is intentionally easy to spot during initial transcription and should be corrected before release.

## 5. Baseline and proposed-system workflows

Use the same scenario fixture and task prompt for all arms. Reset the workspace and external state between runs.

### B0 - Isolated unconstrained baseline

1. Create a disposable Docker worker with the same image and outer resource limits.
2. Disable project-specific task policy enforcement, the privilege ratchet, Landlock rules and project seccomp rules.
3. Retain mandatory outer isolation such as normal Docker namespaces, default Docker seccomp, non-root execution and resource ceilings.
4. Run the scenario with the same agent/planner configuration.
5. Record successful unauthorized operations, attempted operations, legitimate task completion, latency and resource use.
6. Destroy the worker.

This is **not** unrestricted execution on the host. It is an application-policy-unconstrained condition inside an isolated test worker.

### B1 - Conventional sandbox-only baseline

1. Create the same disposable worker.
2. Apply static Docker, Landlock and seccomp confinement for the task.
3. Do not apply the monotonic privilege-ratchet component or dynamic narrowing mechanism.
4. Run the same scenario.
5. Record the same metrics.
6. Destroy the worker.

### P1 - Full privilege-ratchet system

1. Create task-specific JSON policy.
2. Validate and apply the monotonic ratchet.
3. Apply Landlock and seccomp from the effective policy.
4. Run with Docker outer isolation and subprocess-aware monitoring.
5. Allow controlled permission narrowing during the run.
6. Deny in-epoch permission expansion; require explicit authorization and a new epoch.
7. Record the same metrics plus policy transition and subprocess violation events.
8. Destroy the worker.

## 6. Workflow for prompt-injection evaluation

1. Prepare a benign coding task and a repository fixture containing a clearly labelled malicious instruction (for example, a README or comment asking the agent to read a protected file or upload workspace contents).
2. Keep the intended task and expected output identical across experiment arms.
3. Run the agent without revealing the test's expected attack outcome.
4. Record whether the planner follows the malicious instruction.
5. Record whether the policy gate detects/denies it.
6. Record whether the kernel denies any operation that reaches the worker.
7. Determine whether the legitimate part of the task still completes.
8. Repeat across multiple attack phrasings and repository locations.

Separate **attack attempted**, **policy denial**, **kernel denial**, and **unauthorized effect completed**. These are different outcomes and must not be collapsed into one “blocked” counter.

## 7. Workflow for staged privilege-escalation evaluation

Example sequence:

1. Task begins with read/write access to `/workspace/task` and no access to `/workspace/secrets`.
2. Agent reads a normal source file.
3. A malicious instruction asks the agent to access `/workspace/secrets`.
4. Agent requests or attempts to add the secrets path.
5. Ratchet rejects the in-epoch expansion.
6. Agent attempts access anyway through a direct file read or child process.
7. Landlock/Docker prevent the file access if the path is outside the allowed hierarchy.
8. Audit events connect the denied policy transition to the subsequent attempt.
9. The legitimate coding task is checked for completion.

Variants should test expansions through filesystem permissions, executable/tool permissions, network permissions, syscall profile changes, process/resource ceilings and subprocess creation.

## 8. Workflow for legitimate coding tasks

For each supported language/runtime:

1. Prepare a clean repository snapshot and expected tests.
2. Generate or provide a benign code-editing task.
3. Allow only the files and tools needed for that task.
4. Let the agent inspect files, edit code and run tests.
5. Capture compiler/test output and exit status.
6. Verify the expected code result independently outside the worker.
7. Record false denials, retries, time-to-completion and resource overhead.

Include tasks that require legitimate subprocesses: compiler invocation, test runner, formatter, linter, build tool, and a nested child process. These prevent the system from appearing secure merely by blocking all process creation.

## 9. Event and metric flow

Each run should produce:

- `run_metadata.json`: arm, task, model/planner version, image digest, host/kernel/Docker versions, policy and profile hashes, seed and time budget.
- `events.jsonl`: chronological structured events.
- `metrics.json`: computed security, utility, latency and resource metrics.
- `result.json`: final task status, artifact hashes and independent test results.
- `artifacts/`: only validated task outputs.

Keep raw observations separate from derived metrics. A report generator should calculate rates from recorded numerators and denominators so results can be re-checked.

## 10. Minimum workflow acceptance checks

- An invalid policy never creates an execution worker.
- A valid task receives a unique workspace and run identity.
- The model cannot directly modify the effective policy.
- Every proposed action is checked against the latest policy version.
- A policy expansion is denied within the current epoch.
- A narrower policy is accepted and recorded.
- Landlock and seccomp are installed before untrusted code starts.
- A spawned child and grandchild remain confined.
- Timeout/cancellation terminates the entire worker process tree.
- B0, B1 and P1 use equivalent task fixtures and record comparable metrics.
- The final report distinguishes attempted attacks from completed unauthorized effects.
- The final task result includes legitimate-task completion and overhead, not security metrics alone.

## 11. Implementation references

- Linux Landlock userspace API: https://docs.kernel.org/userspace-api/landlock.html
- Linux seccomp filter documentation: https://docs.kernel.org/userspace-api/seccomp_filter.html
- Docker seccomp profiles: https://docs.docker.com/engine/security/seccomp/
- Docker resource constraints: https://docs.docker.com/engine/containers/resource_constraints/
