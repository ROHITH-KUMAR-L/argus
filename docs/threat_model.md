# Threat Model

Scope: the first-release prototype described in `architecture.md`. Supported environment: a Linux x86_64 host with Landlock enabled, Docker Engine with cgroup v2, a Rust launcher inside a pinned worker image, and Python + C as the untrusted workload runtimes.

## 1. Protected assets

| Asset | Where it lives | Why it matters |
|---|---|---|
| Host filesystem (home, SSH keys, credentials, other projects) | Host | Must never be reachable from task code |
| LLM API key (`.env`) | Controller process only | Leakage enables abuse/billing; never enters worker or image |
| Docker daemon access | Controller (`docker` group or socket) | Root-equivalent on a rootful host |
| Ratchet state and effective policy | `ratchetd` memory and its state directory | Corruption could broaden privileges |
| Trusted audit log | Controller `runs/` directory | Evidence for every claim |
| Files outside the task's allowed paths inside the worker (canaries, `/etc`) | Worker image | Stand-ins for sensitive data in experiments |

## 2. Attacker model

The attacker controls:

- **task content**: the user prompt, repository files, README files, comments and test fixtures (direct and indirect prompt injection);
- **planner output**: any LLM response may be adversarial, and it is treated as untrusted structured data;
- **code running inside the worker**: generated code, build scripts and anything they spawn (children, grandchildren, daemons).

The attacker does **not** control the host kernel, the Docker daemon, the controller process, `ratchetd`, the worker image build, or the human approver. These form the trusted computing base.

## 3. Trust boundaries

- **A. Content → planner.** Repository text and tool output are data, never policy.
- **B. Planner → policy gate.** Proposals are validated against a strict schema (Python), then decided by `ratchetd` (Rust). The model has no tool that writes policy, touches Docker or reaches the host shell.
- **C. Controller → worker.** A fresh container is created for each action with a hardened, fixed configuration. The worker receives only its task volume and a bounded JSON request on stdin. It gets no host bind mounts, no Docker socket, no credentials and no network.
- **D. Worker → host.** Only a tar stream of expected outputs comes back. It is validated, and entries that are absolute, contain `..`, or are links or special files are rejected. Output is bounded.

## 4. Attacker goals considered

1. Read or modify files outside the allowed paths, including through children and grandchildren.
2. Execute prohibited high-risk syscalls (mount, ptrace, bpf, namespaces, kernel modules, reboot, and similar).
3. Regain a narrowed permission within an epoch: a staged escalation, a stale plan, or a checkpoint replay.
4. Self-approve a privilege expansion.
5. Escape the process-tree lifecycle (daemonize, `setsid`) to outlive the action.
6. Exhaust resources (fork bombs, memory, disk, output flooding).
7. Smuggle data out through network, artifact export or log output.

## 5. Known residual risks and non-goals

- **Rootful Docker.** On the development host, the controller's access to the Docker daemon is root-equivalent. A compromised *controller* (not the worker) would have host-root power. Mitigations: a narrow Docker adapter with a hard-coded config, and no planner-controlled Docker parameters. Rootless Docker or Podman is recommended for shared machines and is evaluated as an optional configuration.
- **Shared kernel.** Docker shares the host kernel, so a kernel vulnerability can break every layer at once. This prototype does not claim VM-level isolation.
- **Executable allowlisting is broker-level only.** seccomp cannot inspect `execve` path strings, so hostile code inside an interpreter can run any binary present in the image. The image is kept minimal, and Landlock execute rights limit which hierarchies are executable.
- **Approver identity.** Approval arrives on a separate socket owned by the same OS user. The prototype separates approval by channel and does not authenticate a distinct human identity.
- **Prompt injection is not prevented.** The project measures whether its effects are contained; it does not claim injection can never succeed.
- **Fixed architecture and kernel.** Only Linux x86_64 with Landlock ABI ≥ 1 is supported. Older ABIs mark the affected rights UNSUPPORTED.
