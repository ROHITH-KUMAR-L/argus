# Task Policy Reference (schema 1.0)

The authoritative validator is `crates/policy-validator` (Rust). `schemas/policy.schema.json` is a shape-only schema that the Python controller uses for early, non-authoritative checks. To validate a policy without running anything:

```bash
cargo run -q --bin argus-policy -- validate config/templates/python-task.json
```

## Fields

| Field | Meaning |
|---|---|
| `schema_version` | Must be `"1.0"`. Other versions are rejected because no migration is defined. |
| `task_id` | 1–64 characters from `[A-Za-z0-9._-]`; must not start with `.` |
| `workspace` | Must equal the deployment's workspace path (`/workspace/task`) |
| `filesystem.read_only` | Hierarchies granted read + execute |
| `filesystem.read_write` | Hierarchies granted read + write + execute. Each must lie inside a writable root (`/workspace/task`, `/tmp`) or be an allow-listed device. |
| `filesystem.deny` | A statement of deny intent. It **must not overlap** any allowed hierarchy (see below). |
| `filesystem.required_rights` | Landlock rights that must be enforceable on the detected ABI, otherwise the policy is rejected (POL-014) |
| `commands.allowed_tool_names` | A subset of the registered broker tools |
| `commands.allowed_executables` | Absolute paths from the executable catalog. Each must lie inside an execute-granted hierarchy. Shells are only allowed when `shell` is `"allow"`. |
| `syscalls.profile` | A registered seccomp profile (`python-build-v1`, `c-build-v1`, `minimal-run-v1`) |
| `syscalls.deny_high_risk` | Extra denials layered on top of the profile; each must be an x86_64 syscall name |
| `network.mode` | `none`, or `tcp_ports` (requires Landlock ABI ≥ 4 and a deployment that permits network). UDP is rejected because Landlock cannot enforce it. |
| `limits.*` | Positive integers no greater than the deployment maximum. Clamping happens only when the deployment enables it, and every clamp is reported as a warning. |
| `approval` | Must be `required_for_privilege_step_up: true` and `approval_mode: "new_execution_epoch"` |

## Path rules

Paths must already be canonical. Anything else is rejected, never silently rewritten:
- absolute;
- no empty, `.` or `..` components;
- no trailing slash;
- no `%`, `\`, NUL or control characters.

Containment is checked component by component, so `/workspace/app` does not contain `/workspace/application`.

Deployment guard rails:
- An allowed path may not equal or contain a protected path (`/home`, `/root`, `/run`, `/var/run`, `/proc`, `/sys`, `/boot`, `/dev`, `/etc/shadow`, …). This means `/` and `/etc` are rejected.
- An allowed path may not lie under a forbidden subtree. The only exceptions are allow-listed devices such as `/dev/null`.

**Why deny may not overlap allow.** Landlock only grants access; it has no "deny this subtree" rule. Allowing `/workspace` while denying `/workspace/secrets` cannot be enforced by the kernel, so the validator rejects the policy (`DENY_ALLOW_OVERLAP`) rather than letting it look enforced. Narrow the allow rules instead.

## Normalization and hashing

- All lists are sorted and de-duplicated.
- A path listed under both `read_only` and `read_write` gets read-write access, which is exactly what was requested.
- An entry is dropped when an ancestor already grants a superset of its access. `/usr/lib` under `/usr` is redundant, and so is anything read-only under a read-write root.
- The canonical form is the normalized policy serialized as JSON with sorted keys. `policy_hash = "sha256:" + hex(sha256(canonical_json))`. Reordering keys never changes the hash (POL-016); changing any permission always does (POL-017).

## What this layer does *not* guarantee

Validation proves that a policy is well-formed and stays within the deployment guard rails. Enforcement comes from the ratchet (Phase 2), Landlock (Phase 6) and seccomp (Phase 7). Two cases are only partly covered at this layer:
- Symlinks inside the container (POL-010) are handled at enforcement time: Landlock checks the resolved path, and the launcher opens rule roots without following symlinks.
- Workspace ownership (POL-020) is enforced when the controller stages the workspace volume.
