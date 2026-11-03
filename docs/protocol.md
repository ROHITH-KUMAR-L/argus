# Controller ↔ Rust Authority Protocol (v1)

The Python controller talks to `ratchetd`, the authoritative Rust policy/ratchet daemon, over a local Unix-domain socket. Python may validate defensively, but **only `ratchetd` decides**. Every execution request is revalidated by Rust against the *current* policy hash and epoch at dispatch time (STACK-005, STK-010).

## 1. Transport

| Property | Value |
|---|---|
| Socket (decision) | `$ARGUS_RUNTIME_DIR/ratchetd.sock`, default `$XDG_RUNTIME_DIR/argus/ratchetd.sock` |
| Socket (approval) | `$ARGUS_RUNTIME_DIR/ratchetd-approve.sock`, used only by the trusted `argus approve` CLI and never by the agent graph |
| Permissions | runtime dir `0700`, sockets `0600`, owned by the controller user. `ratchetd` also checks `SO_PEERCRED` and rejects any peer UID other than its own. |
| Framing | 4-byte big-endian unsigned length, then a UTF-8 JSON object. Maximum frame size is 1 MiB; larger frames close the connection. |
| Concurrency | One request in flight per connection. The daemon serializes all state mutations. |

## 2. Envelope

Request:

```json
{"protocol_version": "1", "request_id": "6f0c…", "method": "evaluate_action", "params": {}}
```

Response:

```json
{"protocol_version": "1", "request_id": "6f0c…", "ok": true, "result": {}}
{"protocol_version": "1", "request_id": "6f0c…", "ok": false, "error": {"code": "STALE_POLICY_HASH", "message": "…"}}
```

Rules:
- Unknown fields anywhere are rejected (`MALFORMED_REQUEST`).
- `protocol_version` must equal `"1"` (`UNSUPPORTED_PROTOCOL_VERSION`).
- `request_id` is 8 to 64 characters from `[A-Za-z0-9_-]` and must not repeat within the daemon's lifetime (`REPLAYED_REQUEST`).
- Any error response carries no partial grant. Callers must treat it as `DENY`.

## 3. Methods

| Method | Params | Result | Notes |
|---|---|---|---|
| `health` | none | `{daemon_version, protocol_version, arm}` | Read-only |
| `validate_policy` | `{policy}` | `{normalized_policy, policy_hash}` | No state change |
| `open_task` | `{task_id, policy}` | `{task_id, epoch_id, epoch, policy_hash}` | Validates `policy` as P0 for epoch 1 |
| `evaluate_action` | `{task_id, epoch_id, policy_hash, action}` | `{decision, reason_code, evidence, dispatch?}` | `decision` ∈ `ALLOW`, `DENY`, `APPROVAL_REQUIRED`. `dispatch` is present only on `ALLOW` and holds the effective-policy snapshot plus the resolved argv for the worker. |
| `apply_narrowing` | `{task_id, epoch_id, expected_policy_hash, proposed_policy, reason}` | `{accepted, policy_hash, transition_id, delta?}` | Rejects any expansion with `PRIVILEGE_EXPANSION_DENIED` and the requested delta |
| `request_expansion` | `{task_id, epoch_id, policy_hash, proposed_policy, reason}` | `{expansion_id, status: "APPROVAL_PENDING", delta}` | Never grants anything by itself |
| `approve_expansion` | `{task_id, expansion_id, approver, decision}` | `{epoch_id, epoch, policy_hash}` or `{status: "DENIED"}` | **Approval socket only.** Approval closes the old epoch and opens a new one with a freshly validated policy. |
| `close_epoch` | `{task_id, epoch_id, reason}` | `{closed: true}` | Further calls on that epoch return `EPOCH_CLOSED` |
| `get_state` | `{task_id}` | `{epoch_id, epoch, policy_hash, transitions}` | Read-only |

`evaluate_action` returns `DENY`, without dispatch, whenever `policy_hash` or `epoch_id` does not match the current state. A stale plan or a replayed checkpoint therefore cannot restore earlier privileges (STK-012).

## 4. Error codes

`MALFORMED_REQUEST`, `UNSUPPORTED_PROTOCOL_VERSION`, `REPLAYED_REQUEST`, `FRAME_TOO_LARGE`, `UNKNOWN_METHOD`, `UNKNOWN_TASK`, `TASK_EXISTS`, `EPOCH_CLOSED`, `STALE_EPOCH`, `STALE_POLICY_HASH`, `POLICY_VALIDATION_FAILED`, `PRIVILEGE_EXPANSION_DENIED`, `UNKNOWN_EXPANSION`, `METHOD_NOT_PERMITTED_ON_SOCKET`, `STATE_STORE_UNAVAILABLE`, `INTERNAL`.

## 5. State persistence

`ratchetd` keeps an append-only JSONL transition log under `$ARGUS_STATE_DIR` (default `$XDG_STATE_HOME/argus/ratchetd/`), which only the Rust daemon writes. On start it replays the log. If any record is unparsable, has a broken hash chain, or would broaden a policy, the daemon refuses to serve (`STATE_STORE_UNAVAILABLE`) instead of guessing.

## 6. Controller → worker request (stdin of `argus-worker`)

This is a single JSON object, at most 1 MiB, and its shape is the `dispatch` object returned by `evaluate_action`. See `schemas/worker_request.schema.json` and `schemas/worker_result.schema.json`. The worker re-checks `policy_hash` against the canonical policy it receives and fails closed on any mismatch.
