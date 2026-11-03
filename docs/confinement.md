# Kernel Confinement: What Is Enforced

This document covers **Landlock** (Phase 6). seccomp-BPF (Phase 7) will be added to it. Every statement here holds for the environment of record in `progress.md` (Linux 7.2, Landlock kernel ABI 10, handled ABI 9) and is backed by `tests/confinement/`.

## Sequence in `argus-worker`

1. In the parent, `linux_confinement::plan(policy)`:
   - probe the kernel ABI; `0` means **fail closed** (`confinement_failed`, LL-018);
   - handled ABI = `min(kernel ABI, 9)`; 9 is the newest ABI the pinned `landlock` 0.4.7 crate can express. Both numbers are reported;
   - `read_only` rules get `Execute | ReadFile | ReadDir`. `read_write` rules get every right handled at that ABI. Non-directory roots (`/dev/null`) get the file-applicable subset.
2. In the forked child, before `execve`, `install(plan)`:
   - the ruleset is a hard requirement (`CompatLevel::HardRequirement`), with no silent downgrade;
   - each rule root is opened **component by component with `O_NOFOLLOW`**. A symlink anywhere in a rule path is fatal (LL-019: an earlier action cannot redirect a later grant by planting a symlink). A missing root grants nothing and is reported as skipped;
   - ABI ≥ 4: TCP bind/connect are handled; only policy ports are granted (none by default);
   - ABI ≥ 6: signal and abstract-UNIX-socket **scoping**, so the task cannot signal the unconfined supervisor (PID 1) or anything outside its domain;
   - `restrict_self` must report `FullyEnforced` with `no_new_privs`; anything else fails the spawn (`confinement_failed`).
3. File operations (list, read, write, patch) run in a re-executed `argus-worker --file-op` child under the same confinement.

The child is single-threaded when it restricts itself, and every task thread and process is created afterwards. Threads (LL-022), children, grandchildren and `setsid` processes (LL-020/021) all inherit the domain. Rust opens descriptors with `O_CLOEXEC`, so the task starts with only fds 0–2 (LL-015).

## Attribution

Each denial test runs the same probe in **B0** (same image, same policy, no project Landlock), where it succeeds. Landlock denials appear as `EACCES`, or `EXDEV` for cross-hierarchy rename/link. The read-only container root shows as `EROFS`, which is a different layer and is never counted as a Landlock result.

## Observed behaviour of special paths (LL-016)

| Probe | P1 result | Note |
|---|---|---|
| `/proc/self/status` read | `EACCES` | procfs is not granted by the templates |
| `/proc/self/root/<canary>` | denied | path alias resolves to the same inode, so Landlock still applies |
| `/dev/zero` read | `EACCES` | only `/dev/null` (read-write) and `/dev/urandom` (read-only) are granted |
| `/dev/null` write | allowed | needed by `subprocess.DEVNULL` |
| `kill(1, SIGTERM)` | `EPERM` | ABI 6 signal scoping |

## Limits of this layer

- Landlock controls only the access rights it handles at the running ABI. Rights newer than ABI 9 (if the kernel adds any) are not handled until the crate is upgraded; the report shows both ABIs.
- It does not restrict which executables run inside granted hierarchies. Executable allowlisting is broker-level: the planner can only request catalog executables, but code already running can execute anything under `/usr` (granted read + execute).
- Descriptors opened *before* restriction would remain usable. The design opens none for the task.
- Older-ABI behaviour (LL-017) is covered by planning unit tests (`crates/linux-confinement/tests/plan.rs`). Running on an older kernel is **UNSUPPORTED** on this host.
