//! argus-worker: the in-container entrypoint.
//!
//! ```text
//! argus-worker              read one WorkerRequest (JSON) on stdin, print a WorkerResult
//! argus-worker --file-op    internal: perform one file Operation (already confined)
//! argus-worker --preflight  report effective security state as JSON
//! argus-worker --version
//! ```
//!
//! Sequence for every action: validate the request (re-hash and re-validate the
//! embedded policy), plan kernel confinement, then spawn the operation in a
//! child that installs rlimits and confinement before `execve`. If a required
//! control cannot be installed, nothing runs (`confinement_failed`).

mod fileops;
mod patch;
mod preflight;
mod request;

use policy_model::{Confinement, Operation, Policy};
use process_supervisor::{run, Rlimits, RunOutcome, RunSpec, SpawnError, Termination};
use serde::Serialize;
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const RESULT_VERSION: &str = "1.0";
const EXEC_OUTPUT_CAP: usize = 256 * 1024;
const FILE_OP_OUTPUT_CAP: usize = 4 * 1024 * 1024;
const FILE_OP_MAX_SECS: u64 = 30;
/// errno used by the pre-exec hook to signal "confinement could not be installed".
const CONFINEMENT_ERRNO: i32 = libc::ENOTRECOVERABLE;

#[derive(Serialize, Default)]
struct ResourceUsage {
    peak_memory_bytes: u64,
    cpu_seconds: f64,
    peak_process_count: Option<u64>,
}

#[derive(Serialize)]
struct ConfinementReport {
    mode: &'static str,
    installed: bool,
    landlock_abi: Option<u32>,
    #[serde(skip_serializing_if = "Value::is_null")]
    landlock: Value,
    seccomp_profile: Option<String>,
    seccomp_installed: bool,
    #[serde(skip_serializing_if = "Value::is_null")]
    seccomp: Value,
    no_new_privs: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Serialize)]
struct WorkerResult {
    result_version: &'static str,
    run_id: String,
    task_id: String,
    epoch: u64,
    action_id: String,
    policy_hash: String,
    arm: String,
    status: &'static str,
    exit_code: Option<i32>,
    signal: Option<i32>,
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    duration_ms: u64,
    resource_usage: ResourceUsage,
    limit_hit: Option<&'static str>,
    descendants_killed: u32,
    process_tree: Vec<process_supervisor::ObservedProcess>,
    process_tree_truncated: bool,
    confinement: ConfinementReport,
    #[serde(skip_serializing_if = "Value::is_null")]
    file_result: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

impl WorkerResult {
    fn empty(status: &'static str, error: Option<String>) -> Self {
        WorkerResult {
            result_version: RESULT_VERSION,
            run_id: String::new(),
            task_id: String::new(),
            epoch: 0,
            action_id: String::new(),
            policy_hash: String::new(),
            arm: String::new(),
            status,
            exit_code: None,
            signal: None,
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            duration_ms: 0,
            resource_usage: ResourceUsage::default(),
            limit_hit: None,
            descendants_killed: 0,
            process_tree: Vec::new(),
            process_tree_truncated: false,
            confinement: ConfinementReport {
                mode: "none",
                installed: false,
                landlock_abi: None,
                landlock: Value::Null,
                seccomp_profile: None,
                seccomp_installed: false,
                seccomp: Value::Null,
                no_new_privs: false,
                detail: None,
            },
            file_result: Value::Null,
            error,
        }
    }
}

fn emit(r: &WorkerResult) {
    let mut out = std::io::stdout().lock();
    let _ = serde_json::to_writer(&mut out, r);
    let _ = out.write_all(b"\n");
    let _ = out.flush();
}

fn file_op_mode() -> i32 {
    let mut raw = Vec::new();
    if std::io::stdin()
        .take(request::MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut raw)
        .is_err()
    {
        return 2;
    }
    let result = match serde_json::from_slice::<Operation>(&raw) {
        Ok(op) => fileops::perform(&op),
        Err(e) => fileops::FileOpResult {
            ok: false,
            error_kind: Some("invalid"),
            message: Some(e.to_string()),
            data: Value::Null,
        },
    };
    let _ = serde_json::to_writer(std::io::stdout().lock(), &result);
    0
}

fn rlimits(policy: &Policy) -> Rlimits {
    let l = policy.limits;
    Rlimits {
        cpu_seconds: l.cpu_seconds,
        address_space_bytes: l.memory_bytes,
        file_size_bytes: l.file_size_bytes,
        open_files: l.open_files,
        // RLIMIT_NPROC counts every process of the UID, so it is only
        // meaningful when the worker owns its whole PID namespace (PID 1 in the
        // container, where the Docker pids limit also applies).
        processes: if std::process::id() == 1 {
            l.process_count
        } else {
            0
        },
    }
}

fn env(policy: &Policy) -> Vec<(String, String)> {
    vec![
        ("PATH".into(), "/usr/local/bin:/usr/bin".into()),
        ("HOME".into(), policy.workspace.clone()),
        ("TMPDIR".into(), "/tmp".into()),
        ("LANG".into(), "C.UTF-8".into()),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
        ("PYTHONUNBUFFERED".into(), "1".into()),
    ]
}

fn peak_pids() -> Option<u64> {
    std::fs::read_to_string("/sys/fs/cgroup/pids.peak")
        .ok()
        .and_then(|s| s.trim().parse().ok())
}

fn main() {
    let arg = std::env::args().nth(1);
    match arg.as_deref() {
        Some("--file-op") => std::process::exit(file_op_mode()),
        Some("--preflight") => {
            println!("{}", preflight::report());
            return;
        }
        Some("--version") => {
            println!("argus-worker {}", env!("CARGO_PKG_VERSION"));
            return;
        }
        Some(other) => {
            emit(&WorkerResult::empty(
                "rejected",
                Some(format!("unknown argument {other:?}")),
            ));
            std::process::exit(2);
        }
        None => {}
    }
    let started = Instant::now();
    let mut raw = Vec::new();
    if let Err(e) = std::io::stdin()
        .take(request::MAX_REQUEST_BYTES as u64 + 1)
        .read_to_end(&mut raw)
    {
        emit(&WorkerResult::empty(
            "error",
            Some(format!("cannot read request: {e}")),
        ));
        return;
    }
    let checked = match request::check(&raw) {
        Ok(c) => c,
        Err(e) => {
            emit(&WorkerResult::empty("rejected", Some(e)));
            return;
        }
    };
    let (req, policy) = (checked.req, checked.policy);
    let mut r = WorkerResult::empty("error", None);
    r.run_id = req.run_id.clone();
    r.task_id = req.task_id.clone();
    r.epoch = req.epoch;
    r.action_id = req.action_id.clone();
    r.policy_hash = req.policy_hash.clone();
    r.arm = req.arm.clone();

    if let Err(e) = process_supervisor::set_child_subreaper() {
        r.error = Some(format!("cannot become child subreaper: {e}"));
        emit(&r);
        return;
    }

    // Plan kernel confinement in the parent; install it in the child.
    let hook: Option<process_supervisor::PreExecHook> = match req.confinement {
        Confinement::None => None,
        Confinement::Kernel => match linux_confinement::plan(&policy) {
            Ok(plan) => {
                r.confinement = ConfinementReport {
                    mode: "kernel",
                    installed: false,
                    landlock_abi: Some(plan.landlock.handled_abi),
                    landlock: serde_json::to_value(&plan.landlock).unwrap_or(Value::Null),
                    seccomp_profile: Some(plan.seccomp.profile.clone()),
                    seccomp_installed: false,
                    seccomp: serde_json::to_value(&plan.seccomp).unwrap_or(Value::Null),
                    no_new_privs: plan.no_new_privs,
                    detail: None,
                };
                Some(Box::new(move || {
                    linux_confinement::install(&plan)
                        .map_err(|_| std::io::Error::from_raw_os_error(CONFINEMENT_ERRNO))
                }))
            }
            Err(e) => {
                r.status = "confinement_failed";
                r.confinement.mode = "kernel";
                r.confinement.detail = Some(e.to_string());
                r.duration_ms = started.elapsed().as_millis() as u64;
                emit(&r);
                return;
            }
        },
    };
    let is_kernel = hook.is_some();

    let (spec, is_file_op) = match &req.operation {
        Operation::Exec {
            argv,
            cwd,
            timeout_seconds,
        } => (
            RunSpec {
                argv: argv.clone(),
                cwd: cwd.clone(),
                env: env(&policy),
                stdin: None,
                timeout: Duration::from_secs(*timeout_seconds),
                rlimits: Some(rlimits(&policy)),
                output_cap: EXEC_OUTPUT_CAP,
                pre_exec: hook,
            },
            false,
        ),
        op => {
            let exe = match std::env::current_exe() {
                Ok(p) => p.to_string_lossy().to_string(),
                Err(e) => {
                    r.error = Some(format!("cannot locate self: {e}"));
                    emit(&r);
                    return;
                }
            };
            (
                RunSpec {
                    argv: vec![exe, "--file-op".into()],
                    cwd: "/".into(),
                    env: vec![("LANG".into(), "C.UTF-8".into())],
                    stdin: Some(serde_json::to_vec(op).expect("operation serializes")),
                    timeout: Duration::from_secs(
                        policy.limits.wall_time_seconds.min(FILE_OP_MAX_SECS),
                    ),
                    rlimits: Some(rlimits(&policy)),
                    output_cap: FILE_OP_OUTPUT_CAP,
                    pre_exec: hook,
                },
                true,
            )
        }
    };

    let outcome: Result<RunOutcome, SpawnError> = run(spec);
    r.duration_ms = started.elapsed().as_millis() as u64;
    let o = match outcome {
        Ok(o) => o,
        Err(SpawnError::Spawn(e)) if e.raw_os_error() == Some(CONFINEMENT_ERRNO) => {
            r.status = "confinement_failed";
            r.confinement.detail =
                Some("confinement install failed in child; command not executed".into());
            emit(&r);
            return;
        }
        Err(e) => {
            r.status = "failed";
            r.error = Some(e.to_string());
            emit(&r);
            return;
        }
    };
    r.confinement.installed = is_kernel;
    // install() succeeded only if both Landlock and seccomp were applied.
    r.confinement.seccomp_installed = is_kernel;
    r.exit_code = o.exit_code;
    r.signal = o.signal;
    r.descendants_killed = o.descendants_killed;
    r.process_tree = o.process_tree;
    r.process_tree_truncated = o.process_tree_truncated;
    r.limit_hit = o.limit_hit;
    r.resource_usage = ResourceUsage {
        peak_memory_bytes: o.peak_memory_bytes,
        cpu_seconds: o.cpu_seconds,
        peak_process_count: peak_pids(),
    };
    r.stderr = String::from_utf8_lossy(&o.stderr).into_owned();
    r.stderr_truncated = o.stderr_truncated;
    if is_file_op {
        match serde_json::from_slice::<Value>(&o.stdout) {
            Ok(v) => {
                r.status = if v["ok"] == true {
                    "completed"
                } else {
                    "failed"
                };
                r.file_result = v;
            }
            Err(_) => {
                r.status = if o.termination == Termination::TimedOut {
                    "timeout"
                } else {
                    "failed"
                };
                r.file_result = json!({"ok": false, "error_kind": "worker_child_failed"});
            }
        }
    } else {
        r.stdout = String::from_utf8_lossy(&o.stdout).into_owned();
        r.stdout_truncated = o.stdout_truncated;
        r.status = match (o.termination, o.exit_code) {
            (Termination::TimedOut, _) => "timeout",
            (Termination::Exited, Some(0)) => "completed",
            _ => "failed",
        };
    }
    emit(&r);
}
