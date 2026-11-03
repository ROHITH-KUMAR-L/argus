//! Process-tree supervision for one action.
//!
//! * argv-only execution (no shell), cleared environment, own process group;
//! * rlimits and an optional confinement hook run in the child before `execve`;
//! * bounded stdout/stderr with truncation flags;
//! * wall-clock deadline; when the main process exits *or* the deadline passes,
//!   the whole tree is killed: the process group, then every descendant that
//!   was reparented to us (the supervisor is a child subreaper). As PID 1 in a
//!   container it uses `kill(-1)`, which reaches every other process in the PID
//!   namespace. That path is never taken outside PID 1.
//!
//! The container/cgroup stop issued by the controller remains the final
//! cleanup boundary; this crate makes cleanup happen even before that.

mod sys;

use serde::Serialize;
use std::io::{self, Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub use sys::set_child_subreaper;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Rlimits {
    pub cpu_seconds: u64,
    pub address_space_bytes: u64,
    pub file_size_bytes: u64,
    pub open_files: u64,
    pub processes: u64,
}

/// Hook run in the forked child after rlimits and before `execve`.
/// It must only perform operations that are safe after `fork` in a
/// single-threaded parent. Returning an error aborts the spawn (fail closed).
pub type PreExecHook = Box<dyn Fn() -> io::Result<()> + Send + Sync>;

pub struct RunSpec {
    pub argv: Vec<String>,
    pub cwd: String,
    pub env: Vec<(String, String)>,
    pub stdin: Option<Vec<u8>>,
    pub timeout: Duration,
    pub rlimits: Option<Rlimits>,
    pub output_cap: usize,
    pub pre_exec: Option<PreExecHook>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Termination {
    Exited,
    Signaled,
    TimedOut,
}

/// One process observed in the action's tree (sampled; short-lived
/// processes can be missed; observation only, never enforcement).
#[derive(Debug, Clone, Serialize)]
pub struct ObservedProcess {
    pub pid: i32,
    pub ppid: i32,
    pub comm: String,
    pub first_seen_ms: u64,
}

pub const MAX_OBSERVED: usize = 512;
const SAMPLE_EVERY: Duration = Duration::from_millis(20);

#[derive(Debug, Clone, Serialize)]
pub struct RunOutcome {
    pub termination: Termination,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub duration_ms: u64,
    pub pid: u32,
    pub descendants_killed: u32,
    pub peak_memory_bytes: u64,
    pub cpu_seconds: f64,
    /// Limit inferred from the terminating signal, if any.
    pub limit_hit: Option<&'static str>,
    pub process_tree: Vec<ObservedProcess>,
    pub process_tree_truncated: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum SpawnError {
    #[error("argv must not be empty")]
    EmptyArgv,
    #[error("spawn failed: {0}")]
    Spawn(io::Error),
}

fn read_bounded<R: Read + Send + 'static>(mut r: R, cap: usize) -> mpsc::Receiver<(Vec<u8>, bool)> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept = Vec::new();
        let mut truncated = false;
        let mut buf = [0u8; 8192];
        loop {
            match r.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let room = cap.saturating_sub(kept.len());
                    if n > room {
                        truncated = true;
                    }
                    kept.extend_from_slice(&buf[..n.min(room)]);
                    // Keep draining past the cap so the child never blocks on a full pipe.
                }
            }
        }
        let _ = tx.send((kept, truncated));
    });
    rx
}

/// Direct children of this process according to /proc (for subreaper cleanup).
fn direct_children() -> Vec<i32> {
    let me = sys::getpid();
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for e in dir.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else {
            continue;
        };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            continue;
        };
        // Field 4 (ppid) follows the ")" that closes the command name.
        let Some(rest) = stat.rfind(')').map(|i| &stat[i + 2..]) else {
            continue;
        };
        let mut it = rest.split_whitespace();
        let _state = it.next();
        if it.next().and_then(|p| p.parse::<i32>().ok()) == Some(me) {
            out.push(pid);
        }
    }
    out
}

/// (pid, ppid, comm) for every process visible in /proc.
fn proc_table() -> Vec<(i32, i32, String)> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/proc") else { return out };
    for e in dir.flatten() {
        let Ok(pid) = e.file_name().to_string_lossy().parse::<i32>() else { continue };
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else { continue };
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else { continue };
        let comm = stat[open + 1..close].to_string();
        let mut it = stat[close + 2..].split_whitespace();
        let _state = it.next();
        if let Some(ppid) = it.next().and_then(|p| p.parse().ok()) {
            out.push((pid, ppid, comm));
        }
    }
    out
}

/// Record descendants of `root` not seen before.
fn sample_tree(root: i32, start: Instant, seen: &mut Vec<ObservedProcess>, truncated: &mut bool) {
    let table = proc_table();
    let mut members: std::collections::BTreeSet<i32> = seen.iter().map(|p| p.pid).collect();
    members.insert(root);
    // Fixed-point expansion over ppid links (reparented orphans point at us,
    // the subreaper, so also accept children of the supervisor itself).
    let me = sys::getpid();
    loop {
        let before = members.len();
        for (pid, ppid, _) in &table {
            if (members.contains(ppid) || *ppid == me) && *pid != me {
                members.insert(*pid);
            }
        }
        if members.len() == before {
            break;
        }
    }
    for (pid, ppid, comm) in table {
        if members.contains(&pid) && !seen.iter().any(|p| p.pid == pid) {
            if seen.len() >= MAX_OBSERVED {
                *truncated = true;
                return;
            }
            seen.push(ObservedProcess {
                pid,
                ppid,
                comm,
                first_seen_ms: start.elapsed().as_millis() as u64,
            });
        }
    }
}

/// Kill and reap every remaining descendant. Returns how many were killed.
fn kill_tree(pgid: i32) -> u32 {
    let _ = sys::kill(-pgid, libc::SIGKILL);
    let pid1 = sys::getpid() == 1;
    let mut killed = 0u32;
    for _round in 0..10_000 {
        if pid1 {
            let _ = sys::kill(-1, libc::SIGKILL);
        }
        let kids = direct_children();
        for k in &kids {
            if sys::kill(*k, libc::SIGKILL).is_ok() {
                killed += 1;
            }
        }
        let mut reaped_any = false;
        loop {
            match sys::reap_any() {
                sys::Reaped::Exited => reaped_any = true,
                sys::Reaped::None => break,
                sys::Reaped::NoChildren => {
                    if direct_children().is_empty() {
                        return killed;
                    }
                    break;
                }
            }
        }
        if !reaped_any && kids.is_empty() {
            std::thread::sleep(Duration::from_millis(2));
        }
    }
    killed
}

/// Run one command under supervision. Never leaves descendants behind.
///
/// Must not be called concurrently within one process: cleanup reaps *all*
/// children of the calling process. The worker runs exactly one action per
/// process lifetime.
pub fn run(spec: RunSpec) -> Result<RunOutcome, SpawnError> {
    if spec.argv.is_empty() {
        return Err(SpawnError::EmptyArgv);
    }
    let mut cmd = Command::new(&spec.argv[0]);
    cmd.args(&spec.argv[1..])
        .env_clear()
        .envs(spec.env.iter().map(|(k, v)| (k, v)))
        .current_dir(&spec.cwd)
        .process_group(0)
        .stdin(if spec.stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let limits = spec.rlimits;
    let hook = spec.pre_exec;
    #[allow(unsafe_code)]
    // SAFETY: the closure runs in the forked child before execve. It only calls
    // setrlimit and the confinement hook, whose contract (see `PreExecHook`)
    // requires fork-safety. The supervisor process is single-threaded when it
    // spawns (reader threads are created after spawn returns).
    unsafe {
        cmd.pre_exec(move || {
            if let Some(l) = limits {
                sys::setrlimit(libc::RLIMIT_CORE, 0, 0)?;
                // soft < hard so the kernel sends SIGXCPU (identifiable) first.
                sys::setrlimit(libc::RLIMIT_CPU, l.cpu_seconds, l.cpu_seconds + 1)?;
                sys::setrlimit(
                    libc::RLIMIT_AS,
                    l.address_space_bytes,
                    l.address_space_bytes,
                )?;
                sys::setrlimit(libc::RLIMIT_FSIZE, l.file_size_bytes, l.file_size_bytes)?;
                sys::setrlimit(libc::RLIMIT_NOFILE, l.open_files, l.open_files)?;
                // RLIMIT_NPROC counts every process of the real UID. It is
                // meaningful inside the worker (UID 10001 runs nothing else);
                // 0 means "leave unchanged" for host-side tests.
                if l.processes > 0 {
                    sys::setrlimit(libc::RLIMIT_NPROC, l.processes, l.processes)?;
                }
            }
            if let Some(h) = &hook {
                h()?;
            }
            Ok(())
        });
    }

    let start = Instant::now();
    let mut child = cmd.spawn().map_err(SpawnError::Spawn)?;
    let pid = child.id();
    let pgid = pid as i32;
    if let (Some(data), Some(mut sin)) = (spec.stdin, child.stdin.take()) {
        std::thread::spawn(move || {
            let _ = sin.write_all(&data);
        });
    }
    let out_rx = read_bounded(child.stdout.take().expect("piped"), spec.output_cap);
    let err_rx = read_bounded(child.stderr.take().expect("piped"), spec.output_cap);

    let deadline = start + spec.timeout;
    let mut timed_out = false;
    let mut tree = Vec::new();
    let mut tree_truncated = false;
    let mut next_sample = Instant::now();
    let status = loop {
        if Instant::now() >= next_sample {
            sample_tree(pgid, start, &mut tree, &mut tree_truncated);
            next_sample = Instant::now() + SAMPLE_EVERY;
        }
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(_) => break None,
        }
        if Instant::now() >= deadline {
            timed_out = true;
            let _ = sys::kill(-pgid, libc::SIGKILL);
            break child.wait().ok();
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    // Last look before cleanup, then: nothing the action started may outlive it.
    sample_tree(pgid, start, &mut tree, &mut tree_truncated);
    let descendants_killed = kill_tree(pgid);
    let duration_ms = start.elapsed().as_millis() as u64;

    let collect = |rx: mpsc::Receiver<(Vec<u8>, bool)>| {
        rx.recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| (Vec::new(), true))
    };
    let (stdout, stdout_truncated) = collect(out_rx);
    let (stderr, stderr_truncated) = collect(err_rx);
    let usage = sys::children_usage();

    let exit_code = status.and_then(|s| s.code());
    let signal = status.and_then(|s| s.signal());
    let limit_hit = if timed_out {
        Some("wall_time_seconds")
    } else {
        match signal {
            Some(libc::SIGXCPU) => Some("cpu_seconds"),
            Some(libc::SIGXFSZ) => Some("file_size_bytes"),
            _ => None,
        }
    };
    Ok(RunOutcome {
        termination: if timed_out {
            Termination::TimedOut
        } else if signal.is_some() {
            Termination::Signaled
        } else {
            Termination::Exited
        },
        exit_code,
        signal,
        stdout,
        stderr,
        stdout_truncated,
        stderr_truncated,
        duration_ms,
        pid,
        descendants_killed,
        peak_memory_bytes: usage.max_rss_bytes,
        cpu_seconds: usage.cpu_seconds,
        limit_hit,
        process_tree: tree,
        process_tree_truncated: tree_truncated,
    })
}
