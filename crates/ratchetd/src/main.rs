//! ratchetd: the authoritative policy/ratchet daemon.
//!
//! ```text
//! ratchetd --runtime-dir DIR --state-dir DIR [--arm P1] [--deployment FILE]
//!          [--landlock-abi N] [--expansion-ttl SECS]
//! ```
//!
//! Serves `DIR/ratchetd.sock` (decisions) and `DIR/ratchetd-approve.sock`
//! (trusted approvals). See `docs/protocol.md`.

mod server;
mod store;
mod sys;

use policy_validator::{hash_canonical, DeploymentConfig};
use privilege_ratchet::{Arm, Engine};
use protocol::{read_frame, write_json, ErrorCode, FrameError, Response};
use server::{handle_frame, SocketKind, State};
use std::fs;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_CONNECTIONS: usize = 64;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

struct Args {
    runtime_dir: PathBuf,
    state_dir: PathBuf,
    arm: Arm,
    deployment: Option<PathBuf>,
    landlock_abi: Option<u32>,
    expansion_ttl: Option<u64>,
}

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("ratchetd: {msg}");
    std::process::exit(1);
}

fn parse_args() -> Args {
    let mut a = std::env::args().skip(1);
    let mut runtime_dir = None;
    let mut state_dir = None;
    let mut arm = Arm::P1;
    let mut deployment = None;
    let mut landlock_abi = None;
    let mut expansion_ttl = None;
    while let Some(k) = a.next() {
        let mut val = || {
            a.next()
                .unwrap_or_else(|| die(format!("{k} needs a value")))
        };
        match k.as_str() {
            "--runtime-dir" => runtime_dir = Some(PathBuf::from(val())),
            "--state-dir" => state_dir = Some(PathBuf::from(val())),
            "--arm" => arm = val().parse().unwrap_or_else(|e| die(e)),
            "--deployment" => deployment = Some(PathBuf::from(val())),
            "--landlock-abi" => landlock_abi = Some(val().parse().unwrap_or_else(|e| die(e))),
            "--expansion-ttl" => expansion_ttl = Some(val().parse().unwrap_or_else(|e| die(e))),
            other => die(format!("unknown argument {other}")),
        }
    }
    Args {
        runtime_dir: runtime_dir.unwrap_or_else(|| die("--runtime-dir is required")),
        state_dir: state_dir.unwrap_or_else(|| die("--state-dir is required")),
        arm,
        deployment,
        landlock_abi,
        expansion_ttl,
    }
}

/// Create `dir` as 0700, or verify an existing one is ours and 0700.
fn private_dir(dir: &Path) {
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .unwrap_or_else(|e| die(format!("cannot create {}: {e}", dir.display())));
    }
    let m = fs::symlink_metadata(dir).unwrap_or_else(|e| die(format!("{}: {e}", dir.display())));
    if !m.is_dir() || m.uid() != sys::geteuid() || m.permissions().mode() & 0o077 != 0 {
        die(format!(
            "{} must be a directory owned by uid {} with mode 0700",
            dir.display(),
            sys::geteuid()
        ));
    }
}

fn bind(path: &Path) -> UnixListener {
    if let Ok(m) = fs::symlink_metadata(path) {
        use std::os::unix::fs::FileTypeExt;
        if m.file_type().is_socket() {
            let _ = fs::remove_file(path);
        } else {
            die(format!("{} exists and is not a socket", path.display()));
        }
    }
    let l =
        UnixListener::bind(path).unwrap_or_else(|e| die(format!("bind {}: {e}", path.display())));
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .unwrap_or_else(|e| die(format!("chmod {}: {e}", path.display())));
    l
}

fn serve_conn(mut s: UnixStream, kind: SocketKind, state: Arc<Mutex<State>>) {
    match sys::peer_uid(&s) {
        Ok(uid) if uid == sys::geteuid() => {}
        _ => return, // wrong or unknown peer: drop silently
    }
    let _ = s.set_read_timeout(Some(IDLE_TIMEOUT));
    loop {
        let frame = match read_frame(&mut s) {
            Ok(Some(f)) => f,
            Ok(None) => return,
            Err(FrameError::TooLarge(n)) => {
                let _ = write_json(
                    &mut s,
                    &Response::err(
                        "",
                        ErrorCode::FrameTooLarge,
                        format!("frame of {n} bytes exceeds limit"),
                    ),
                );
                return;
            }
            Err(_) => return,
        };
        let resp = {
            let mut st = match state.lock() {
                Ok(g) => g,
                Err(_) => die("state mutex poisoned"),
            };
            handle_frame(&mut st, kind, &frame)
        };
        if write_json(&mut s, &resp).is_err() {
            return;
        }
    }
}

fn accept_loop(
    l: UnixListener,
    kind: SocketKind,
    state: Arc<Mutex<State>>,
    active: Arc<AtomicUsize>,
) {
    for conn in l.incoming() {
        let Ok(s) = conn else { continue };
        if active.load(Ordering::SeqCst) >= MAX_CONNECTIONS {
            continue; // dropping the stream closes it
        }
        active.fetch_add(1, Ordering::SeqCst);
        let (st, ac) = (state.clone(), active.clone());
        std::thread::spawn(move || {
            serve_conn(s, kind, st);
            ac.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

fn main() {
    sys::set_umask(0o077);
    let args = parse_args();

    let deployment_text = match &args.deployment {
        Some(p) => fs::read_to_string(p).unwrap_or_else(|e| die(format!("{}: {e}", p.display()))),
        None => policy_validator::deployment::DEFAULT_DEPLOYMENT_JSON.to_string(),
    };
    let deployment: DeploymentConfig = serde_json::from_str(&deployment_text)
        .unwrap_or_else(|e| die(format!("deployment config: {e}")));
    let deployment_hash = hash_canonical(
        &serde_json::to_string(&serde_json::to_value(&deployment).expect("serializes"))
            .expect("serializes"),
    );
    let abi = args.landlock_abi.unwrap_or_else(sys::landlock_abi);

    private_dir(&args.runtime_dir);
    private_dir(&args.state_dir);
    let lock = fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(args.state_dir.join("ratchetd.lock"))
        .unwrap_or_else(|e| die(format!("lock file: {e}")));
    sys::try_lock_exclusive(&lock)
        .unwrap_or_else(|_| die("another ratchetd owns this state directory"));

    let mut engine = Engine::new(args.arm, deployment, Some(abi));
    if let Some(ttl) = args.expansion_ttl {
        engine.expansion_ttl = ttl;
    }
    let header = store::Header {
        log_version: store::LOG_VERSION,
        arm: args.arm.as_str().into(),
        deployment_hash: deployment_hash.clone(),
    };
    let store = store::Store::open(&args.state_dir, &header, &mut engine)
        .unwrap_or_else(|e| die(format!("refusing to start: {e}")));
    eprintln!(
        "ratchetd: arm={} landlock_abi={abi} state={}",
        args.arm.as_str(),
        store.path().display()
    );

    let state = Arc::new(Mutex::new(State {
        engine,
        store,
        seen_request_ids: Default::default(),
        store_poisoned: false,
        deployment_hash,
    }));
    let decision = bind(&args.runtime_dir.join("ratchetd.sock"));
    let approval = bind(&args.runtime_dir.join("ratchetd-approve.sock"));
    let active = Arc::new(AtomicUsize::new(0));
    let (st2, ac2) = (state.clone(), active.clone());
    std::thread::spawn(move || accept_loop(approval, SocketKind::Approval, st2, ac2));
    // Readiness marker for supervisors/tests (written after both sockets exist).
    let _ = fs::write(
        args.runtime_dir.join("ratchetd.ready"),
        std::process::id().to_string(),
    );
    accept_loop(decision, SocketKind::Decision, state, active);
    let _ = lock; // held for the life of the process
}
