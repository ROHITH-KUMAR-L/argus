//! ratchetd over real Unix sockets: RAT-017/018/019/023 and protocol hardening.

use protocol::{read_frame, write_frame};
use serde_json::{json, Value};
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn rid() -> String {
    format!(
        "req-{:08}-{}",
        COUNTER.fetch_add(1, Ordering::SeqCst),
        std::process::id()
    )
}

fn template(task: &str) -> Value {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/templates/python-task.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["task_id"] = json!(task);
    v
}

struct Daemon {
    child: Child,
    run: PathBuf,
    state: PathBuf,
    _tmp: tempfile::TempDir,
}

impl Daemon {
    fn start_in(tmp: tempfile::TempDir, extra: &[&str]) -> Result<Self, String> {
        let run = tmp.path().join("run");
        let state = tmp.path().join("state");
        let mut child = Command::new(env!("CARGO_BIN_EXE_ratchetd"))
            .args([
                "--runtime-dir",
                run.to_str().unwrap(),
                "--state-dir",
                state.to_str().unwrap(),
            ])
            .args(extra)
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let ready = run.join("ratchetd.ready");
        let t0 = Instant::now();
        while !ready.exists() {
            if let Some(status) = child.try_wait().unwrap() {
                let mut err = String::new();
                use std::io::Read;
                child
                    .stderr
                    .take()
                    .unwrap()
                    .read_to_string(&mut err)
                    .unwrap();
                return Err(format!("exited {status}: {err}"));
            }
            assert!(
                t0.elapsed() < Duration::from_secs(10),
                "daemon did not become ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        Ok(Daemon {
            child,
            run,
            state,
            _tmp: tmp,
        })
    }
    fn start(extra: &[&str]) -> Self {
        Self::start_in(tempfile::tempdir().unwrap(), extra).unwrap()
    }
    fn stop(mut self) -> tempfile::TempDir {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        let _ = std::fs::remove_file(self.run.join("ratchetd.ready"));
        std::mem::replace(&mut self._tmp, tempfile::tempdir().unwrap())
    }
    fn conn(&self, sock: &str) -> UnixStream {
        UnixStream::connect(self.run.join(sock)).unwrap()
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn call_raw(s: &mut UnixStream, req: &Value) -> Value {
    write_frame(s, &serde_json::to_vec(req).unwrap()).unwrap();
    serde_json::from_slice(&read_frame(s).unwrap().unwrap()).unwrap()
}

fn call(s: &mut UnixStream, method: &str, params: Value) -> Value {
    call_raw(
        s,
        &json!({"protocol_version":"1","request_id":rid(),"method":method,"params":params}),
    )
}

fn ok(v: Value) -> Value {
    assert_eq!(v["ok"], true, "{v}");
    v["result"].clone()
}

fn err_code(v: &Value) -> String {
    assert_eq!(v["ok"], false, "{v}");
    v["error"]["code"].as_str().unwrap().to_string()
}

struct Task {
    id: String,
    epoch_id: String,
    hash: String,
}

fn open(s: &mut UnixStream, task: &str) -> Task {
    let r = ok(call(
        s,
        "open_task",
        json!({"task_id": task, "policy_json": template(task).to_string()}),
    ));
    Task {
        id: task.into(),
        epoch_id: r["epoch_id"].as_str().unwrap().into(),
        hash: r["policy_hash"].as_str().unwrap().into(),
    }
}

fn narrow(s: &mut UnixStream, t: &Task, cpu: u64) -> Value {
    let mut p = template(&t.id);
    p["limits"]["cpu_seconds"] = json!(cpu);
    call(
        s,
        "apply_narrowing",
        json!({"task_id": t.id, "epoch_id": t.epoch_id, "expected_policy_hash": t.hash, "proposed_policy_json": p.to_string(), "reason": "test"}),
    )
}

#[test]
fn health_and_permissions() {
    let d = Daemon::start(&["--landlock-abi", "6"]);
    let mut s = d.conn("ratchetd.sock");
    let h = ok(call(&mut s, "health", Value::Null));
    assert_eq!(h["arm"], "P1");
    assert_eq!(h["landlock_abi"], 6);
    for f in ["ratchetd.sock", "ratchetd-approve.sock"] {
        let mode = std::fs::metadata(d.run.join(f))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "{f}");
    }
    assert_eq!(
        std::fs::metadata(&d.run).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let log = std::fs::metadata(d.state.join("ratchet.log")).unwrap();
    assert_eq!(log.permissions().mode() & 0o777, 0o600);
}

#[test]
fn protocol_hardening() {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    // Unknown envelope field.
    let r = call_raw(
        &mut s,
        &json!({"protocol_version":"1","request_id":rid(),"method":"health","params":{},"admin":true}),
    );
    assert_eq!(err_code(&r), "MALFORMED_REQUEST");
    // Wrong version.
    let r = call_raw(
        &mut s,
        &json!({"protocol_version":"2","request_id":rid(),"method":"health"}),
    );
    assert_eq!(err_code(&r), "UNSUPPORTED_PROTOCOL_VERSION");
    // Replay.
    let id = rid();
    let req = json!({"protocol_version":"1","request_id":id,"method":"health"});
    ok(call_raw(&mut s, &req));
    assert_eq!(err_code(&call_raw(&mut s, &req)), "REPLAYED_REQUEST");
    // Unknown method, unknown params.
    assert_eq!(
        err_code(&call(&mut s, "grant_all", json!({}))),
        "UNKNOWN_METHOD"
    );
    assert_eq!(
        err_code(&call(&mut s, "get_state", json!({"task_id":"x","sudo":1}))),
        "MALFORMED_REQUEST"
    );
    // Malformed action.
    let t = open(&mut s, "proto");
    let r = call(
        &mut s,
        "evaluate_action",
        json!({"task_id":t.id,"epoch_id":t.epoch_id,"policy_hash":t.hash,"run_id":"r1","action_id":"a1","action":{"type":"shell","cmd":"id"}}),
    );
    assert_eq!(err_code(&r), "MALFORMED_REQUEST");
    // Oversized frame closes the connection with an error.
    let mut big = d.conn("ratchetd.sock");
    big.write_all(&(2u32 * 1024 * 1024).to_be_bytes()).unwrap();
    let r: Value = serde_json::from_slice(&read_frame(&mut big).unwrap().unwrap()).unwrap();
    assert_eq!(err_code(&r), "FRAME_TOO_LARGE");
}

#[test]
fn evaluate_allow_and_stale() {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    let t = open(&mut s, "eval");
    let r = ok(call(
        &mut s,
        "evaluate_action",
        json!({"task_id":t.id,"epoch_id":t.epoch_id,"policy_hash":t.hash,"run_id":"run-1","action_id":"a-1","action":{"type":"run_tests","target":"python-pytest"}}),
    ));
    assert_eq!(r["decision"], "ALLOW");
    assert_eq!(r["dispatch"]["policy_hash"], t.hash);
    assert_eq!(r["dispatch"]["confinement"], "kernel");
    ok(narrow(&mut s, &t, 10));
    // STK-010: a plan made against the old hash is refused at dispatch time.
    let r = call(
        &mut s,
        "evaluate_action",
        json!({"task_id":t.id,"epoch_id":t.epoch_id,"policy_hash":t.hash,"run_id":"run-1","action_id":"a-2","action":{"type":"list_files"}}),
    );
    assert_eq!(err_code(&r), "STALE_POLICY_HASH");
}

#[test]
fn rat_023_approval_only_on_approval_socket() {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    let t = open(&mut s, "appr");
    let mut p = template("appr");
    p["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);
    let x = ok(call(
        &mut s,
        "request_expansion",
        json!({"task_id":t.id,"epoch_id":t.epoch_id,"policy_hash":t.hash,"proposed_policy_json":p.to_string(),"reason":"compile C"}),
    ));
    let xid = x["expansion_id"].as_str().unwrap();
    // The decision socket (the one the agent graph uses) cannot approve.
    let r = call(
        &mut s,
        "approve_expansion",
        json!({"task_id":t.id,"expansion_id":xid,"approver":"model","decision":"approve"}),
    );
    assert_eq!(err_code(&r), "METHOD_NOT_PERMITTED_ON_SOCKET");
    // The approval socket cannot evaluate or mutate policy.
    let mut a = d.conn("ratchetd-approve.sock");
    assert_eq!(
        err_code(&narrow(&mut a, &t, 5)),
        "METHOD_NOT_PERMITTED_ON_SOCKET"
    );
    let r = ok(call(
        &mut a,
        "approve_expansion",
        json!({"task_id":t.id,"expansion_id":xid,"approver":"alice","decision":"approve"}),
    ));
    assert_eq!(r["epoch"], 2);
    // RAT-022 over the wire: replaying the approval fails.
    let r = call(
        &mut a,
        "approve_expansion",
        json!({"task_id":t.id,"expansion_id":xid,"approver":"alice","decision":"approve"}),
    );
    assert_eq!(err_code(&r), "UNKNOWN_EXPANSION");
}

#[test]
fn rat_017_concurrent_transitions_serialize() {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    let t = open(&mut s, "race");
    let (tid, eid, h) = (t.id.clone(), t.epoch_id.clone(), t.hash.clone());
    let handles: Vec<_> = (0..8)
        .map(|i| {
            let mut c = d.conn("ratchetd.sock");
            let t = Task {
                id: tid.clone(),
                epoch_id: eid.clone(),
                hash: h.clone(),
            };
            std::thread::spawn(move || narrow(&mut c, &t, 40 - i))
        })
        .collect();
    let results: Vec<Value> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    let accepted = results.iter().filter(|r| r["ok"] == true).count();
    let stale = results
        .iter()
        .filter(|r| r["ok"] == false && r["error"]["code"] == "STALE_POLICY_HASH")
        .count();
    assert_eq!(accepted, 1, "{results:?}");
    assert_eq!(stale, 7);
}

#[test]
fn rat_018_restart_restores_committed_state() {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    let t = open(&mut s, "persist");
    let narrowed = ok(narrow(&mut s, &t, 7))["policy_hash"]
        .as_str()
        .unwrap()
        .to_string();
    let before = ok(call(&mut s, "get_state", json!({"task_id":"persist"})));
    drop(s);
    let tmp = d.stop();
    let d2 = Daemon::start_in(tmp, &[]).unwrap();
    let mut s = d2.conn("ratchetd.sock");
    let after = ok(call(&mut s, "get_state", json!({"task_id":"persist"})));
    assert_eq!(after, before);
    assert_eq!(after["policy_hash"], narrowed);
    // The original (broader) P0 hash cannot be used after restart.
    let r = call(
        &mut s,
        "evaluate_action",
        json!({"task_id":"persist","epoch_id":t.epoch_id,"policy_hash":t.hash,"run_id":"r","action_id":"a","action":{"type":"list_files"}}),
    );
    assert_eq!(err_code(&r), "STALE_POLICY_HASH");
}

fn restart_fails(tmp: tempfile::TempDir, extra: &[&str]) -> String {
    match Daemon::start_in(tmp, extra) {
        Ok(_) => panic!("daemon started on bad state"),
        Err(e) => e,
    }
}

fn with_log(mutate: impl FnOnce(&Path)) -> String {
    let d = Daemon::start(&[]);
    let mut s = d.conn("ratchetd.sock");
    let t = open(&mut s, "corrupt");
    ok(narrow(&mut s, &t, 5));
    drop(s);
    let tmp = d.stop();
    mutate(&tmp.path().join("state/ratchet.log"));
    restart_fails(tmp, &[])
}

#[test]
fn rat_019_corruption_fails_closed() {
    // Truncated final record.
    let e = with_log(|p| {
        let raw = std::fs::read(p).unwrap();
        std::fs::write(p, &raw[..raw.len() - 20]).unwrap();
    });
    assert!(e.contains("refusing to start"), "{e}");
    // Tampered op (e.g. raising a limit back) breaks the hash chain.
    let e = with_log(|p| {
        let s = std::fs::read_to_string(p)
            .unwrap()
            .replace("\\\"cpu_seconds\\\":5", "\\\"cpu_seconds\\\":45");
        std::fs::write(p, s).unwrap();
    });
    assert!(e.contains("hash mismatch"), "{e}");
    // Dropped record.
    let e = with_log(|p| {
        let s = std::fs::read_to_string(p).unwrap();
        let lines: Vec<&str> = s.lines().collect();
        std::fs::write(p, format!("{}\n{}\n", lines[0], lines[2])).unwrap();
    });
    assert!(e.contains("expected seq"), "{e}");
    // Emptied log.
    let e = with_log(|p| std::fs::write(p, "").unwrap());
    assert!(e.contains("refusing to start"), "{e}");
    // World-readable log.
    let e =
        with_log(|p| std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o644)).unwrap());
    assert!(e.contains("group/other"), "{e}");
}

#[test]
fn config_mismatch_refuses() {
    let d = Daemon::start(&[]);
    let tmp = d.stop();
    let e = restart_fails(tmp, &["--arm", "B1"]);
    assert!(e.contains("different configuration"), "{e}");
}

#[test]
fn second_daemon_on_same_state_refused() {
    let d = Daemon::start(&[]);
    let out = Command::new(env!("CARGO_BIN_EXE_ratchetd"))
        .args([
            "--runtime-dir",
            d.run.join("x").to_str().unwrap(),
            "--state-dir",
            d.state.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("another ratchetd"));
}
