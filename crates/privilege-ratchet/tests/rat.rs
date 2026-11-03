//! RAT-001 … RAT-024 at the engine level (socket/persistence cases live in ratchetd tests).

use policy_model::Action;
use policy_validator::DeploymentConfig;
use privilege_ratchet::{Arm, Engine, Op, RatchetError};
use serde_json::{json, Value};
use std::path::PathBuf;

const T: &str = "task-rat";

fn template() -> Value {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/templates/python-task.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["task_id"] = json!(T);
    v
}

fn net_deployment() -> DeploymentConfig {
    let mut d = DeploymentConfig::builtin();
    d.allow_network = true;
    d
}

struct H {
    e: Engine,
    epoch_id: String,
    hash: String,
    now: u64,
}

impl H {
    fn new(arm: Arm, d: DeploymentConfig, p0: &Value) -> Self {
        let mut e = Engine::new(arm, d, Some(10));
        let out = e
            .apply(
                &Op::OpenTask {
                    task_id: T.into(),
                    policy: p0.to_string(),
                },
                1,
            )
            .unwrap();
        H {
            e,
            epoch_id: out["epoch_id"].as_str().unwrap().into(),
            hash: out["policy_hash"].as_str().unwrap().into(),
            now: 1,
        }
    }
    fn p1(p0: &Value) -> Self {
        Self::new(Arm::P1, DeploymentConfig::builtin(), p0)
    }
    fn tick(&mut self) -> u64 {
        self.now += 1;
        self.now
    }
    fn narrow(&mut self, proposed: &Value) -> Result<Value, RatchetError> {
        let now = self.tick();
        let r = self.e.apply(
            &Op::ApplyNarrowing {
                task_id: T.into(),
                epoch_id: self.epoch_id.clone(),
                expected_policy_hash: self.hash.clone(),
                proposed_policy: proposed.to_string(),
                reason: "test".into(),
            },
            now,
        );
        if let Ok(v) = &r {
            self.hash = v["policy_hash"].as_str().unwrap().into();
        }
        r
    }
    fn request(&mut self, proposed: &Value) -> Result<Value, RatchetError> {
        let now = self.tick();
        self.e.apply(
            &Op::RequestExpansion {
                task_id: T.into(),
                epoch_id: self.epoch_id.clone(),
                policy_hash: self.hash.clone(),
                proposed_policy: proposed.to_string(),
                reason: "need it".into(),
            },
            now,
        )
    }
    fn decide(&mut self, xid: &str, approve: bool, at: u64) -> Result<Value, RatchetError> {
        let r = self.e.apply(
            &Op::DecideExpansion {
                task_id: T.into(),
                expansion_id: xid.into(),
                approver: "alice".into(),
                approve,
            },
            at,
        );
        if let Ok(v) = &r {
            if v["status"] == "APPROVED" {
                self.epoch_id = v["epoch_id"].as_str().unwrap().into();
                self.hash = v["policy_hash"].as_str().unwrap().into();
            }
        }
        r
    }
    fn eval(&self, action: Value) -> Result<privilege_ratchet::Decision, RatchetError> {
        let a: Action = serde_json::from_value(action).unwrap();
        self.e
            .evaluate_action(T, &self.epoch_id, &self.hash, "run-1", "act-1", &a)
    }
    fn decision(&self, action: Value) -> (String, String) {
        let d = self.eval(action).unwrap();
        (d.decision.to_string(), d.reason_code.to_string())
    }
    fn last_kind(&self) -> &'static str {
        self.e.task(T).unwrap().transitions.last().unwrap().kind
    }
}

fn expansion(r: Result<Value, RatchetError>) -> Vec<privilege_ratchet::DeltaItem> {
    match r {
        Err(RatchetError::ExpansionDenied(d)) => d,
        other => panic!("expected expansion denial, got {other:?}"),
    }
}

#[test]
fn rat_001_noop() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let before = h.hash.clone();
    let r = h.narrow(&p0).unwrap();
    assert_eq!(r["changed"], false);
    assert_eq!(h.hash, before);
    assert_eq!(h.last_kind(), "POLICY_UNCHANGED");
}

#[test]
fn rat_002_remove_read_path() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let mut p = p0.clone();
    p["filesystem"]["read_only"] = json!(["/usr", "/etc/ld.so.cache", "/dev/null"]);
    assert_eq!(h.narrow(&p).unwrap()["changed"], true);
    let perms = &h.e.task(T).unwrap().current.permissions;
    assert_eq!(privilege_ratchet::coverage(&perms.fs, "/dev/urandom").0, 0);
}

#[test]
fn rat_003_read_write_to_read_only() {
    let p0 = template();
    let mut h = H::p1(&p0);
    assert_eq!(
        h.decision(json!({"type":"write_file","path":"a.py","content":"x"}))
            .0,
        "ALLOW"
    );
    let mut p = p0.clone();
    p["filesystem"]["read_only"] = json!([
        "/usr",
        "/etc/ld.so.cache",
        "/dev/null",
        "/dev/urandom",
        "/workspace/task"
    ]);
    p["filesystem"]["read_write"] = json!(["/tmp"]);
    h.narrow(&p).unwrap();
    assert_eq!(
        h.decision(json!({"type":"write_file","path":"a.py","content":"x"})),
        ("DENY".into(), "PATH_NOT_PERMITTED".into())
    );
    assert_eq!(
        h.decision(json!({"type":"read_file","path":"a.py"})).0,
        "ALLOW"
    );
}

#[test]
fn rat_004_remove_executable() {
    let mut p0 = template();
    p0["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/true"]);
    let mut h = H::p1(&p0);
    let run = json!({"type":"run_command","executable":"/usr/bin/true","argv":["/usr/bin/true"]});
    assert_eq!(h.decision(run.clone()).0, "ALLOW");
    let mut p = p0.clone();
    p["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3"]);
    h.narrow(&p).unwrap();
    assert_eq!(
        h.decision(run),
        ("DENY".into(), "EXECUTABLE_NOT_PERMITTED".into())
    );
}

#[test]
fn rat_005_disable_network() {
    let mut p0 = template();
    p0["network"] = json!({"mode":"tcp_ports","allowed_tcp_ports":[8080, 8443]});
    let mut h = H::new(Arm::P1, net_deployment(), &p0);
    let mut fewer = p0.clone();
    fewer["network"]["allowed_tcp_ports"] = json!([8080]);
    assert_eq!(h.narrow(&fewer).unwrap()["changed"], true);
    let mut none = p0.clone();
    none["network"] = json!({"mode":"none"});
    assert_eq!(h.narrow(&none).unwrap()["changed"], true);
    assert!(h.e.task(T).unwrap().current.permissions.tcp_ports.is_none());
}

#[test]
fn rat_006_reduce_limits() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let mut p = p0.clone();
    p["limits"]["wall_time_seconds"] = json!(10);
    p["limits"]["memory_bytes"] = json!(268435456);
    p["limits"]["process_count"] = json!(8);
    h.narrow(&p).unwrap();
    let run = json!({"type":"run_command","executable":"/usr/local/bin/python3","argv":["/usr/local/bin/python3","-V"],"timeout_seconds":30});
    assert_eq!(
        h.decision(run),
        ("DENY".into(), "TIMEOUT_EXCEEDS_LIMIT".into())
    );
}

#[test]
fn rat_007_add_syscall_denial() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let mut p = p0.clone();
    p["syscalls"]["deny_high_risk"] = json!(["kill"]);
    assert_eq!(h.narrow(&p).unwrap()["changed"], true);
    p["syscalls"]["profile"] = json!("minimal-run-v1");
    assert_eq!(h.narrow(&p).unwrap()["changed"], true);
}

#[test]
fn rat_008_add_new_path_rejected() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let before = h.hash.clone();
    let mut p = p0.clone();
    p["filesystem"]["read_only"]
        .as_array_mut()
        .unwrap()
        .push(json!("/opt"));
    let d = expansion(h.narrow(&p));
    assert_eq!(d.len(), 1);
    assert_eq!(h.e.task(T).unwrap().current.policy_hash, before);
    assert_eq!(h.last_kind(), "PRIVILEGE_EXPANSION_DENIED");
    assert!(!h
        .e
        .task(T)
        .unwrap()
        .transitions
        .last()
        .unwrap()
        .delta
        .is_empty());
}

#[test]
fn rat_009_expand_to_parent_rejected() {
    let mut p0 = template();
    p0["filesystem"]["read_only"] = json!(["/usr/lib", "/usr/local", "/etc/ld.so.cache"]);
    let mut h = H::p1(&p0);
    let mut p = p0.clone();
    p["filesystem"]["read_only"] = json!(["/usr", "/etc/ld.so.cache"]);
    expansion(h.narrow(&p));
}

#[test]
fn rat_010_to_013_expansions_rejected() {
    let mut p0 = template();
    p0["syscalls"]["profile"] = json!("minimal-run-v1");
    let mut h = H::new(Arm::P1, net_deployment(), &p0);

    let mut exe = p0.clone();
    exe["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);
    expansion(h.narrow(&exe)); // RAT-010

    let mut net = p0.clone();
    net["network"] = json!({"mode":"tcp_ports","allowed_tcp_ports":[443]});
    expansion(h.narrow(&net)); // RAT-011

    for (k, v) in [
        ("memory_bytes", 1u64 << 30),
        ("cpu_seconds", 46),
        ("process_count", 33),
        ("file_size_bytes", 52428801),
        ("wall_time_seconds", 61),
        ("open_files", 129),
    ] {
        let mut lim = p0.clone();
        lim["limits"][k] = json!(v);
        expansion(h.narrow(&lim)); // RAT-012
    }

    let mut weaker = p0.clone();
    weaker["syscalls"]["profile"] = json!("python-build-v1");
    let d = expansion(h.narrow(&weaker)); // RAT-013
    assert!(d
        .iter()
        .all(|x| matches!(x, privilege_ratchet::DeltaItem::SyscallUndenied { .. })));

    let mut tool = p0.clone();
    tool["commands"]["shell"] = json!("allow");
    tool["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/sh"]);
    expansion(h.narrow(&tool));
}

#[test]
fn rat_014_mixed_transition_rejected_entirely() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let before = h.e.task(T).unwrap().current.clone();
    let mut p = p0.clone();
    p["filesystem"]["read_only"] = json!(["/usr", "/etc/ld.so.cache", "/dev/null", "/opt"]); // -urandom +opt
    p["limits"]["memory_bytes"] = json!(1024); // narrowing too
    let d = expansion(h.narrow(&p));
    assert_eq!(d.len(), 1);
    assert_eq!(h.e.task(T).unwrap().current, before);
}

#[test]
fn rat_015_malformed_transitions() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let now = h.tick();
    let wrong_epoch = h.e.apply(
        &Op::ApplyNarrowing {
            task_id: T.into(),
            epoch_id: format!("{T}:e9"),
            expected_policy_hash: h.hash.clone(),
            proposed_policy: p0.to_string(),
            reason: "x".into(),
        },
        now,
    );
    assert_eq!(wrong_epoch, Err(RatchetError::StaleEpoch));
    assert_eq!(h.last_kind(), "TRANSITION_REJECTED");
    let unknown = h.e.apply(
        &Op::CloseEpoch {
            task_id: "nope".into(),
            epoch_id: "nope:e1".into(),
            reason: "x".into(),
        },
        now,
    );
    assert_eq!(unknown, Err(RatchetError::UnknownTask));
    let mut other = p0.clone();
    other["task_id"] = json!("someone-else");
    assert!(matches!(
        h.narrow(&other),
        Err(RatchetError::TaskMismatch(_))
    ));
    assert!(matches!(
        h.narrow(&json!({"schema_version":"1.0"})),
        Err(RatchetError::PolicyInvalid(_))
    ));
}

#[test]
fn rat_016_stale_policy_hash() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let original = h.hash.clone();
    let mut p = p0.clone();
    p["limits"]["cpu_seconds"] = json!(30);
    h.narrow(&p).unwrap();
    h.hash = original; // a second writer based on the old version
    let mut q = p0.clone();
    q["limits"]["memory_bytes"] = json!(1024);
    assert_eq!(h.narrow(&q), Err(RatchetError::StalePolicyHash));
    // The stale writer's view also cannot evaluate actions.
    assert_eq!(
        h.eval(json!({"type":"list_files"})).unwrap_err(),
        RatchetError::StalePolicyHash
    );
}

#[test]
fn rat_020_approval_denied() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let before = h.hash.clone();
    let mut p = p0.clone();
    p["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);
    let xid = h.request(&p).unwrap()["expansion_id"]
        .as_str()
        .unwrap()
        .to_string();
    let r = h.decide(&xid, false, h.now + 1).unwrap();
    assert_eq!(r["status"], "DENIED");
    assert_eq!(h.e.task(T).unwrap().current.policy_hash, before);
    assert_eq!(h.e.task(T).unwrap().epoch, 1);
}

#[test]
fn rat_021_approval_granted_new_epoch() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let old_epoch = h.epoch_id.clone();
    let old_hash = h.hash.clone();
    let mut p = p0.clone();
    p["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);
    let req = h.request(&p).unwrap();
    assert_eq!(req["status"], "APPROVAL_PENDING");
    assert!(!req["delta"].as_array().unwrap().is_empty());
    // Pending request grants nothing yet.
    let gcc = json!({"type":"run_command","executable":"/usr/bin/gcc","argv":["/usr/bin/gcc","--version"]});
    assert_eq!(h.decision(gcc.clone()).1, "EXECUTABLE_NOT_PERMITTED");
    let xid = req["expansion_id"].as_str().unwrap().to_string();
    let r = h.decide(&xid, true, h.now + 1).unwrap();
    assert_eq!(r["status"], "APPROVED");
    assert_eq!(r["epoch"], 2);
    assert_ne!(h.epoch_id, old_epoch);
    assert_eq!(h.decision(gcc).0, "ALLOW");
    let t = h.e.task(T).unwrap();
    let last = t.transitions.last().unwrap();
    assert_eq!(last.kind, "EXPANSION_APPROVED_NEW_EPOCH");
    assert_eq!(last.approver.as_deref(), Some("alice"));
    assert_eq!(last.from_hash, old_hash);
    assert!(t
        .transitions
        .iter()
        .any(|x| x.kind == "EPOCH_CLOSED" && x.epoch == 1));
    // The old epoch can no longer be used.
    let a: Action = serde_json::from_value(json!({"type":"list_files"})).unwrap();
    assert_eq!(
        h.e.evaluate_action(T, &old_epoch, &old_hash, "run-1", "act-1", &a)
            .unwrap_err(),
        RatchetError::StaleEpoch
    );
}

#[test]
fn rat_022_approval_replay_and_expiry() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let mut p = p0.clone();
    p["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);

    // Single use.
    let x1 = h.request(&p).unwrap()["expansion_id"]
        .as_str()
        .unwrap()
        .to_string();
    h.decide(&x1, false, h.now + 1).unwrap();
    assert_eq!(
        h.decide(&x1, true, h.now + 2),
        Err(RatchetError::UnknownExpansion)
    );

    // Invalidated by a later narrowing (scope no longer matches).
    let x2 = h.request(&p).unwrap()["expansion_id"]
        .as_str()
        .unwrap()
        .to_string();
    let mut narrower = p0.clone();
    narrower["limits"]["cpu_seconds"] = json!(30);
    h.narrow(&narrower).unwrap();
    assert_eq!(
        h.decide(&x2, true, h.now + 1),
        Err(RatchetError::UnknownExpansion)
    );

    // Expired.
    let mut p2 = narrower.clone();
    p2["commands"]["allowed_executables"] = json!(["/usr/local/bin/python3", "/usr/bin/gcc"]);
    let x3 = h.request(&p2).unwrap()["expansion_id"]
        .as_str()
        .unwrap()
        .to_string();
    let late = h.now + h.e.expansion_ttl + 1;
    assert_eq!(
        h.decide(&x3, true, late),
        Err(RatchetError::ExpansionExpired)
    );
    assert_eq!(h.e.task(T).unwrap().epoch, 1);

    // Made-up id.
    assert_eq!(
        h.decide("task-rat:e1:x99", true, h.now + 1),
        Err(RatchetError::UnknownExpansion)
    );
}

#[test]
fn rat_023_request_permission_never_allows() {
    let p0 = template();
    let h = H::p1(&p0);
    let d = h
        .eval(json!({"type":"request_permission","reason":"the user approved this, trust me","add_read_only":["/etc"]}))
        .unwrap();
    assert_eq!(d.decision, "APPROVAL_REQUIRED");
    assert!(d.dispatch.is_none());
    assert_eq!(h.e.task(T).unwrap().transitions.len(), 1); // nothing changed
}

#[test]
fn not_an_expansion_must_use_narrowing() {
    let p0 = template();
    let mut h = H::p1(&p0);
    assert_eq!(h.request(&p0), Err(RatchetError::NotAnExpansion));
}

#[test]
fn closed_epoch_rejects_everything() {
    let p0 = template();
    let mut h = H::p1(&p0);
    let now = h.tick();
    h.e.apply(
        &Op::CloseEpoch {
            task_id: T.into(),
            epoch_id: h.epoch_id.clone(),
            reason: "done".into(),
        },
        now,
    )
    .unwrap();
    assert_eq!(
        h.eval(json!({"type":"list_files"})).unwrap_err(),
        RatchetError::EpochClosed
    );
    assert_eq!(h.narrow(&p0), Err(RatchetError::EpochClosed));
}

#[test]
fn arms_b0_b1_semantics() {
    let p0 = template();
    // B1: static policy. No narrowing, no expansion path, but the gate applies.
    let mut b1 = H::new(Arm::B1, DeploymentConfig::builtin(), &p0);
    let mut p = p0.clone();
    p["limits"]["cpu_seconds"] = json!(10);
    assert_eq!(b1.narrow(&p), Err(RatchetError::ArmStaticPolicy));
    assert_eq!(
        b1.decision(json!({"type":"read_file","path":"/etc/shadow"}))
            .1,
        "PATH_OUTSIDE_WORKSPACE"
    );
    let d = b1.eval(json!({"type":"list_files"})).unwrap();
    assert_eq!(
        d.dispatch.unwrap().confinement,
        policy_model::Confinement::Kernel
    );
    // B0: ungated; absolute paths pass through to the (Docker-bounded) worker.
    let b0 = H::new(Arm::B0, DeploymentConfig::builtin(), &p0);
    let d = b0
        .eval(json!({"type":"read_file","path":"/etc/shadow"}))
        .unwrap();
    assert_eq!(d.decision, "ALLOW");
    assert_eq!(d.reason_code, "ARM_B0_UNGATED");
    assert_eq!(
        d.dispatch.unwrap().confinement,
        policy_model::Confinement::None
    );
}

#[test]
fn action_gate_basics() {
    let p0 = template();
    let h = H::p1(&p0);
    let cases = [
        (
            json!({"type":"read_file","path":"../secrets/key"}),
            "PATH_OUTSIDE_WORKSPACE",
        ),
        (
            json!({"type":"read_file","path":"/etc/passwd"}),
            "PATH_OUTSIDE_WORKSPACE",
        ),
        (
            json!({"type":"read_file","path":"a","length":0}),
            "READ_LENGTH_INVALID",
        ),
        (
            json!({"type":"run_tests","target":"rm-rf"}),
            "UNKNOWN_TEST_TARGET",
        ),
        (
            json!({"type":"run_tests","target":"make-test"}),
            "EXECUTABLE_NOT_PERMITTED",
        ),
        (
            json!({"type":"run_command","executable":"/usr/local/bin/python3","argv":["/usr/bin/sh","-c","id"]}),
            "ARGV_INVALID",
        ),
        (
            json!({"type":"run_command","executable":"/usr/bin/sh","argv":["/usr/bin/sh","-c","id"]}),
            "EXECUTABLE_NOT_PERMITTED",
        ),
        (
            json!({"type":"run_command","executable":"/usr/local/bin/python3","argv":["/usr/local/bin/python3"],"cwd":"../.."}),
            "PATH_OUTSIDE_WORKSPACE",
        ),
    ];
    for (a, want) in cases {
        assert_eq!(h.decision(a.clone()), ("DENY".into(), want.into()), "{a}");
    }
    let d = h
        .eval(json!({"type":"run_tests","target":"python-pytest"}))
        .unwrap();
    let w = d.dispatch.unwrap();
    assert_eq!(w.policy_hash, h.hash);
    match w.operation {
        policy_model::Operation::Exec { argv, cwd, .. } => {
            assert_eq!(argv[0], "/usr/local/bin/python3");
            assert_eq!(cwd, "/workspace/task");
        }
        other => panic!("{other:?}"),
    }
    // Argument metacharacters stay data inside argv (AGT-009).
    let d = h
        .eval(json!({"type":"run_command","executable":"/usr/local/bin/python3","argv":["/usr/local/bin/python3","-c","print(1); import os; os.system('id') ; $(whoami)"]}))
        .unwrap();
    assert_eq!(d.decision, "ALLOW");
}
