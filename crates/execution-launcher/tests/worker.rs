//! argus-worker end to end with dispatches produced by the real ratchet engine.

use policy_model::Action;
use policy_validator::DeploymentConfig;
use privilege_ratchet::{Arm, Engine, Op};
use serde_json::{json, Value};
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn template() -> Value {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/templates/python-task.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    v["task_id"] = json!("wtask");
    v
}

fn dispatch(arm: Arm, action: Value) -> Value {
    let mut e = Engine::new(arm, DeploymentConfig::builtin(), Some(10));
    let out = e
        .apply(
            &Op::OpenTask {
                task_id: "wtask".into(),
                policy: template().to_string(),
            },
            1,
        )
        .unwrap();
    let a: Action = serde_json::from_value(action).unwrap();
    let d = e
        .evaluate_action(
            "wtask",
            out["epoch_id"].as_str().unwrap(),
            out["policy_hash"].as_str().unwrap(),
            "run-1",
            "act-1",
            &a,
        )
        .unwrap();
    assert_eq!(d.decision, "ALLOW", "{d:?}");
    serde_json::to_value(d.dispatch.unwrap()).unwrap()
}

fn worker(req: &Value) -> Value {
    worker_raw(&serde_json::to_vec(req).unwrap())
}

fn worker_raw(bytes: &[u8]) -> Value {
    let mut child = Command::new(env!("CARGO_BIN_EXE_argus-worker"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child.stdin.take().unwrap().write_all(bytes); // the worker may stop reading early
    let out = child.wait_with_output().unwrap();
    serde_json::from_slice(&out.stdout)
        .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stdout)))
}

#[test]
fn b0_exec_and_result_fields() {
    let tmp = tempfile::tempdir().unwrap();
    let cwd = tmp.path().to_str().unwrap();
    let r = worker(&dispatch(
        Arm::B0,
        json!({"type":"run_command","executable":"/usr/bin/sh","argv":["/usr/bin/sh","-c","echo hi; echo err >&2; pwd"],"cwd":cwd}),
    ));
    assert_eq!(r["status"], "completed", "{r}");
    assert_eq!(r["stdout"], format!("hi\n{cwd}\n"));
    assert_eq!(r["stderr"], "err\n");
    assert_eq!(r["confinement"]["mode"], "none");
    assert_eq!(r["confinement"]["installed"], false);
    assert_eq!(r["arm"], "B0");
    assert_eq!(r["action_id"], "act-1");
}

#[test]
fn b0_file_operations() {
    let tmp = tempfile::tempdir().unwrap();
    let f = tmp.path().join("src/app.py");
    let fs = f.to_str().unwrap();
    let w = worker(&dispatch(
        Arm::B0,
        json!({"type":"write_file","path":fs,"content":"a = 1\nb = 2\n"}),
    ));
    assert_eq!(w["status"], "completed", "{w}");
    let p = worker(&dispatch(
        Arm::B0,
        json!({"type":"apply_patch","path":fs,"patch":"@@ -2,1 +2,1 @@\n-b = 2\n+b = 3\n"}),
    ));
    assert_eq!(p["status"], "completed", "{p}");
    let rd = worker(&dispatch(Arm::B0, json!({"type":"read_file","path":fs})));
    assert_eq!(rd["file_result"]["data"]["content"], "a = 1\nb = 3\n");
    let ls = worker(&dispatch(
        Arm::B0,
        json!({"type":"list_files","path":tmp.path().to_str().unwrap()}),
    ));
    let paths: Vec<&str> = ls["file_result"]["data"]["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, vec!["src", "src/app.py"]);
    let bad = worker(&dispatch(
        Arm::B0,
        json!({"type":"apply_patch","path":fs,"patch":"@@ -1,1 +1,1 @@\n-nope\n+x\n"}),
    ));
    assert_eq!(bad["status"], "failed");
    assert_eq!(bad["file_result"]["error_kind"], "patch_failed");
}

#[test]
fn read_does_not_follow_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let target = tmp.path().join("secret");
    std::fs::write(&target, "canary").unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    let r = worker(&dispatch(
        Arm::B0,
        json!({"type":"read_file","path":link.to_str().unwrap()}),
    ));
    assert_eq!(r["file_result"]["error_kind"], "is_symlink", "{r}");
    let w = worker(&dispatch(
        Arm::B0,
        json!({"type":"write_file","path":link.to_str().unwrap(),"content":"x"}),
    ));
    assert_eq!(w["status"], "failed");
    assert_eq!(std::fs::read_to_string(&target).unwrap(), "canary");
}

#[test]
fn timeout_status() {
    let tmp = tempfile::tempdir().unwrap();
    let r = worker(&dispatch(
        Arm::B0,
        json!({"type":"run_command","executable":"/usr/bin/sleep","argv":["/usr/bin/sleep","30"],"cwd":tmp.path().to_str().unwrap(),"timeout_seconds":1}),
    ));
    assert_eq!(r["status"], "timeout");
    assert_eq!(r["limit_hit"], "wall_time_seconds");
}

#[test]
fn fail_011_kernel_confinement_unavailable_fails_closed() {
    // P1 always needs kernel confinement. Until Phase 6/7 it must refuse.
    for arm in [Arm::P1, Arm::B1] {
        let r = worker(&dispatch(
            arm,
            json!({"type":"run_tests","target":"python-pytest"}),
        ));
        assert_eq!(r["status"], "confinement_failed", "{r}");
        assert!(r["exit_code"].is_null());
        assert_eq!(r["confinement"]["installed"], false);
    }
}

#[test]
fn tampered_requests_rejected() {
    let good = dispatch(
        Arm::P1,
        json!({"type":"run_tests","target":"python-pytest"}),
    );
    type Mutation = Box<dyn Fn(&mut Value)>;
    let cases: Vec<(&str, Mutation)> = vec![
        (
            "policy edited",
            Box::new(|r| {
                r["canonical_policy"] = json!(r["canonical_policy"]
                    .as_str()
                    .unwrap()
                    .replace("\"cpu_seconds\":45", "\"cpu_seconds\":600"));
            }),
        ),
        (
            "hash swapped",
            Box::new(|r| r["policy_hash"] = json!(format!("sha256:{}", "0".repeat(64)))),
        ),
        (
            "confinement downgraded",
            Box::new(|r| r["confinement"] = json!("none")),
        ),
        ("arm relabelled", Box::new(|r| r["arm"] = json!("B0"))),
        (
            "unknown field",
            Box::new(|r| r["docker_flags"] = json!(["--privileged"])),
        ),
        (
            "executable swapped",
            Box::new(|r| r["operation"]["argv"][0] = json!("/usr/bin/sh")),
        ),
        (
            "cwd escaped",
            Box::new(|r| r["operation"]["cwd"] = json!("/")),
        ),
        ("version", Box::new(|r| r["request_version"] = json!("9.9"))),
    ];
    for (name, mutate) in cases {
        let mut r = good.clone();
        mutate(&mut r);
        let out = worker(&r);
        assert_eq!(out["status"], "rejected", "{name}: {out}");
    }
    assert_eq!(worker_raw(b"{not json")["status"], "rejected");
    assert_eq!(
        worker_raw(&vec![b' '; 3 * 1024 * 1024])["status"],
        "rejected"
    );
}
