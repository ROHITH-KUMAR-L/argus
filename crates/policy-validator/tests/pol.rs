//! POL-001 … POL-020 and STK-002 (shared vectors).

use policy_validator::{validate_str, DeploymentConfig, ValidationContext};
use serde_json::{json, Value};
use std::path::PathBuf;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn ctx(d: &DeploymentConfig) -> ValidationContext<'_> {
    ValidationContext {
        deployment: d,
        landlock_abi: None,
    }
}

fn template(name: &str) -> Value {
    let raw =
        std::fs::read_to_string(repo_root().join(format!("config/templates/{name}.json"))).unwrap();
    serde_json::from_str(&raw).unwrap()
}

fn codes(json: &str, c: &ValidationContext<'_>) -> Vec<String> {
    match validate_str(json, c) {
        Ok(_) => vec!["ACCEPT".into()],
        Err(issues) => issues.into_iter().map(|i| i.code).collect(),
    }
}

#[test]
fn shared_vectors_stk_002() {
    let raw =
        std::fs::read_to_string(repo_root().join("tests/fixtures/policy_vectors.json")).unwrap();
    let file: Value = serde_json::from_str(&raw).unwrap();
    let d = DeploymentConfig::builtin();
    let mut failures = Vec::new();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 40);
    for v in vectors {
        let id = v["id"].as_str().unwrap();
        let want = v["expect"].as_str().unwrap();
        let input = match v.get("raw") {
            Some(r) => r.as_str().unwrap().to_string(),
            None => serde_json::to_string(&v["policy"]).unwrap(),
        };
        let got = codes(&input, &ctx(&d));
        let pass = if want == "ACCEPT" {
            got == ["ACCEPT"]
        } else {
            got.iter().any(|c| c == want)
        };
        if !pass {
            failures.push(format!("{id}: want {want}, got {got:?}"));
        }
    }
    assert!(
        failures.is_empty(),
        "vector failures:\n{}",
        failures.join("\n")
    );
}

#[test]
fn templates_validate() {
    let d = DeploymentConfig::builtin();
    for name in ["python-task", "c-build", "test-only"] {
        let v = validate_str(&template(name).to_string(), &ctx(&d));
        assert!(v.is_ok(), "{name}: {:?}", v.err());
    }
}

#[test]
fn pol_001_canonical_policy_and_hash() {
    let d = DeploymentConfig::builtin();
    let v = validate_str(&template("python-task").to_string(), &ctx(&d)).unwrap();
    assert!(v.policy_hash.starts_with("sha256:"));
    assert_eq!(v.policy_hash.len(), "sha256:".len() + 64);
    // Canonical JSON re-validates to the identical hash (idempotent normalization).
    let again = validate_str(&v.canonical_json, &ctx(&d)).unwrap();
    assert_eq!(again.policy_hash, v.policy_hash);
    assert_eq!(again.canonical_json, v.canonical_json);
}

#[test]
fn pol_004_errors_are_field_specific() {
    let d = DeploymentConfig::builtin();
    let mut p = template("python-task");
    p["limits"]["memory_bytes"] = json!("lots");
    let errs = validate_str(&p.to_string(), &ctx(&d)).unwrap_err();
    assert_eq!(errs[0].field, "$.limits.memory_bytes");
    assert_eq!(errs[0].code, "WRONG_TYPE");
}

#[test]
fn pol_007_clamping_only_when_configured_and_logged() {
    let mut d = DeploymentConfig::builtin();
    let mut p = template("python-task");
    p["limits"]["memory_bytes"] = json!(1u64 << 40);
    assert!(validate_str(&p.to_string(), &ctx(&d)).is_err());
    d.clamp_limits = true;
    let v = validate_str(&p.to_string(), &ctx(&d)).unwrap();
    assert_eq!(v.policy.limits.memory_bytes, d.max_limits.memory_bytes);
    assert_eq!(v.warnings.len(), 1);
    assert_eq!(v.warnings[0].code, "LIMIT_CLAMPED");
}

#[test]
fn pol_011_overlaps_normalize_deterministically_without_broadening() {
    let d = DeploymentConfig::builtin();
    let mut a = template("python-task");
    a["filesystem"]["read_only"] = json!([
        "/usr",
        "/dev/null",
        "/usr/lib",
        "/usr",
        "/workspace/task/src",
        "/etc/ld.so.cache",
        "/dev/urandom"
    ]);
    let mut b = template("python-task");
    b["filesystem"]["read_only"] = json!(["/dev/urandom", "/etc/ld.so.cache", "/usr", "/dev/null"]);
    let va = validate_str(&a.to_string(), &ctx(&d)).unwrap();
    let vb = validate_str(&b.to_string(), &ctx(&d)).unwrap();
    assert_eq!(va.policy_hash, vb.policy_hash);
    assert_eq!(va.permissions, vb.permissions);
    // A path listed both ways gets exactly what read_write grants: nothing more.
    let mut c = template("python-task");
    c["filesystem"]["read_only"] = json!(["/usr", "/tmp"]);
    let vc = validate_str(&c.to_string(), &ctx(&d)).unwrap();
    assert!(vc
        .policy
        .filesystem
        .read_write
        .contains(&"/tmp".to_string()));
    assert!(!vc.policy.filesystem.read_only.contains(&"/tmp".to_string()));
}

#[test]
fn pol_014_unsupported_landlock_right_rejected() {
    let d = DeploymentConfig::builtin();
    let mut p = template("python-task");
    p["filesystem"]["required_rights"] = json!(["truncate", "ioctl_dev"]);
    let c = ValidationContext {
        deployment: &d,
        landlock_abi: Some(3),
    };
    let errs = validate_str(&p.to_string(), &c).unwrap_err();
    assert!(errs
        .iter()
        .any(|e| e.code == "UNSUPPORTED_LANDLOCK_RIGHT" && e.message.contains("IoctlDev")));
    assert!(!errs.iter().any(|e| e.message.contains("Truncate")));
    let ok = ValidationContext {
        deployment: &d,
        landlock_abi: Some(5),
    };
    assert!(validate_str(&p.to_string(), &ok).is_ok());
}

#[test]
fn pol_015_network_requires_abi_4() {
    let mut d = DeploymentConfig::builtin();
    d.allow_network = true;
    let mut p = template("python-task");
    p["network"] = json!({"mode": "tcp_ports", "allowed_tcp_ports": [8080, 8080]});
    let old = ValidationContext {
        deployment: &d,
        landlock_abi: Some(3),
    };
    assert!(codes(&p.to_string(), &old).contains(&"UNSUPPORTED_LANDLOCK_RIGHT".to_string()));
    let new = ValidationContext {
        deployment: &d,
        landlock_abi: Some(4),
    };
    let v = validate_str(&p.to_string(), &new).unwrap();
    assert_eq!(v.policy.network.allowed_tcp_ports, vec![8080]);
}

#[test]
fn pol_016_hash_stable_under_key_reordering() {
    let d = DeploymentConfig::builtin();
    let p = template("python-task");
    // Re-serialize with reversed key order at every level.
    fn reverse(v: &Value) -> String {
        match v {
            Value::Object(m) => {
                let parts: Vec<String> = m
                    .iter()
                    .rev()
                    .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), reverse(v)))
                    .collect();
                format!("{{{}}}", parts.join(","))
            }
            Value::Array(a) => format!("[{}]", a.iter().map(reverse).collect::<Vec<_>>().join(",")),
            other => other.to_string(),
        }
    }
    let forward = p.to_string();
    let backward = reverse(&p);
    assert_ne!(forward, backward);
    let h1 = validate_str(&forward, &ctx(&d)).unwrap().policy_hash;
    let h2 = validate_str(&backward, &ctx(&d)).unwrap().policy_hash;
    assert_eq!(h1, h2);
}

#[test]
fn pol_017_hash_changes_with_any_permission() {
    let d = DeploymentConfig::builtin();
    let base = template("python-task");
    let h0 = validate_str(&base.to_string(), &ctx(&d))
        .unwrap()
        .policy_hash;
    type Mutation = Box<dyn Fn(&mut Value)>;
    let mutations: Vec<Mutation> = vec![
        Box::new(|p| p["limits"]["cpu_seconds"] = json!(44)),
        Box::new(|p| p["filesystem"]["read_write"] = json!(["/workspace/task"])),
        Box::new(|p| p["commands"]["allowed_tool_names"] = json!(["read_file"])),
        Box::new(|p| p["syscalls"]["profile"] = json!("minimal-run-v1")),
        Box::new(|p| p["syscalls"]["deny_high_risk"] = json!(["kill"])),
    ];
    for m in mutations {
        let mut p = base.clone();
        m(&mut p);
        let h = validate_str(&p.to_string(), &ctx(&d)).unwrap().policy_hash;
        assert_ne!(h, h0);
    }
}

#[test]
fn oversized_input_rejected() {
    let d = DeploymentConfig::builtin();
    let big = format!("{{\"x\":\"{}\"}}", "a".repeat(300 * 1024));
    assert_eq!(codes(&big, &ctx(&d)), vec!["INPUT_TOO_LARGE".to_string()]);
}

#[test]
fn too_many_entries_rejected() {
    let d = DeploymentConfig::builtin();
    let mut p = template("python-task");
    let many: Vec<String> = (0..100).map(|i| format!("/usr/lib/x{i}")).collect();
    p["filesystem"]["read_only"] = json!(many);
    assert!(codes(&p.to_string(), &ctx(&d)).contains(&"TOO_MANY_ENTRIES".to_string()));
}
