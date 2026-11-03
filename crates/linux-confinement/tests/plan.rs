//! LL-017 (ABI downgrade) and LL-018 planning, without needing an older kernel.

use linux_confinement::landlock_rules::{plan, MAX_CRATE_ABI};
use policy_validator::{validate_str, DeploymentConfig, ValidationContext};
use serde_json::{json, Value};
use std::path::PathBuf;

fn policy(mut f: impl FnMut(&mut Value)) -> policy_model::Policy {
    let p =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/templates/python-task.json");
    let mut v: Value = serde_json::from_str(&std::fs::read_to_string(p).unwrap()).unwrap();
    f(&mut v);
    let mut d = DeploymentConfig::builtin();
    d.allow_network = true;
    validate_str(
        &v.to_string(),
        &ValidationContext {
            deployment: &d,
            landlock_abi: None,
        },
    )
    .unwrap()
    .policy
}

#[test]
fn ll_018_no_landlock_is_an_error() {
    assert!(plan(&policy(|_| {}), 0)
        .unwrap_err()
        .contains("unavailable"));
}

#[test]
fn ll_017_older_abis_handle_only_their_rights() {
    let p = policy(|_| {});
    let v1 = plan(&p, 1).unwrap();
    assert_eq!(v1.handled_abi, 1);
    assert!(!v1
        .handled_fs
        .iter()
        .any(|r| r == "Refer" || r == "Truncate"));
    assert!(!v1.handled_net && !v1.scoped);
    let v3 = plan(&p, 3).unwrap();
    assert!(v3.handled_fs.iter().any(|r| r == "Truncate"));
    assert!(!v3.handled_fs.iter().any(|r| r == "IoctlDev"));
    let v6 = plan(&p, 6).unwrap();
    assert!(v6.handled_net && v6.scoped);
    let future = plan(&p, 42).unwrap();
    assert_eq!(future.kernel_abi, 42);
    assert_eq!(future.handled_abi, MAX_CRATE_ABI);
}

#[test]
fn required_rights_beyond_abi_fail() {
    let p = policy(|v| v["filesystem"]["required_rights"] = json!(["ioctl_dev"]));
    assert!(plan(&p, 4).is_err());
    assert!(plan(&p, 5).is_ok());
}

#[test]
fn tcp_ports_need_abi_4() {
    let p = policy(|v| v["network"] = json!({"mode": "tcp_ports", "allowed_tcp_ports": [8080]}));
    assert!(plan(&p, 3).is_err());
    assert_eq!(plan(&p, 4).unwrap().tcp_ports, vec![8080]);
}
