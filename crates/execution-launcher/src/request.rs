//! Worker-side defensive validation of a `WorkerRequest`.
//!
//! `ratchetd` is authoritative; this is defense in depth against a corrupted or
//! forged request reaching the worker.

use policy_model::{
    valid_id, Confinement, Operation, Policy, WorkerRequest, WORKER_REQUEST_VERSION,
};
use policy_validator::{hash_canonical, paths, validate_str, DeploymentConfig, ValidationContext};

pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;

pub struct Checked {
    pub req: WorkerRequest,
    pub policy: Policy,
}

pub fn check(raw: &[u8]) -> Result<Checked, String> {
    if raw.len() > MAX_REQUEST_BYTES {
        return Err("request too large".into());
    }
    let req: WorkerRequest =
        serde_json::from_slice(raw).map_err(|e| format!("invalid request: {e}"))?;
    if req.request_version != WORKER_REQUEST_VERSION {
        return Err(format!(
            "unsupported request_version {:?}",
            req.request_version
        ));
    }
    for (name, id) in [
        ("run_id", &req.run_id),
        ("task_id", &req.task_id),
        ("epoch_id", &req.epoch_id),
        ("action_id", &req.action_id),
    ] {
        if !valid_id(id) {
            return Err(format!("invalid {name}"));
        }
    }
    let expected_conf = match req.arm.as_str() {
        "B0" => Confinement::None,
        "B1" | "P1" => Confinement::Kernel,
        other => return Err(format!("unknown arm {other:?}")),
    };
    if req.confinement != expected_conf {
        return Err("confinement mode does not match arm".into());
    }
    if hash_canonical(&req.canonical_policy) != req.policy_hash {
        return Err("policy_hash does not match canonical_policy".into());
    }
    let deployment = DeploymentConfig::builtin();
    let ctx = ValidationContext {
        deployment: &deployment,
        landlock_abi: None,
    };
    let v = validate_str(&req.canonical_policy, &ctx)
        .map_err(|issues| format!("embedded policy invalid: {:?}", issues.first()))?;
    if v.canonical_json != req.canonical_policy {
        return Err("embedded policy is not in canonical form".into());
    }
    if v.policy.task_id != req.task_id {
        return Err("task_id mismatch".into());
    }
    if req.confinement == Confinement::Kernel {
        check_operation(&req.operation, &v.policy)?;
    }
    Ok(Checked {
        req,
        policy: v.policy,
    })
}

fn within_workspace(p: &str, policy: &Policy) -> Result<(), String> {
    paths::check_absolute(p).map_err(|e| format!("{p:?}: {e}"))?;
    if !paths::is_within(p, &policy.workspace) {
        return Err(format!("{p:?} is outside the workspace"));
    }
    Ok(())
}

fn check_operation(op: &Operation, policy: &Policy) -> Result<(), String> {
    match op {
        Operation::ListFiles { path } | Operation::ReadFile { path, .. } => {
            within_workspace(path, policy)
        }
        Operation::WriteFile { path, .. } | Operation::ApplyPatch { path, .. } => {
            within_workspace(path, policy)
        }
        Operation::Exec {
            argv,
            cwd,
            timeout_seconds,
        } => {
            within_workspace(cwd, policy)?;
            let exe = argv.first().ok_or("empty argv")?;
            if !policy.commands.allowed_executables.contains(exe) {
                return Err(format!("{exe:?} is not an allowed executable"));
            }
            if *timeout_seconds == 0 || *timeout_seconds > policy.limits.wall_time_seconds {
                return Err("timeout exceeds policy".into());
            }
            Ok(())
        }
    }
}
