//! RAT-024: property-based subset invariant, checked against an independent oracle.
//!
//! For random sequences of candidate policies, every transition the engine
//! *accepts* must be a subset of the previous policy and of P0, and every
//! transition it *rejects as an expansion* must really add a permission.

use policy_model::{profile, Policy};
use policy_validator::DeploymentConfig;
use privilege_ratchet::{Arm, Engine, Op, RatchetError};
use proptest::prelude::*;
use serde_json::json;
use std::collections::BTreeSet;

const RO_POOL: &[&str] = &[
    "/usr",
    "/usr/lib",
    "/usr/local",
    "/usr/local/bin",
    "/etc/ld.so.cache",
    "/dev/null",
    "/dev/urandom",
    "/opt",
    "/opt/tools",
    "/workspace/task",
    "/workspace/task/src",
];
const RW_POOL: &[&str] = &[
    "/workspace/task",
    "/workspace/task/src",
    "/workspace/task/build",
    "/tmp",
    "/tmp/cache",
];
const EXE_POOL: &[&str] = &["/usr/local/bin/python3", "/usr/bin/true", "/usr/bin/gcc"];
const TOOL_POOL: &[&str] = &[
    "list_files",
    "read_file",
    "write_file",
    "apply_patch",
    "run_command",
    "run_tests",
    "request_permission",
];
const PROFILES: &[&str] = &["python-build-v1", "c-build-v1", "minimal-run-v1"];
const EXTRA_DENY: &[&str] = &["kill", "fork", "vfork", "clone3", "socket"];
const LIMIT_VALUES: &[u64] = &[1, 8, 32, 60];

fn pick<'a>(pool: &'a [&'a str], mask: u32) -> Vec<&'a str> {
    pool.iter()
        .enumerate()
        .filter(|(i, _)| mask & (1 << i) != 0)
        .map(|(_, p)| *p)
        .collect()
}

#[derive(Debug, Clone)]
struct Cand {
    ro: u32,
    rw: u32,
    exe: u32,
    tools: u32,
    profile: usize,
    deny: u32,
    limits: [usize; 6],
}

fn cand() -> impl Strategy<Value = Cand> {
    (
        any::<u32>(),
        1u32..(1 << RW_POOL.len()),
        any::<u32>(),
        any::<u32>(),
        0..PROFILES.len(),
        any::<u32>(),
        prop::array::uniform6(0..LIMIT_VALUES.len()),
    )
        .prop_map(|(ro, rw, exe, tools, profile, deny, limits)| Cand {
            ro,
            rw,
            exe,
            tools,
            profile,
            deny,
            limits,
        })
}

fn render(c: &Cand) -> String {
    let lim = |i: usize| LIMIT_VALUES[c.limits[i]];
    json!({
        "schema_version": "1.0",
        "task_id": "prop",
        "workspace": "/workspace/task",
        "filesystem": {"read_only": pick(RO_POOL, c.ro), "read_write": pick(RW_POOL, c.rw)},
        "commands": {"allowed_tool_names": pick(TOOL_POOL, c.tools), "allowed_executables": pick(EXE_POOL, c.exe), "shell": "deny"},
        "syscalls": {"profile": PROFILES[c.profile], "deny_high_risk": pick(EXTRA_DENY, c.deny)},
        "network": {"mode": "none"},
        "limits": {"wall_time_seconds": lim(0), "cpu_seconds": lim(1), "memory_bytes": lim(2), "file_size_bytes": lim(3), "process_count": lim(4), "open_files": lim(5)},
        "approval": {"required_for_privilege_step_up": true, "approval_mode": "new_execution_epoch"}
    })
    .to_string()
}

// ----- independent oracle (does not use privilege_ratchet::subset) -----

fn access_at(p: &Policy, probe: &str) -> u8 {
    let under = |root: &str| probe == root || probe.starts_with(&format!("{root}/"));
    let mut a = 0u8;
    for r in &p.filesystem.read_only {
        if under(r) {
            a |= 0b101;
        }
    }
    for r in &p.filesystem.read_write {
        if under(r) {
            a |= 0b111;
        }
    }
    a
}

fn denied(p: &Policy) -> BTreeSet<String> {
    let mut s: BTreeSet<String> = profile(&p.syscalls.profile)
        .unwrap()
        .denied()
        .into_iter()
        .map(String::from)
        .collect();
    s.extend(p.syscalls.deny_high_risk.iter().cloned());
    s
}

fn oracle_subset(new: &Policy, old: &Policy) -> bool {
    let probes: Vec<String> = RO_POOL
        .iter()
        .chain(RW_POOL)
        .flat_map(|p| [p.to_string(), format!("{p}/child")])
        .collect();
    let fs_ok = probes
        .iter()
        .all(|q| access_at(new, q) & !access_at(old, q) == 0);
    let set = |v: &Vec<String>| v.iter().cloned().collect::<BTreeSet<_>>();
    fs_ok
        && set(&new.commands.allowed_tool_names).is_subset(&set(&old.commands.allowed_tool_names))
        && set(&new.commands.allowed_executables).is_subset(&set(&old.commands.allowed_executables))
        && denied(new).is_superset(&denied(old))
        && new.limits.le(&old.limits)
}

/// Derive the next candidate from `prev`: narrowing steps AND the masks and
/// lower limits; widening steps OR the masks and raise limits.
fn step(prev: &Cand, narrow: bool, r: &Cand) -> Cand {
    let mut limits = prev.limits;
    for (i, l) in limits.iter_mut().enumerate() {
        *l = if narrow {
            (*l).min(r.limits[i])
        } else {
            (*l).max(r.limits[i])
        };
    }
    if narrow {
        Cand {
            ro: prev.ro & r.ro,
            rw: (prev.rw & r.rw).max(prev.rw & 1), // usually keep the workspace grant
            exe: prev.exe & r.exe,
            tools: prev.tools & r.tools,
            profile: if r.profile == 2 { 2 } else { prev.profile },
            deny: prev.deny | r.deny,
            limits,
        }
    } else {
        Cand {
            ro: prev.ro | r.ro,
            rw: prev.rw | r.rw,
            exe: prev.exe | r.exe,
            tools: prev.tools | r.tools,
            profile: r.profile,
            deny: prev.deny & r.deny,
            limits,
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 1000, ..ProptestConfig::default() })]

    #[test]
    fn rat_024_accepted_transitions_never_add_permissions(
        first in cand(),
        steps in prop::collection::vec((prop::bool::weighted(0.7), cand()), 1..10),
    ) {
        // Bias P0 towards validity: always grant /usr (executables) and the workspace.
        let mut first = first;
        first.ro |= 1;
        first.rw |= 1;
        let mut e = Engine::new(Arm::P1, DeploymentConfig::builtin(), Some(10));
        let Ok(out) = e.apply(&Op::OpenTask { task_id: "prop".into(), policy: render(&first) }, 0) else {
            return Ok(());
        };
        let epoch_id = out["epoch_id"].as_str().unwrap().to_string();
        let p0 = e.task("prop").unwrap().current.policy.clone();
        let mut prev = p0.clone();
        let mut prev_cand = first;
        let mut hash = out["policy_hash"].as_str().unwrap().to_string();
        for (i, (narrow, r)) in steps.iter().enumerate() {
            let c = step(&prev_cand, *narrow, r);
            let res = e.apply(&Op::ApplyNarrowing {
                task_id: "prop".into(), epoch_id: epoch_id.clone(), expected_policy_hash: hash.clone(),
                proposed_policy: render(&c), reason: "prop".into(),
            }, i as u64 + 1);
            let now = e.task("prop").unwrap().current.policy.clone();
            match res {
                Ok(v) => {
                    prop_assert!(oracle_subset(&now, &prev), "accepted a non-subset");
                    prop_assert!(oracle_subset(&now, &p0), "drifted beyond P0");
                    hash = v["policy_hash"].as_str().unwrap().to_string();
                    prev = now;
                    prev_cand = c;
                }
                Err(RatchetError::ExpansionDenied(_)) => {
                    let proposed = policy_validator::validate_str(&render(&c), &policy_validator::ValidationContext {
                        deployment: &DeploymentConfig::builtin(), landlock_abi: Some(10),
                    }).unwrap().policy;
                    prop_assert!(!oracle_subset(&proposed, &prev), "rejected a genuine narrowing");
                    prop_assert_eq!(&now, &prev);
                }
                Err(RatchetError::PolicyInvalid(_)) => prop_assert_eq!(&now, &prev),
                Err(other) => prop_assert!(false, "unexpected error {:?}", other),
            }
        }
    }
}
