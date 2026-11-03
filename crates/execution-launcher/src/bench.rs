//! `argus-worker --bench-confinement N`: measure confinement setup (PERF-002/003).
//!
//! Reads a canonical policy on stdin, times `plan` once, then spawns
//! `/usr/bin/true` N times with a pre-exec hook that installs Landlock and then
//! seccomp, timestamping each step. Timings travel back over a pipe that
//! stays open during pre-exec and is closed by CLOEXEC at exec. (A pipe, not a
//! socket: Rust socket writes use `sendto`, which the strict profile denies.) A
//! baseline of N unconfined spawns is measured too.

use process_supervisor::{run, RunSpec};
use serde_json::json;
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn spec(hook: Option<process_supervisor::PreExecHook>) -> RunSpec {
    RunSpec {
        argv: vec!["/usr/bin/true".into()],
        cwd: "/".into(),
        env: vec![],
        stdin: None,
        timeout: Duration::from_secs(10),
        rlimits: None,
        output_cap: 1024,
        pre_exec: hook,
    }
}

fn stats(mut v: Vec<f64>) -> serde_json::Value {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let q = |p: f64| {
        v.get(
            ((p * v.len() as f64).ceil() as usize)
                .saturating_sub(1)
                .min(v.len() - 1),
        )
        .copied()
    };
    json!({"n": v.len(), "median_us": q(0.5), "p95_us": q(0.95), "min_us": v.first(), "max_us": v.last()})
}

pub fn main(n: usize) -> i32 {
    let mut raw = String::new();
    if std::io::stdin().read_to_string(&mut raw).is_err() {
        return 2;
    }
    let deployment = policy_validator::DeploymentConfig::builtin();
    let ctx = policy_validator::ValidationContext {
        deployment: &deployment,
        landlock_abi: None,
    };
    let policy = match policy_validator::validate_str(&raw, &ctx) {
        Ok(v) => v.policy,
        Err(e) => {
            eprintln!("invalid policy: {e:?}");
            return 2;
        }
    };
    let _ = process_supervisor::set_child_subreaper();
    let t = Instant::now();
    let plan = match linux_confinement::plan(&policy) {
        Ok(p) => Arc::new(p),
        Err(e) => {
            eprintln!("plan failed: {e}");
            return 1;
        }
    };
    let plan_us = t.elapsed().as_secs_f64() * 1e6;

    let (mut landlock, mut seccomp, mut spawn_conf, mut spawn_base) =
        (vec![], vec![], vec![], vec![]);
    for _ in 0..n {
        let t = Instant::now();
        let _ = run(spec(None));
        spawn_base.push(t.elapsed().as_secs_f64() * 1e6);
    }
    for _ in 0..n {
        let (mut rx, tx) = match std::io::pipe() {
            Ok(p) => p,
            Err(_) => return 1,
        };
        let tx = Arc::new(Mutex::new(tx));
        let p = plan.clone();
        let hook: process_supervisor::PreExecHook = Box::new(move || {
            let t0 = Instant::now();
            linux_confinement::landlock_rules::install(&p.landlock)
                .map_err(std::io::Error::other)?;
            let t1 = Instant::now();
            linux_confinement::seccomp::install(&p.seccomp).map_err(std::io::Error::other)?;
            let t2 = Instant::now();
            let ll = (t1 - t0).as_nanos() as u64;
            let sc = (t2 - t1).as_nanos() as u64;
            let mut buf = [0u8; 16];
            buf[..8].copy_from_slice(&ll.to_le_bytes());
            buf[8..].copy_from_slice(&sc.to_le_bytes());
            if let Ok(mut w) = tx.lock() {
                let _ = w.write_all(&buf);
            }
            Ok(())
        });
        let t = Instant::now();
        let _ = run(spec(Some(hook)));
        spawn_conf.push(t.elapsed().as_secs_f64() * 1e6);
        let mut buf = [0u8; 16];
        if rx.read_exact(&mut buf).is_ok() {
            landlock.push(u64::from_le_bytes(buf[..8].try_into().unwrap_or_default()) as f64 / 1e3);
            seccomp.push(u64::from_le_bytes(buf[8..].try_into().unwrap_or_default()) as f64 / 1e3);
        }
    }
    let out = json!({
        "bench_version": "1.0",
        "plan_us": plan_us,
        "landlock_install": stats(landlock),
        "seccomp_install": stats(seccomp),
        "spawn_confined": stats(spawn_conf),
        "spawn_unconfined": stats(spawn_base),
        "profile": plan.seccomp.profile,
        "landlock_handled_abi": plan.landlock.handled_abi,
    });
    println!("{out}");
    0
}
