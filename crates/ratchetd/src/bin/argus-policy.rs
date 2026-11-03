//! `argus-policy validate [--deployment FILE] [--landlock-abi N] <FILE|->`
//!
//! Validates a task policy without executing anything and prints a JSON
//! report: the normalized policy and hash on success, or field-specific issues.
//! Exit status: 0 valid, 1 invalid, 2 usage or I/O error.

use policy_validator::{validate_str, DeploymentConfig, ValidationContext};
use std::io::Read;

fn usage() -> ! {
    eprintln!("usage: argus-policy validate [--deployment FILE] [--landlock-abi N] <FILE|->");
    std::process::exit(2);
}

fn main() {
    let mut args = std::env::args().skip(1);
    if args.next().as_deref() != Some("validate") {
        usage();
    }
    let mut deployment_path: Option<String> = None;
    let mut abi: Option<u32> = None;
    let mut input: Option<String> = None;
    while let Some(a) = args.next() {
        match a.as_str() {
            "--deployment" => deployment_path = Some(args.next().unwrap_or_else(|| usage())),
            "--landlock-abi" => {
                abi = Some(
                    args.next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or_else(|| usage()),
                )
            }
            _ if input.is_none() => input = Some(a),
            _ => usage(),
        }
    }
    let input = input.unwrap_or_else(|| usage());

    let deployment = match deployment_path {
        None => DeploymentConfig::builtin(),
        Some(p) => match std::fs::read_to_string(&p)
            .map_err(|e| e.to_string())
            .and_then(|s| serde_json::from_str::<DeploymentConfig>(&s).map_err(|e| e.to_string()))
        {
            Ok(d) => d,
            Err(e) => {
                eprintln!("argus-policy: cannot load deployment {p}: {e}");
                std::process::exit(2);
            }
        },
    };

    let mut text = String::new();
    let read = if input == "-" {
        std::io::stdin()
            .take(policy_validator::MAX_POLICY_BYTES as u64 + 1)
            .read_to_string(&mut text)
            .map(|_| ())
    } else {
        std::fs::read_to_string(&input).map(|s| text = s)
    };
    if let Err(e) = read {
        eprintln!("argus-policy: cannot read {input}: {e}");
        std::process::exit(2);
    }

    let ctx = ValidationContext {
        deployment: &deployment,
        landlock_abi: abi,
    };
    let (report, code) = match validate_str(&text, &ctx) {
        Ok(v) => (
            serde_json::json!({
                "ok": true,
                "policy_hash": v.policy_hash,
                "normalized_policy": v.policy,
                "warnings": v.warnings,
            }),
            0,
        ),
        Err(issues) => (serde_json::json!({"ok": false, "errors": issues}), 1),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report serializes")
    );
    std::process::exit(code);
}
