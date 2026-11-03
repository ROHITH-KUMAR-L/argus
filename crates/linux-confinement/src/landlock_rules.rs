//! Policy → Landlock ruleset.
//!
//! * Handled ABI = min(kernel ABI, newest ABI this crate knows). Both are
//!   reported. Only rights of the handled ABI are requested, as a *hard*
//!   requirement: anything unsupported is an error, never a silent downgrade.
//! * `read_only` hierarchies get read + execute; `read_write` get every
//!   handled filesystem right. Non-directory roots (e.g. `/dev/null`) get the
//!   file-applicable subset.
//! * Rule roots are opened component by component with `O_NOFOLLOW`; a
//!   symlink anywhere in a rule path is fatal (an earlier action could have
//!   planted one to redirect a grant). A missing root grants nothing and is
//!   reported.
//! * ABI >= 4: TCP bind/connect are handled; only policy ports are granted.
//! * ABI >= 6: signals and abstract UNIX sockets are scoped to the domain, so
//!   the task cannot signal the (unconfined) supervisor or anything outside.

use landlock::{
    Access, AccessFs, AccessNet, BitFlags, CompatLevel, Compatible, NetPort, PathBeneath, Ruleset,
    RulesetAttr, RulesetCreatedAttr, RulesetStatus, Scope, ABI,
};
use policy_model::{NetworkMode, Policy};
use serde::Serialize;

/// Newest Landlock ABI the pinned `landlock` crate can express.
pub const MAX_CRATE_ABI: u32 = 9;

#[derive(Debug, Clone, Serialize)]
pub struct FsRule {
    pub path: String,
    pub access: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct LandlockPlan {
    pub kernel_abi: u32,
    pub handled_abi: u32,
    pub handled_fs: Vec<String>,
    pub handled_net: bool,
    pub scoped: bool,
    pub rules: Vec<FsRule>,
    pub tcp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Serialize)]
pub struct LandlockReport {
    pub installed_rules: Vec<FsRule>,
    pub skipped_missing: Vec<String>,
}

fn abi_enum(v: u32) -> ABI {
    match v {
        1 => ABI::V1,
        2 => ABI::V2,
        3 => ABI::V3,
        4 => ABI::V4,
        5 => ABI::V5,
        6 => ABI::V6,
        7 => ABI::V7,
        8 => ABI::V8,
        _ => ABI::V9,
    }
}

fn names(b: BitFlags<AccessFs>) -> Vec<String> {
    b.iter().map(|a| format!("{a:?}")).collect()
}

pub fn plan(policy: &Policy, kernel_abi: u32) -> Result<LandlockPlan, String> {
    if kernel_abi == 0 {
        return Err(
            "Landlock is unavailable on this kernel (or blocked by the outer seccomp profile)"
                .into(),
        );
    }
    let handled_abi = kernel_abi.min(MAX_CRATE_ABI);
    let abi = abi_enum(handled_abi);
    let mut rules = Vec::new();
    for p in &policy.filesystem.read_only {
        rules.push(FsRule {
            path: p.clone(),
            access: "read_execute",
        });
    }
    for p in &policy.filesystem.read_write {
        rules.push(FsRule {
            path: p.clone(),
            access: "all",
        });
    }
    let tcp_ports = match policy.network.mode {
        NetworkMode::None => vec![],
        NetworkMode::TcpPorts => {
            if handled_abi < 4 {
                return Err("TCP port rules need Landlock ABI 4".into());
            }
            policy.network.allowed_tcp_ports.clone()
        }
    };
    for r in &policy.filesystem.required_rights {
        if r.min_abi() > handled_abi {
            return Err(format!("required right {r:?} needs ABI {}", r.min_abi()));
        }
    }
    Ok(LandlockPlan {
        kernel_abi,
        handled_abi,
        handled_fs: names(AccessFs::from_all(abi)),
        handled_net: handled_abi >= 4,
        scoped: handled_abi >= 6,
        rules,
        tcp_ports,
    })
}

/// Build and enforce the ruleset on the calling thread (call in the child,
/// before `execve`, while the process is single-threaded).
pub fn install(plan: &LandlockPlan) -> Result<LandlockReport, String> {
    let abi = abi_enum(plan.handled_abi);
    let all = AccessFs::from_all(abi);
    let read = AccessFs::from_read(abi);
    let file_only = AccessFs::from_file(abi);
    fn e(what: &'static str) -> impl Fn(landlock::RulesetError) -> String {
        move |err| format!("{what}: {err}")
    }

    let mut rs = Ruleset::default()
        .set_compatibility(CompatLevel::HardRequirement)
        .handle_access(all)
        .map_err(e("handle fs"))?;
    if plan.handled_net {
        rs = rs
            .handle_access(AccessNet::from_all(abi))
            .map_err(e("handle net"))?;
    }
    if plan.scoped {
        rs = rs.scope(Scope::from_all(abi)).map_err(e("scope"))?;
    }
    let mut created = rs.create().map_err(e("create"))?;
    let mut installed = Vec::new();
    let mut skipped = Vec::new();
    for r in &plan.rules {
        let (fd, is_dir) = match crate::sys::open_no_symlinks(&r.path) {
            Ok(v) => v,
            Err(err) if err.raw_os_error() == Some(libc::ENOENT) => {
                skipped.push(r.path.clone());
                continue;
            }
            Err(err) => return Err(format!("rule root {:?}: {err}", r.path)),
        };
        let mut access = if r.access == "all" { all } else { read };
        if !is_dir {
            access &= file_only;
        }
        created = created
            .add_rule(PathBeneath::new(fd, access))
            .map_err(e("add rule"))?;
        installed.push(r.clone());
    }
    for port in &plan.tcp_ports {
        created = created
            .add_rule(NetPort::new(*port, AccessNet::from_all(abi)))
            .map_err(e("add port"))?;
    }
    let status = created.restrict_self().map_err(e("restrict_self"))?;
    if status.ruleset != RulesetStatus::FullyEnforced {
        return Err(format!("ruleset not fully enforced: {:?}", status.ruleset));
    }
    if !status.no_new_privs {
        return Err("no_new_privs was not set".into());
    }
    Ok(LandlockReport {
        installed_rules: installed,
        skipped_missing: skipped,
    })
}
