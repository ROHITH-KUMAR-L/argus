//! Authoritative task-policy validation, canonicalization and hashing.
//!
//! `validate_str` is the only way a policy enters the system: strict parsing
//! (unknown fields, wrong types, duplicates and trailing data all rejected),
//! semantic checks against the deployment guard rails, normalization into a
//! deterministic canonical form, and a SHA-256 hash over that form.

pub mod deployment;
pub mod paths;

pub use deployment::DeploymentConfig;

use policy_model::{
    profile, Access, NetworkMode, PermissionSet, Policy, ShellMode, APPROVAL_MODE_NEW_EPOCH,
    SCHEMA_VERSION,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_POLICY_BYTES: usize = 256 * 1024;
/// Landlock ABI that introduced TCP bind/connect rules.
pub const LANDLOCK_NET_ABI: u32 = 4;

/// One validation problem, addressed by a JSON path such as `$.limits.memory_bytes`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Issue {
    pub field: String,
    pub code: String,
    pub message: String,
}

impl Issue {
    fn new(field: impl Into<String>, code: &str, message: impl Into<String>) -> Self {
        Self {
            field: field.into(),
            code: code.into(),
            message: message.into(),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ValidationContext<'a> {
    pub deployment: &'a DeploymentConfig,
    /// Detected Landlock ABI, when known. `None` skips ABI-dependent checks
    /// (the launcher re-checks against the real kernel and fails closed).
    pub landlock_abi: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Validated {
    pub policy: Policy,
    pub canonical_json: String,
    pub policy_hash: String,
    pub permissions: PermissionSet,
    pub warnings: Vec<Issue>,
}

/// Strictly parse a policy document. No semantic checks.
pub fn parse(json: &str) -> Result<Policy, Vec<Issue>> {
    if json.len() > MAX_POLICY_BYTES {
        return Err(vec![Issue::new(
            "$",
            "INPUT_TOO_LARGE",
            format!("policy exceeds {MAX_POLICY_BYTES} bytes"),
        )]);
    }
    let mut de = serde_json::Deserializer::from_str(json);
    let policy: Policy = match serde_path_to_error::deserialize(&mut de) {
        Ok(p) => p,
        Err(e) => {
            let path = e.path().to_string();
            let field = if path == "." {
                "$".to_string()
            } else {
                format!("$.{path}")
            };
            return Err(vec![classify_serde(field, e.inner())]);
        }
    };
    if let Err(e) = de.end() {
        return Err(vec![Issue::new("$", "INVALID_JSON", e.to_string())]);
    }
    Ok(policy)
}

fn classify_serde(field: String, e: &serde_json::Error) -> Issue {
    use serde_json::error::Category;
    let msg = e.to_string();
    let code = match e.classify() {
        Category::Syntax | Category::Eof | Category::Io => "INVALID_JSON",
        Category::Data => {
            if msg.starts_with("unknown field") {
                "UNKNOWN_FIELD"
            } else if msg.starts_with("missing field") {
                "MISSING_FIELD"
            } else if msg.starts_with("duplicate field") {
                "DUPLICATE_FIELD"
            } else if msg.starts_with("invalid type") {
                "WRONG_TYPE"
            } else {
                "INVALID_VALUE"
            }
        }
    };
    Issue::new(field, code, msg)
}

/// Parse and validate. On success the returned policy is normalized.
pub fn validate_str(json: &str, ctx: &ValidationContext<'_>) -> Result<Validated, Vec<Issue>> {
    validate(parse(json)?, ctx)
}

/// Validate and normalize an already-parsed policy.
pub fn validate(mut p: Policy, ctx: &ValidationContext<'_>) -> Result<Validated, Vec<Issue>> {
    let d = ctx.deployment;
    let mut errs: Vec<Issue> = Vec::new();
    let mut warnings: Vec<Issue> = Vec::new();

    // --- identity -------------------------------------------------------
    if p.schema_version != SCHEMA_VERSION {
        errs.push(Issue::new(
            "$.schema_version",
            "UNSUPPORTED_SCHEMA_VERSION",
            format!("schema_version {:?} is not supported (expected {SCHEMA_VERSION:?}); no migration is defined", p.schema_version),
        ));
    }
    if !valid_task_id(&p.task_id) {
        errs.push(Issue::new(
            "$.task_id",
            "INVALID_TASK_ID",
            "task_id must be 1-64 characters of [A-Za-z0-9._-] and not start with '.'",
        ));
    }
    if p.description.chars().count() > d.max_description_len {
        errs.push(Issue::new(
            "$.description",
            "DESCRIPTION_TOO_LONG",
            format!("description exceeds {} characters", d.max_description_len),
        ));
    }

    // --- list sizes -----------------------------------------------------
    let lists: [(&str, usize); 7] = [
        ("$.filesystem.read_only", p.filesystem.read_only.len()),
        ("$.filesystem.read_write", p.filesystem.read_write.len()),
        ("$.filesystem.deny", p.filesystem.deny.len()),
        (
            "$.commands.allowed_tool_names",
            p.commands.allowed_tool_names.len(),
        ),
        (
            "$.commands.allowed_executables",
            p.commands.allowed_executables.len(),
        ),
        ("$.syscalls.deny_high_risk", p.syscalls.deny_high_risk.len()),
        (
            "$.network.allowed_tcp_ports",
            p.network.allowed_tcp_ports.len(),
        ),
    ];
    for (field, n) in lists {
        if n > d.max_list_entries {
            errs.push(Issue::new(
                field,
                "TOO_MANY_ENTRIES",
                format!("{n} entries exceeds the maximum of {}", d.max_list_entries),
            ));
        }
    }
    if !errs.is_empty() && errs.iter().any(|e| e.code == "TOO_MANY_ENTRIES") {
        return Err(errs);
    }

    // --- workspace ------------------------------------------------------
    let ws_ok = match paths::check_absolute(&p.workspace) {
        Ok(_) => {
            if p.workspace != d.workspace_path {
                errs.push(Issue::new(
                    "$.workspace",
                    "WORKSPACE_MISMATCH",
                    format!("workspace must be {:?}", d.workspace_path),
                ));
                false
            } else {
                true
            }
        }
        Err(e) => {
            errs.push(Issue::new("$.workspace", e.code(), e.to_string()));
            false
        }
    };

    // --- filesystem -----------------------------------------------------
    let mut grants: BTreeMap<String, Access> = BTreeMap::new();
    for (list, access, writable) in [
        ("read_only", Access::READ_ONLY, false),
        ("read_write", Access::READ_WRITE, true),
    ] {
        let entries = if writable {
            &p.filesystem.read_write
        } else {
            &p.filesystem.read_only
        };
        for (i, path) in entries.iter().enumerate() {
            let field = format!("$.filesystem.{list}[{i}]");
            if let Err(e) = paths::check_absolute(path) {
                errs.push(Issue::new(field, e.code(), format!("{path:?}: {e}")));
                continue;
            }
            if let Some(why) = guard_violation(path, d) {
                errs.push(Issue::new(
                    field,
                    "PATH_FORBIDDEN",
                    format!("{path:?}: {why}"),
                ));
                continue;
            }
            if writable
                && !d.device_allowlist.contains(path)
                && !d.writable_roots.iter().any(|r| paths::is_within(path, r))
            {
                errs.push(Issue::new(
                    field,
                    "PATH_NOT_WRITABLE_ROOT",
                    format!(
                        "{path:?} is not inside a writable root {:?}",
                        d.writable_roots
                    ),
                ));
                continue;
            }
            let e = grants.entry(path.clone()).or_insert(Access(0));
            *e = e.union(access);
        }
    }
    let grants = remove_redundant(grants);

    let mut deny: BTreeSet<String> = BTreeSet::new();
    for (i, path) in p.filesystem.deny.iter().enumerate() {
        let field = format!("$.filesystem.deny[{i}]");
        if let Err(e) = paths::check_absolute(path) {
            errs.push(Issue::new(field, e.code(), format!("{path:?}: {e}")));
            continue;
        }
        if let Some(allowed) = grants.keys().find(|a| paths::overlaps(path, a)) {
            errs.push(Issue::new(
                field,
                "DENY_ALLOW_OVERLAP",
                format!("deny {path:?} overlaps allowed {allowed:?}; Landlock is allow-only, so a deny inside (or around) an allowed hierarchy cannot be enforced. Narrow the allow rules instead"),
            ));
            continue;
        }
        deny.insert(path.clone());
    }

    if ws_ok && !grants.keys().any(|g| paths::is_within(&p.workspace, g)) {
        errs.push(Issue::new(
            "$.filesystem",
            "WORKSPACE_NOT_GRANTED",
            "the workspace must be covered by a read_only or read_write entry",
        ));
    }

    let mut rights: BTreeSet<_> = p.filesystem.required_rights.iter().copied().collect();
    if let Some(abi) = ctx.landlock_abi {
        for r in &rights {
            if r.min_abi() > abi {
                errs.push(Issue::new(
                    "$.filesystem.required_rights",
                    "UNSUPPORTED_LANDLOCK_RIGHT",
                    format!(
                        "{r:?} requires Landlock ABI {} but the kernel provides {abi}",
                        r.min_abi()
                    ),
                ));
            }
        }
    }

    // --- commands -------------------------------------------------------
    let mut tools = BTreeSet::new();
    for (i, t) in p.commands.allowed_tool_names.iter().enumerate() {
        if d.tool_names.contains(t) {
            tools.insert(t.clone());
        } else {
            errs.push(Issue::new(
                format!("$.commands.allowed_tool_names[{i}]"),
                "UNKNOWN_TOOL",
                format!("{t:?} is not a registered tool"),
            ));
        }
    }
    let mut exes = BTreeSet::new();
    for (i, x) in p.commands.allowed_executables.iter().enumerate() {
        let field = format!("$.commands.allowed_executables[{i}]");
        if let Err(e) = paths::check_absolute(x) {
            errs.push(Issue::new(field, e.code(), format!("{x:?}: {e}")));
            continue;
        }
        if !d.executables.contains(x) {
            errs.push(Issue::new(
                field,
                "UNKNOWN_EXECUTABLE",
                format!("{x:?} is not in the executable catalog"),
            ));
            continue;
        }
        if p.commands.shell == ShellMode::Deny && d.shell_executables.contains(x) {
            errs.push(Issue::new(
                field,
                "SHELL_CONFLICT",
                format!("{x:?} is a shell but commands.shell is \"deny\""),
            ));
            continue;
        }
        if !grants
            .iter()
            .any(|(g, a)| a.contains(Access(Access::EXECUTE)) && paths::is_within(x, g))
        {
            errs.push(Issue::new(
                field,
                "EXECUTABLE_NOT_GRANTED",
                format!("{x:?} is not inside any filesystem hierarchy granted execute"),
            ));
            continue;
        }
        exes.insert(x.clone());
    }

    // --- syscalls -------------------------------------------------------
    if profile(&p.syscalls.profile).is_none() {
        errs.push(Issue::new(
            "$.syscalls.profile",
            "UNKNOWN_SYSCALL_PROFILE",
            format!(
                "{:?} is not a registered seccomp profile",
                p.syscalls.profile
            ),
        ));
    }
    let mut extra_deny = BTreeSet::new();
    for (i, s) in p.syscalls.deny_high_risk.iter().enumerate() {
        if policy_model::syscall_nr(s).is_some() {
            extra_deny.insert(s.clone());
        } else {
            errs.push(Issue::new(
                format!("$.syscalls.deny_high_risk[{i}]"),
                "UNKNOWN_SYSCALL",
                format!("{s:?} is not an x86_64 syscall"),
            ));
        }
    }

    // --- network --------------------------------------------------------
    let mut ports = BTreeSet::new();
    if !p.network.allowed_udp_ports.is_empty() {
        errs.push(Issue::new(
            "$.network.allowed_udp_ports",
            "NETWORK_UNSUPPORTED_PROTOCOL",
            "UDP rules cannot be enforced by Landlock; allowed_udp_ports must be empty",
        ));
    }
    match p.network.mode {
        NetworkMode::None => {
            if !p.network.allowed_tcp_ports.is_empty() {
                errs.push(Issue::new(
                    "$.network.allowed_tcp_ports",
                    "NETWORK_INVALID",
                    "ports may not be listed when network.mode is \"none\"",
                ));
            }
        }
        NetworkMode::TcpPorts => {
            if !d.allow_network {
                errs.push(Issue::new(
                    "$.network.mode",
                    "NETWORK_NOT_PERMITTED",
                    "this deployment does not permit network access",
                ));
            }
            if let Some(abi) = ctx.landlock_abi {
                if abi < LANDLOCK_NET_ABI {
                    errs.push(Issue::new(
                        "$.network.mode",
                        "UNSUPPORTED_LANDLOCK_RIGHT",
                        format!("TCP port rules require Landlock ABI {LANDLOCK_NET_ABI}; kernel provides {abi}"),
                    ));
                }
            }
            if p.network.allowed_tcp_ports.is_empty() {
                errs.push(Issue::new(
                    "$.network.allowed_tcp_ports",
                    "NETWORK_INVALID",
                    "tcp_ports mode requires at least one port",
                ));
            }
            for (i, port) in p.network.allowed_tcp_ports.iter().enumerate() {
                if *port == 0 {
                    errs.push(Issue::new(
                        format!("$.network.allowed_tcp_ports[{i}]"),
                        "NETWORK_INVALID",
                        "port 0 is not a valid TCP port",
                    ));
                } else {
                    ports.insert(*port);
                }
            }
        }
    }

    // --- limits ---------------------------------------------------------
    let max = d.max_limits;
    let mut lim = p.limits;
    {
        let slots: [(&str, &mut u64, u64); 6] = [
            (
                "wall_time_seconds",
                &mut lim.wall_time_seconds,
                max.wall_time_seconds,
            ),
            ("cpu_seconds", &mut lim.cpu_seconds, max.cpu_seconds),
            ("memory_bytes", &mut lim.memory_bytes, max.memory_bytes),
            (
                "file_size_bytes",
                &mut lim.file_size_bytes,
                max.file_size_bytes,
            ),
            ("process_count", &mut lim.process_count, max.process_count),
            ("open_files", &mut lim.open_files, max.open_files),
        ];
        for (name, v, m) in slots {
            let field = format!("$.limits.{name}");
            if *v == 0 {
                errs.push(Issue::new(
                    field,
                    "LIMIT_INVALID",
                    "limit must be greater than zero",
                ));
            } else if *v > m {
                if d.clamp_limits {
                    warnings.push(Issue::new(
                        field,
                        "LIMIT_CLAMPED",
                        format!("{} clamped to deployment maximum {m}", *v),
                    ));
                    *v = m;
                } else {
                    errs.push(Issue::new(
                        field,
                        "LIMIT_EXCEEDS_MAXIMUM",
                        format!("{} exceeds deployment maximum {m}", *v),
                    ));
                }
            }
        }
    }

    // --- approval -------------------------------------------------------
    if !p.approval.required_for_privilege_step_up
        || p.approval.approval_mode != APPROVAL_MODE_NEW_EPOCH
    {
        errs.push(Issue::new(
            "$.approval",
            "APPROVAL_MODE_UNSUPPORTED",
            format!(
                "privilege step-up must require approval with mode {APPROVAL_MODE_NEW_EPOCH:?}"
            ),
        ));
    }

    if !errs.is_empty() {
        return Err(errs);
    }

    // --- normalize ------------------------------------------------------
    p.filesystem.read_only = grants
        .iter()
        .filter(|(_, a)| **a == Access::READ_ONLY)
        .map(|(k, _)| k.clone())
        .collect();
    p.filesystem.read_write = grants
        .iter()
        .filter(|(_, a)| **a == Access::READ_WRITE)
        .map(|(k, _)| k.clone())
        .collect();
    p.filesystem.deny = deny.into_iter().collect();
    p.filesystem.required_rights = std::mem::take(&mut rights).into_iter().collect();
    p.commands.allowed_tool_names = tools.into_iter().collect();
    p.commands.allowed_executables = exes.into_iter().collect();
    p.syscalls.deny_high_risk = extra_deny.into_iter().collect();
    p.network.allowed_tcp_ports = ports.into_iter().collect();
    p.limits = lim;

    let canonical_json = canonical_json(&p);
    let policy_hash = hash_canonical(&canonical_json);
    let permissions = permissions(&p);
    Ok(Validated {
        policy: p,
        canonical_json,
        policy_hash,
        permissions,
        warnings,
    })
}

fn valid_task_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && !id.starts_with('.')
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// Why `path` may not be granted, if it violates a deployment guard rail.
fn guard_violation(path: &str, d: &DeploymentConfig) -> Option<String> {
    if d.device_allowlist.iter().any(|x| x == path) {
        return None;
    }
    if let Some(prot) = d
        .protected_paths
        .iter()
        .find(|prot| paths::is_within(prot, path))
    {
        return Some(format!("granting it would expose protected path {prot:?}"));
    }
    if let Some(sub) = d
        .forbidden_subtrees
        .iter()
        .find(|s| paths::is_within(path, s))
    {
        return Some(format!("it lies inside forbidden subtree {sub:?}"));
    }
    None
}

/// Drop entries already covered by an ancestor granting a superset of access.
fn remove_redundant(grants: BTreeMap<String, Access>) -> BTreeMap<String, Access> {
    grants
        .iter()
        .filter(|(p, a)| {
            !grants
                .iter()
                .any(|(q, b)| q != *p && paths::is_within(p, q) && b.contains(**a))
        })
        .map(|(p, a)| (p.clone(), *a))
        .collect()
}

/// Canonical JSON: normalized policy serialized with lexicographically sorted keys.
pub fn canonical_json(p: &Policy) -> String {
    // serde_json::Value uses a BTreeMap (the `preserve_order` feature is not
    // enabled), so object keys come out sorted.
    let v = serde_json::to_value(p).expect("policy serializes");
    serde_json::to_string(&v).expect("value serializes")
}

pub fn hash_canonical(canonical: &str) -> String {
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(canonical.as_bytes()))
    )
}

/// Derive the normalized permission set from a *normalized* policy.
pub fn permissions(p: &Policy) -> PermissionSet {
    let mut fs = BTreeMap::new();
    for x in &p.filesystem.read_only {
        fs.insert(x.clone(), Access::READ_ONLY);
    }
    for x in &p.filesystem.read_write {
        fs.insert(x.clone(), Access::READ_WRITE);
    }
    let mut denied: BTreeSet<String> = profile(&p.syscalls.profile)
        .map(|pr| pr.denied().into_iter().map(String::from).collect())
        .unwrap_or_default();
    denied.extend(p.syscalls.deny_high_risk.iter().cloned());
    PermissionSet {
        fs,
        tools: p.commands.allowed_tool_names.iter().cloned().collect(),
        executables: p.commands.allowed_executables.iter().cloned().collect(),
        shell: p.commands.shell == ShellMode::Allow,
        denied_syscalls: denied,
        tcp_ports: match p.network.mode {
            NetworkMode::None => None,
            NetworkMode::TcpPorts => Some(p.network.allowed_tcp_ports.iter().copied().collect()),
        },
        limits: p.limits,
    }
}
