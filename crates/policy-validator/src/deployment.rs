//! Deployment-level guard rails that no task policy may exceed.

use policy_model::Limits;
use serde::{Deserialize, Serialize};

/// Built-in deployment configuration for the reference worker image.
pub const DEFAULT_DEPLOYMENT_JSON: &str = include_str!("../deployment.default.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentConfig {
    pub deployment_version: String,
    /// The one workspace path every policy must use.
    pub workspace_path: String,
    /// `read_write` paths must lie within one of these.
    pub writable_roots: Vec<String>,
    /// An allowed path may not equal or contain any of these.
    pub protected_paths: Vec<String>,
    /// An allowed path may not lie beneath any of these (except `device_allowlist`).
    pub forbidden_subtrees: Vec<String>,
    /// Exact device paths that may be granted despite `/dev` being forbidden.
    pub device_allowlist: Vec<String>,
    pub max_limits: Limits,
    /// When true, over-maximum limits are clamped with a warning instead of rejected.
    pub clamp_limits: bool,
    /// Whether any network mode other than `none` may be requested.
    pub allow_network: bool,
    pub tool_names: Vec<String>,
    pub executables: Vec<String>,
    /// Executables that count as shells (only permitted when `commands.shell = allow`).
    pub shell_executables: Vec<String>,
    pub max_list_entries: usize,
    pub max_description_len: usize,
}

impl DeploymentConfig {
    pub fn builtin() -> Self {
        serde_json::from_str(DEFAULT_DEPLOYMENT_JSON).expect("built-in deployment config is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paths::check_absolute;

    #[test]
    fn builtin_parses_and_paths_are_canonical() {
        let d = DeploymentConfig::builtin();
        let all = [
            std::slice::from_ref(&d.workspace_path),
            &d.writable_roots,
            &d.protected_paths,
            &d.forbidden_subtrees,
            &d.device_allowlist,
            &d.executables,
            &d.shell_executables,
        ];
        for p in all.into_iter().flatten() {
            check_absolute(p).unwrap_or_else(|e| panic!("{p}: {e}"));
        }
        for s in &d.shell_executables {
            assert!(
                d.executables.contains(s),
                "shell {s} must be in the executable catalog"
            );
        }
    }
}
