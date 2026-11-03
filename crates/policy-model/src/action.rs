//! Planner-proposed actions (untrusted input) and the resolved worker dispatch
//! that `ratchetd` emits after an `ALLOW` decision.

use serde::{Deserialize, Serialize};

pub const MAX_ARGV: usize = 256;
pub const MAX_ARG_BYTES: usize = 4096;
pub const MAX_CONTENT_BYTES: usize = 512 * 1024;
pub const MAX_ID_LEN: usize = 64;

/// A tool-broker action as proposed by the planner. Paths are relative to the
/// task workspace; executables are absolute catalog paths; argv is an array.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    ListFiles {
        #[serde(default)]
        path: String,
    },
    ReadFile {
        path: String,
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        length: Option<u64>,
    },
    WriteFile {
        path: String,
        content: String,
    },
    ApplyPatch {
        path: String,
        patch: String,
    },
    RunCommand {
        executable: String,
        argv: Vec<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        timeout_seconds: Option<u64>,
    },
    RunTests {
        target: String,
    },
    RequestPermission {
        reason: String,
        #[serde(default)]
        add_read_only: Vec<String>,
        #[serde(default)]
        add_read_write: Vec<String>,
        #[serde(default)]
        add_executables: Vec<String>,
        #[serde(default)]
        add_tools: Vec<String>,
    },
}

impl Action {
    /// The broker tool name this action requires.
    pub fn tool_name(&self) -> &'static str {
        match self {
            Action::ListFiles { .. } => "list_files",
            Action::ReadFile { .. } => "read_file",
            Action::WriteFile { .. } => "write_file",
            Action::ApplyPatch { .. } => "apply_patch",
            Action::RunCommand { .. } => "run_command",
            Action::RunTests { .. } => "run_tests",
            Action::RequestPermission { .. } => "request_permission",
        }
    }
}

/// A fully resolved operation for the worker: absolute paths, concrete argv.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Operation {
    ListFiles {
        path: String,
    },
    ReadFile {
        path: String,
        offset: u64,
        length: u64,
    },
    WriteFile {
        path: String,
        content: String,
    },
    ApplyPatch {
        path: String,
        patch: String,
    },
    Exec {
        argv: Vec<String>,
        cwd: String,
        timeout_seconds: u64,
    },
}

/// What the confined worker must enforce for this operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confinement {
    /// B0: no project Landlock/seccomp (outer Docker boundary only).
    None,
    /// B1 / P1: install Landlock + seccomp from the policy; fail closed.
    Kernel,
}

/// Worker request (stdin of `argus-worker`). Produced only by `ratchetd`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkerRequest {
    pub request_version: String,
    pub run_id: String,
    pub task_id: String,
    pub epoch: u64,
    pub epoch_id: String,
    pub action_id: String,
    pub arm: String,
    pub confinement: Confinement,
    pub policy_hash: String,
    /// Canonical policy JSON; the worker re-hashes it and must match `policy_hash`.
    pub canonical_policy: String,
    pub operation: Operation,
}

pub const WORKER_REQUEST_VERSION: &str = "1.0";

/// `[A-Za-z0-9._:-]{1,64}` identifiers (action ids, run ids).
pub fn valid_id(id: &str) -> bool {
    (1..=MAX_ID_LEN).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-' | b':'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_rejects_unknown_fields_and_types() {
        let ok = r#"{"type":"read_file","path":"src/a.py"}"#;
        assert!(serde_json::from_str::<Action>(ok).is_ok());
        for bad in [
            r#"{"type":"read_file","path":"a","sudo":true}"#,
            r#"{"type":"shell","cmd":"rm -rf /"}"#,
            r#"{"type":"run_command","executable":"/usr/bin/sh","argv":"sh -c id"}"#,
            r#"{"path":"a"}"#,
        ] {
            assert!(serde_json::from_str::<Action>(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn ids() {
        assert!(valid_id("action-004"));
        assert!(valid_id("task-1:e2"));
        assert!(!valid_id(""));
        assert!(!valid_id("a b"));
        assert!(!valid_id(&"x".repeat(65)));
    }
}
