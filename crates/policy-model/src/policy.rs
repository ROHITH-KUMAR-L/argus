//! Task policy document (schema version 1.0). Mirrors `schemas/policy.schema.json`.

use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: String,
    pub task_id: String,
    #[serde(default)]
    pub description: String,
    pub workspace: String,
    pub filesystem: Filesystem,
    pub commands: Commands,
    pub syscalls: Syscalls,
    pub network: Network,
    pub limits: Limits,
    pub approval: Approval,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Filesystem {
    /// Hierarchies granted read + execute.
    pub read_only: Vec<String>,
    /// Hierarchies granted read + write + execute.
    pub read_write: Vec<String>,
    /// Explicit deny intent. Must not overlap any allowed hierarchy (Landlock is allow-only).
    #[serde(default)]
    pub deny: Vec<String>,
    /// Landlock rights that must be *handled* (enforced) by the running ABI, else reject.
    #[serde(default)]
    pub required_rights: Vec<FsRight>,
}

/// Landlock filesystem access rights, by the ABI version that introduced them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FsRight {
    Execute,
    WriteFile,
    ReadFile,
    ReadDir,
    RemoveDir,
    RemoveFile,
    MakeChar,
    MakeDir,
    MakeReg,
    MakeSock,
    MakeFifo,
    MakeBlock,
    MakeSym,
    Refer,
    Truncate,
    IoctlDev,
}

impl FsRight {
    pub fn min_abi(self) -> u32 {
        match self {
            FsRight::Refer => 2,
            FsRight::Truncate => 3,
            FsRight::IoctlDev => 5,
            _ => 1,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellMode {
    Deny,
    Allow,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commands {
    pub allowed_tool_names: Vec<String>,
    pub allowed_executables: Vec<String>,
    pub shell: ShellMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Syscalls {
    pub profile: String,
    /// Additional denials layered on top of the profile.
    #[serde(default)]
    pub deny_high_risk: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// No network (Docker `network none`, no Landlock port grants).
    None,
    /// Landlock TCP port grants (ABI >= 4). UDP is not supported by Landlock.
    TcpPorts,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    pub mode: NetworkMode,
    #[serde(default)]
    pub allowed_tcp_ports: Vec<u16>,
    /// Must be empty: Landlock cannot enforce UDP rules.
    #[serde(default)]
    pub allowed_udp_ports: Vec<u16>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub wall_time_seconds: u64,
    pub cpu_seconds: u64,
    pub memory_bytes: u64,
    pub file_size_bytes: u64,
    pub process_count: u64,
    pub open_files: u64,
}

impl Limits {
    /// (field name, value) pairs in a fixed order.
    pub fn fields(&self) -> [(&'static str, u64); 6] {
        [
            ("wall_time_seconds", self.wall_time_seconds),
            ("cpu_seconds", self.cpu_seconds),
            ("memory_bytes", self.memory_bytes),
            ("file_size_bytes", self.file_size_bytes),
            ("process_count", self.process_count),
            ("open_files", self.open_files),
        ]
    }

    /// True when every ceiling in `self` is <= the matching ceiling in `other`.
    pub fn le(&self, other: &Limits) -> bool {
        self.fields()
            .iter()
            .zip(other.fields().iter())
            .all(|((_, a), (_, b))| a <= b)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Approval {
    pub required_for_privilege_step_up: bool,
    pub approval_mode: String,
}

pub const APPROVAL_MODE_NEW_EPOCH: &str = "new_execution_epoch";
