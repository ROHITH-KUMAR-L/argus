//! Built-in file operations. They run in a child process that has the same
//! rlimits and kernel confinement as any task command (`argus-worker --file-op`).

use policy_model::Operation;
use serde::Serialize;
use serde_json::{json, Value};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

const MAX_LIST_ENTRIES: usize = 2000;
const MAX_LIST_DEPTH: usize = 8;

#[derive(Debug, Serialize)]
pub struct FileOpResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Value::is_null")]
    pub data: Value,
}

fn ok(data: Value) -> FileOpResult {
    FileOpResult {
        ok: true,
        error_kind: None,
        message: None,
        data,
    }
}

fn fail(kind: &'static str, msg: impl Into<String>) -> FileOpResult {
    FileOpResult {
        ok: false,
        error_kind: Some(kind),
        message: Some(msg.into()),
        data: Value::Null,
    }
}

fn io_fail(e: &io::Error, what: &str) -> FileOpResult {
    let kind = match e.raw_os_error() {
        Some(libc::EACCES) | Some(libc::EPERM) => "permission_denied",
        Some(libc::ENOENT) => "not_found",
        Some(libc::ELOOP) => "is_symlink",
        Some(libc::EFBIG) => "file_too_large",
        _ => "io",
    };
    fail(kind, format!("{what}: {e}"))
}

fn list(root: &Path) -> FileOpResult {
    let mut entries = Vec::new();
    let mut truncated = false;
    let mut stack = vec![(root.to_path_buf(), 0usize)];
    if let Err(e) = fs::symlink_metadata(root) {
        return io_fail(&e, "list");
    }
    while let Some((dir, depth)) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if dir == root => return io_fail(&e, "list"),
            Err(_) => continue,
        };
        let mut items: Vec<_> = rd.flatten().collect();
        items.sort_by_key(|e| e.file_name());
        for e in items {
            if entries.len() >= MAX_LIST_ENTRIES {
                truncated = true;
                break;
            }
            let Ok(m) = fs::symlink_metadata(e.path()) else {
                continue;
            };
            let rel = e
                .path()
                .strip_prefix(root)
                .unwrap_or(&e.path())
                .to_string_lossy()
                .to_string();
            let kind = if m.file_type().is_symlink() {
                "symlink"
            } else if m.is_dir() {
                "dir"
            } else if m.is_file() {
                "file"
            } else {
                "other"
            };
            entries.push(json!({"path": rel, "type": kind, "size": m.len()}));
            if m.is_dir() && depth + 1 < MAX_LIST_DEPTH {
                stack.push((e.path(), depth + 1));
            }
        }
    }
    entries.sort_by(|a, b| a["path"].as_str().cmp(&b["path"].as_str()));
    ok(json!({"entries": entries, "truncated": truncated}))
}

fn read(path: &Path, offset: u64, length: u64) -> FileOpResult {
    let mut f = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(f) => f,
        Err(e) => return io_fail(&e, "open"),
    };
    let m = match f.metadata() {
        Ok(m) => m,
        Err(e) => return io_fail(&e, "stat"),
    };
    if !m.is_file() {
        return fail("not_regular", "not a regular file");
    }
    if let Err(e) = f.seek(SeekFrom::Start(offset)) {
        return io_fail(&e, "seek");
    }
    let mut buf = Vec::new();
    if let Err(e) = (&mut f).take(length).read_to_end(&mut buf) {
        return io_fail(&e, "read");
    }
    let truncated = offset + (buf.len() as u64) < m.len();
    match String::from_utf8(buf) {
        Ok(text) => {
            ok(json!({"content": text, "size": m.len(), "offset": offset, "truncated": truncated}))
        }
        Err(_) => fail("binary", "file is not valid UTF-8"),
    }
}

fn write_all(path: &Path, content: &str) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o644)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    if !f.metadata()?.is_file() {
        return Err(io::Error::other("not a regular file"));
    }
    f.write_all(content.as_bytes())?;
    f.set_permissions(fs::Permissions::from_mode(0o644))?;
    Ok(())
}

pub fn perform(op: &Operation) -> FileOpResult {
    match op {
        Operation::ListFiles { path } => list(Path::new(path)),
        Operation::ReadFile {
            path,
            offset,
            length,
        } => read(Path::new(path), *offset, *length),
        Operation::WriteFile { path, content } => match write_all(Path::new(path), content) {
            Ok(()) => ok(json!({"bytes_written": content.len()})),
            Err(e) => io_fail(&e, "write"),
        },
        Operation::ApplyPatch { path, patch } => {
            let p = Path::new(path);
            let original = match read(p, 0, u64::MAX) {
                FileOpResult { ok: true, data, .. } => {
                    data["content"].as_str().unwrap_or("").to_string()
                }
                FileOpResult {
                    error_kind: Some("not_found"),
                    ..
                } => String::new(),
                other => return other,
            };
            match crate::patch::apply(&original, patch) {
                Ok(updated) => match write_all(p, &updated) {
                    Ok(()) => ok(json!({"bytes_written": updated.len()})),
                    Err(e) => io_fail(&e, "write"),
                },
                Err(e) => fail("patch_failed", e),
            }
        }
        Operation::Exec { .. } => fail("invalid", "exec is not a file operation"),
    }
}
