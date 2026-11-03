//! Append-only, hash-chained, write-ahead op log.

use privilege_ratchet::{Engine, Op};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

pub const LOG_VERSION: u32 = 1;
const GENESIS: &str = "sha256:genesis";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Header {
    pub log_version: u32,
    pub arm: String,
    pub deployment_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Record {
    seq: u64,
    at: u64,
    prev: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<Header>,
    #[serde(skip_serializing_if = "Option::is_none")]
    op: Option<Op>,
    hash: String,
}

fn record_hash(seq: u64, at: u64, prev: &str, body: &str) -> String {
    let mut h = Sha256::new();
    h.update(format!("{seq}\n{at}\n{prev}\n{body}").as_bytes());
    format!("sha256:{}", hex::encode(h.finalize()))
}

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("state log corrupt at line {line}: {why}")]
    Corrupt { line: usize, why: String },
    #[error("state log was written under a different configuration: {0}")]
    ConfigMismatch(String),
}

pub struct Store {
    path: PathBuf,
    file: File,
    next_seq: u64,
    last_hash: String,
}

impl Store {
    /// Open (creating if absent) and replay into `engine`. Any inconsistency is fatal.
    pub fn open(dir: &Path, header: &Header, engine: &mut Engine) -> Result<Self, StoreError> {
        let path = dir.join("ratchet.log");
        let exists = path.exists();
        let mut next_seq = 0;
        let mut last_hash = GENESIS.to_string();

        if exists {
            let meta = std::fs::metadata(&path)?;
            if meta.permissions().mode() & 0o077 != 0 {
                return Err(StoreError::Corrupt {
                    line: 0,
                    why: "log file is accessible by group/other".into(),
                });
            }
            let reader = BufReader::new(File::open(&path)?);
            let raw = std::fs::read(&path)?;
            if !raw.is_empty() && raw.last() != Some(&b'\n') {
                return Err(StoreError::Corrupt {
                    line: raw.iter().filter(|b| **b == b'\n').count() + 1,
                    why: "truncated final record".into(),
                });
            }
            for (i, line) in reader.lines().enumerate() {
                let line = line?;
                let corrupt = |why: String| StoreError::Corrupt { line: i + 1, why };
                let rec: Record =
                    serde_json::from_str(&line).map_err(|e| corrupt(e.to_string()))?;
                if rec.seq != next_seq {
                    return Err(corrupt(format!(
                        "expected seq {next_seq}, found {}",
                        rec.seq
                    )));
                }
                if rec.prev != last_hash {
                    return Err(corrupt("hash chain broken".into()));
                }
                let body = match (&rec.header, &rec.op) {
                    (Some(h), None) if rec.seq == 0 => serde_json::to_string(h).expect("header"),
                    (None, Some(op)) if rec.seq > 0 => serde_json::to_string(op).expect("op"),
                    _ => return Err(corrupt("record must be a header (seq 0) or an op".into())),
                };
                if record_hash(rec.seq, rec.at, &rec.prev, &body) != rec.hash {
                    return Err(corrupt("record hash mismatch".into()));
                }
                if let Some(h) = &rec.header {
                    if h != header {
                        return Err(StoreError::ConfigMismatch(format!(
                            "log has {h:?}, daemon runs with {header:?}"
                        )));
                    }
                }
                if let Some(op) = &rec.op {
                    // Results are deterministic; rejections were rejections then too.
                    let _ = engine.apply(op, rec.at);
                }
                next_seq += 1;
                last_hash = rec.hash;
            }
            if next_seq == 0 {
                return Err(StoreError::Corrupt {
                    line: 0,
                    why: "empty log (missing header)".into(),
                });
            }
        }

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        let mut store = Store {
            path,
            file,
            next_seq,
            last_hash,
        };
        if !exists {
            store.append_raw(Some(header.clone()), None, 0)?;
        }
        Ok(store)
    }

    fn append_raw(
        &mut self,
        header: Option<Header>,
        op: Option<Op>,
        at: u64,
    ) -> Result<(), StoreError> {
        let body = match (&header, &op) {
            (Some(h), None) => serde_json::to_string(h).expect("header"),
            (None, Some(o)) => serde_json::to_string(o).expect("op"),
            _ => unreachable!("exactly one of header/op"),
        };
        let hash = record_hash(self.next_seq, at, &self.last_hash, &body);
        let rec = Record {
            seq: self.next_seq,
            at,
            prev: self.last_hash.clone(),
            header,
            op,
            hash: hash.clone(),
        };
        let mut line = serde_json::to_string(&rec).expect("record");
        line.push('\n');
        self.file.write_all(line.as_bytes())?;
        self.file.sync_data()?;
        self.next_seq += 1;
        self.last_hash = hash;
        Ok(())
    }

    /// Durably append an op. Must succeed before the op is applied.
    pub fn append(&mut self, op: &Op, at: u64) -> Result<(), StoreError> {
        self.append_raw(None, Some(op.clone()), at)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}
