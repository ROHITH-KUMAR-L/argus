//! Versioned wire protocol between the Python controller and `ratchetd`.
//!
//! See `docs/protocol.md`. Framing is a 4-byte big-endian length followed by
//! a JSON object. Unknown fields are rejected everywhere.

use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

pub const PROTOCOL_VERSION: &str = "1";
pub const MAX_FRAME_BYTES: usize = 1024 * 1024;

/// Error codes returned to the controller. Any error means "no grant".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    MalformedRequest,
    UnsupportedProtocolVersion,
    ReplayedRequest,
    FrameTooLarge,
    UnknownMethod,
    UnknownTask,
    TaskExists,
    EpochClosed,
    StaleEpoch,
    StalePolicyHash,
    PolicyValidationFailed,
    PrivilegeExpansionDenied,
    UnknownExpansion,
    MethodNotPermittedOnSocket,
    StateStoreUnavailable,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol_version: String,
    pub request_id: String,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorBody {
    pub code: ErrorCode,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<serde_json::Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Response {
    pub protocol_version: String,
    pub request_id: String,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorBody>,
}

impl Response {
    pub fn ok(request_id: &str, result: serde_json::Value) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.into(),
            request_id: request_id.into(),
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    pub fn err(request_id: &str, code: ErrorCode, message: impl Into<String>) -> Self {
        Self::err_detail(request_id, code, message, None)
    }

    pub fn err_detail(
        request_id: &str,
        code: ErrorCode,
        message: impl Into<String>,
        detail: Option<serde_json::Value>,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION.into(),
            request_id: request_id.into(),
            ok: false,
            result: None,
            error: Some(ErrorBody {
                code,
                message: message.into(),
                detail,
            }),
        }
    }
}

/// `request_id` must be 8..=64 chars of `[A-Za-z0-9_-]`.
pub fn valid_request_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("io: {0}")]
    Io(#[from] io::Error),
    #[error("frame of {0} bytes exceeds limit")]
    TooLarge(usize),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
}

/// Read one length-prefixed frame. Returns `Ok(None)` on clean EOF before a header.
pub fn read_frame<R: Read>(r: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut hdr = [0u8; 4];
    match r.read_exact(&mut hdr) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let len = u32::from_be_bytes(hdr) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)?;
    Ok(Some(buf))
}

pub fn write_frame<W: Write>(w: &mut W, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(FrameError::TooLarge(payload.len()));
    }
    w.write_all(&(payload.len() as u32).to_be_bytes())?;
    w.write_all(payload)?;
    w.flush()?;
    Ok(())
}

pub fn write_json<W: Write, T: Serialize>(w: &mut W, v: &T) -> Result<(), FrameError> {
    let bytes = serde_json::to_vec(v)?;
    write_frame(w, &bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_roundtrip() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"{\"a\":1}").unwrap();
        let mut cur = io::Cursor::new(buf);
        assert_eq!(read_frame(&mut cur).unwrap().unwrap(), b"{\"a\":1}");
        assert!(read_frame(&mut cur).unwrap().is_none());
    }

    #[test]
    fn oversized_frame_rejected() {
        let hdr = ((MAX_FRAME_BYTES + 1) as u32).to_be_bytes();
        let mut cur = io::Cursor::new(hdr.to_vec());
        assert!(matches!(read_frame(&mut cur), Err(FrameError::TooLarge(_))));
    }

    #[test]
    fn request_rejects_unknown_fields() {
        let raw = r#"{"protocol_version":"1","request_id":"abcdefgh","method":"health","params":{},"grant":"all"}"#;
        assert!(serde_json::from_str::<Request>(raw).is_err());
    }

    #[test]
    fn request_id_rules() {
        assert!(valid_request_id("abcd-1234"));
        assert!(!valid_request_id("short"));
        assert!(!valid_request_id("has space!"));
        assert!(!valid_request_id(&"a".repeat(65)));
    }

    #[test]
    fn error_codes_serialize_screaming() {
        let s = serde_json::to_string(&ErrorCode::PrivilegeExpansionDenied).unwrap();
        assert_eq!(s, "\"PRIVILEGE_EXPANSION_DENIED\"");
    }
}
