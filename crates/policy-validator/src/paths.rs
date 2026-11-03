//! Lexical path normalization and containment.
//!
//! Policy paths name locations *inside the worker container*, so they are never
//! resolved against the host filesystem. They must already be in canonical
//! form: absolute, no empty / `.` / `..` components, no trailing slash, no
//! percent-encoding or backslashes. Anything else is rejected rather than
//! "fixed", so that a policy author cannot be surprised by a rewrite that
//! widens access. Symlinks inside the container are handled at enforcement time
//! (Landlock resolves the real path; the launcher opens rule roots without
//! following symlinks).

use std::fmt;

pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_COMPONENT_LEN: usize = 255;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    Empty,
    NotAbsolute,
    TooLong,
    ComponentTooLong,
    EmptyComponent,
    DotComponent,
    Traversal,
    TrailingSlash,
    ForbiddenChar(char),
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::Empty => write!(f, "path is empty"),
            PathError::NotAbsolute => write!(f, "path must be absolute"),
            PathError::TooLong => write!(f, "path exceeds {MAX_PATH_LEN} bytes"),
            PathError::ComponentTooLong => {
                write!(f, "path component exceeds {MAX_COMPONENT_LEN} bytes")
            }
            PathError::EmptyComponent => write!(f, "path contains an empty component (//)"),
            PathError::DotComponent => write!(f, "path contains a '.' component"),
            PathError::Traversal => write!(f, "path contains a '..' component"),
            PathError::TrailingSlash => write!(f, "path has a trailing slash"),
            PathError::ForbiddenChar(c) => write!(f, "path contains forbidden character {c:?}"),
        }
    }
}

impl PathError {
    pub fn code(&self) -> &'static str {
        match self {
            PathError::Traversal | PathError::DotComponent => "PATH_TRAVERSAL",
            PathError::ForbiddenChar('%') | PathError::ForbiddenChar('\\') => "PATH_TRAVERSAL",
            _ => "PATH_INVALID",
        }
    }
}

/// Check that `p` is a canonical absolute path. Returns it unchanged on success.
pub fn check_absolute(p: &str) -> Result<&str, PathError> {
    if p.is_empty() {
        return Err(PathError::Empty);
    }
    if p.len() > MAX_PATH_LEN {
        return Err(PathError::TooLong);
    }
    for c in p.chars() {
        if c == '\0' || c == '%' || c == '\\' || c.is_control() {
            return Err(PathError::ForbiddenChar(c));
        }
    }
    if !p.starts_with('/') {
        return Err(PathError::NotAbsolute);
    }
    if p == "/" {
        return Ok(p);
    }
    if p.ends_with('/') {
        return Err(PathError::TrailingSlash);
    }
    for comp in p[1..].split('/') {
        match comp {
            "" => return Err(PathError::EmptyComponent),
            "." => return Err(PathError::DotComponent),
            ".." => return Err(PathError::Traversal),
            c if c.len() > MAX_COMPONENT_LEN => return Err(PathError::ComponentTooLong),
            _ => {}
        }
    }
    Ok(p)
}

/// Component-wise containment: `child` equals `parent` or lies beneath it.
/// `/workspace/app` does **not** contain `/workspace/application` (POL-009).
/// Both arguments must already be canonical (see [`check_absolute`]).
pub fn is_within(child: &str, parent: &str) -> bool {
    if parent == "/" {
        return child.starts_with('/');
    }
    child == parent
        || (child.len() > parent.len()
            && child.starts_with(parent)
            && child.as_bytes()[parent.len()] == b'/')
}

/// True when either path contains the other.
pub fn overlaps(a: &str, b: &str) -> bool {
    is_within(a, b) || is_within(b, a)
}

/// Resolve a planner-supplied *relative* path against the workspace, lexically.
/// Rejects absolute paths, `..`, `.`, empty components and forbidden characters,
/// so the result is always strictly inside `workspace`.
pub fn resolve_relative(workspace: &str, rel: &str) -> Result<String, PathError> {
    if rel.is_empty() {
        return Err(PathError::Empty);
    }
    if rel.starts_with('/') {
        return Err(PathError::Traversal);
    }
    let joined = format!("{}/{}", workspace.trim_end_matches('/'), rel);
    check_absolute(&joined)?;
    debug_assert!(is_within(&joined, workspace));
    Ok(joined)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_paths_accepted() {
        for p in ["/", "/usr", "/workspace/task", "/a/b-c_d.e"] {
            assert_eq!(check_absolute(p), Ok(p));
        }
    }

    #[test]
    fn non_canonical_paths_rejected() {
        let cases = [
            ("", PathError::Empty),
            ("usr", PathError::NotAbsolute),
            ("/usr/", PathError::TrailingSlash),
            ("//usr", PathError::EmptyComponent),
            ("/usr//lib", PathError::EmptyComponent),
            ("/usr/./lib", PathError::DotComponent),
            ("/workspace/../etc", PathError::Traversal),
            ("/workspace/..", PathError::Traversal),
            ("/workspace/%2e%2e/etc", PathError::ForbiddenChar('%')),
            ("/workspace\\..\\etc", PathError::ForbiddenChar('\\')),
            ("/a\0b", PathError::ForbiddenChar('\0')),
            ("/a\nb", PathError::ForbiddenChar('\n')),
        ];
        for (p, want) in cases {
            assert_eq!(check_absolute(p), Err(want), "{p:?}");
        }
        assert_eq!(
            check_absolute(&format!("/{}", "a".repeat(256))),
            Err(PathError::ComponentTooLong)
        );
    }

    #[test]
    fn prefix_confusion_pol_009() {
        assert!(!is_within("/workspace/application", "/workspace/app"));
        assert!(!is_within("/workspace/app", "/workspace/application"));
        assert!(is_within("/workspace/app/x", "/workspace/app"));
        assert!(is_within("/workspace/app", "/workspace/app"));
        assert!(is_within("/anything", "/"));
        assert!(!is_within("/", "/workspace"));
    }

    #[test]
    fn relative_resolution_stays_inside() {
        assert_eq!(
            resolve_relative("/workspace/task", "src/a.py").unwrap(),
            "/workspace/task/src/a.py"
        );
        for bad in [
            "/etc/passwd",
            "../secrets",
            "src/../../x",
            "./a",
            "a//b",
            "",
            "a/%2e%2e/b",
        ] {
            assert!(resolve_relative("/workspace/task", bad).is_err(), "{bad:?}");
        }
    }
}
