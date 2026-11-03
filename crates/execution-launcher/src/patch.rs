//! Strict unified-diff application for a single file (no fuzz).

#[derive(Debug)]
struct Hunk {
    old_start: usize,
    old: Vec<String>,
    new: Vec<String>,
}

fn parse_range(s: &str) -> Option<usize> {
    let s = s.trim_start_matches(['-', '+']);
    s.split(',').next()?.parse().ok()
}

fn parse(patch: &str) -> Result<Vec<Hunk>, String> {
    let mut hunks = Vec::new();
    let mut cur: Option<Hunk> = None;
    for line in patch.lines() {
        if line.starts_with("--- ")
            || line.starts_with("+++ ")
            || line.starts_with("diff ")
            || line.starts_with("index ")
        {
            continue;
        }
        if let Some(rest) = line.strip_prefix("@@ ") {
            if let Some(h) = cur.take() {
                hunks.push(h);
            }
            let mut parts = rest.split_whitespace();
            let old = parts
                .next()
                .and_then(parse_range)
                .ok_or("malformed hunk header")?;
            cur = Some(Hunk {
                old_start: old,
                old: Vec::new(),
                new: Vec::new(),
            });
            continue;
        }
        if line.starts_with('\\') {
            continue; // "\ No newline at end of file"
        }
        let h = cur
            .as_mut()
            .ok_or("patch content before first hunk header")?;
        if let Some(t) = line.strip_prefix(' ') {
            h.old.push(t.into());
            h.new.push(t.into());
        } else if let Some(t) = line.strip_prefix('-') {
            h.old.push(t.into());
        } else if let Some(t) = line.strip_prefix('+') {
            h.new.push(t.into());
        } else if line.is_empty() {
            h.old.push(String::new());
            h.new.push(String::new());
        } else {
            return Err(format!("unexpected patch line: {line:?}"));
        }
    }
    if let Some(h) = cur.take() {
        hunks.push(h);
    }
    if hunks.is_empty() {
        return Err("patch contains no hunks".into());
    }
    Ok(hunks)
}

/// Apply `patch` to `original`. Each hunk must match exactly, at its stated
/// position or (if lines shifted) at a unique location after the previous hunk.
pub fn apply(original: &str, patch: &str) -> Result<String, String> {
    let hunks = parse(patch)?;
    let trailing_nl = original.is_empty() || original.ends_with('\n');
    let mut lines: Vec<String> = original.lines().map(String::from).collect();
    let mut offset: isize = 0;
    let mut min_pos = 0usize;
    for (i, h) in hunks.iter().enumerate() {
        let want = (h.old_start.saturating_sub(1) as isize + offset).max(0) as usize;
        let matches_at = |pos: usize| {
            pos + h.old.len() <= lines.len() && lines[pos..pos + h.old.len()] == h.old[..]
        };
        let pos = if h.old.is_empty() {
            want.min(lines.len())
        } else if want >= min_pos && matches_at(want) {
            want
        } else {
            let found: Vec<usize> = (min_pos..=lines.len().saturating_sub(h.old.len()))
                .filter(|p| matches_at(*p))
                .collect();
            match found.as_slice() {
                [p] => *p,
                [] => return Err(format!("hunk {} does not apply", i + 1)),
                _ => return Err(format!("hunk {} matches ambiguously", i + 1)),
            }
        };
        lines.splice(pos..pos + h.old.len(), h.new.iter().cloned());
        offset += h.new.len() as isize - h.old.len() as isize;
        min_pos = pos + h.new.len();
    }
    let mut out = lines.join("\n");
    if trailing_nl && !out.is_empty() {
        out.push('\n');
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::apply;

    #[test]
    fn simple_and_shifted() {
        let orig = "a\nb\nc\nd\n";
        let p = "--- a/x\n+++ b/x\n@@ -2,2 +2,2 @@\n b\n-c\n+C\n";
        assert_eq!(apply(orig, p).unwrap(), "a\nb\nC\nd\n");
        // Stated line numbers are off; unique context still applies.
        let p2 = "@@ -9,2 +9,3 @@\n c\n+c2\n d\n";
        assert_eq!(apply(orig, p2).unwrap(), "a\nb\nc\nc2\nd\n");
    }

    #[test]
    fn create_new_file() {
        assert_eq!(apply("", "@@ -0,0 +1,2 @@\n+x\n+y\n").unwrap(), "x\ny\n");
    }

    #[test]
    fn rejects_mismatch_and_ambiguity() {
        assert!(apply("a\nb\n", "@@ -1,1 +1,1 @@\n-z\n+y\n").is_err());
        assert!(apply("x\nx\n", "@@ -5,1 +5,1 @@\n-x\n+y\n").is_err());
        assert!(apply("a\n", "not a patch").is_err());
    }
}
