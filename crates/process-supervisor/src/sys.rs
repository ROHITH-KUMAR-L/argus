//! libc wrappers used by the supervisor. All `unsafe` in this crate lives here.
#![allow(unsafe_code)]

use std::io;

pub fn getpid() -> i32 {
    // SAFETY: no preconditions.
    unsafe { libc::getpid() }
}

/// Make this process a child subreaper so orphaned descendants are reparented to it.
pub fn set_child_subreaper() -> io::Result<()> {
    // SAFETY: PR_SET_CHILD_SUBREAPER takes an integer flag; no pointers.
    let rc = unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Send `sig` to `pid` (negative = process group). Errors are ignored by callers.
pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
    // SAFETY: kill has no memory-safety preconditions.
    let rc = unsafe { libc::kill(pid, sig) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

pub enum Reaped {
    Exited,
    NoChildren,
    None,
}

/// Non-blocking reap of any child.
pub fn reap_any() -> Reaped {
    let mut status = 0;
    // SAFETY: `status` is a valid out-pointer.
    let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
    if pid > 0 {
        Reaped::Exited
    } else if pid == 0 {
        Reaped::None
    } else {
        Reaped::NoChildren
    }
}

pub struct Usage {
    pub max_rss_bytes: u64,
    pub cpu_seconds: f64,
}

/// Cumulative usage of all reaped children of this process.
pub fn children_usage() -> Usage {
    // SAFETY: zeroed rusage is a valid value; getrusage fills it.
    let mut ru: libc::rusage = unsafe { std::mem::zeroed() };
    // SAFETY: `ru` is a valid out-pointer.
    unsafe { libc::getrusage(libc::RUSAGE_CHILDREN, &mut ru) };
    let t = |tv: libc::timeval| tv.tv_sec as f64 + tv.tv_usec as f64 / 1e6;
    Usage {
        max_rss_bytes: (ru.ru_maxrss as u64) * 1024,
        cpu_seconds: t(ru.ru_utime) + t(ru.ru_stime),
    }
}

pub fn setrlimit(resource: libc::__rlimit_resource_t, soft: u64, hard: u64) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `lim` is a valid rlimit struct.
    let rc = unsafe { libc::setrlimit(resource, &lim) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
