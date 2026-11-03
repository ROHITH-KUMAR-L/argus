//! The only `unsafe` in ratchetd: small libc wrappers with documented invariants.
#![allow(unsafe_code)]

use std::io;
use std::os::fd::AsRawFd;

/// Set the process umask (always succeeds).
pub fn set_umask(mask: libc::mode_t) {
    // SAFETY: umask has no memory-safety preconditions.
    unsafe {
        libc::umask(mask);
    }
}

pub fn geteuid() -> u32 {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

/// UID of the peer connected to a Unix stream socket (SO_PEERCRED).
pub fn peer_uid<S: AsRawFd>(sock: &S) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid, correctly sized out-parameters for
    // SO_PEERCRED, and the fd is owned by `sock` for the duration of the call.
    let rc = unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// Take a non-blocking exclusive flock on `f`; error if already held.
pub fn try_lock_exclusive<F: AsRawFd>(f: &F) -> io::Result<()> {
    // SAFETY: flock on a valid fd owned by `f`.
    let rc = unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Landlock ABI version of the running kernel (0 = unavailable).
pub fn landlock_abi() -> u32 {
    const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1;
    // SAFETY: with a NULL attr, zero size and the VERSION flag, the kernel only
    // returns the ABI version; no memory is read or written.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<u8>(),
            0usize,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if rc < 0 {
        0
    } else {
        rc as u32
    }
}
