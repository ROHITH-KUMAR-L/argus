//! Raw syscalls for confinement. All `unsafe` in this crate lives here.
#![allow(unsafe_code)]

/// Landlock ABI version of the running kernel (0 = unavailable or blocked).
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

/// Open `path` as an `O_PATH` descriptor, walking it one component at a time
/// with `O_NOFOLLOW`, so that no component (including the last) may be a
/// symlink. Returns the fd and whether the target is a directory.
pub fn open_no_symlinks(path: &str) -> std::io::Result<(std::os::fd::OwnedFd, bool)> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    if !path.starts_with('/') {
        return Err(std::io::Error::from_raw_os_error(libc::EINVAL));
    }
    let open = |dirfd: libc::c_int, name: &CString| -> std::io::Result<OwnedFd> {
        // SAFETY: `name` is a valid NUL-terminated string; the returned fd is
        // owned exclusively by the OwnedFd we construct.
        let fd = unsafe {
            libc::openat(
                dirfd,
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        // SAFETY: `fd` is a fresh, valid descriptor not owned elsewhere.
        Ok(unsafe { OwnedFd::from_raw_fd(fd) })
    };
    let root = CString::new("/").expect("static");
    let mut cur = open(libc::AT_FDCWD, &root)?;
    for comp in path.split('/').filter(|c| !c.is_empty()) {
        let name =
            CString::new(comp).map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
        cur = open(cur.as_raw_fd(), &name)?;
    }
    // SAFETY: zeroed stat is a valid out-parameter for fstat.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: `cur` is a valid fd and `st` a valid out-pointer.
    if unsafe { libc::fstat(cur.as_raw_fd(), &mut st) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    match st.st_mode & libc::S_IFMT {
        libc::S_IFLNK => Err(std::io::Error::from_raw_os_error(libc::ELOOP)),
        libc::S_IFDIR => Ok((cur, true)),
        _ => Ok((cur, false)),
    }
}
