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
