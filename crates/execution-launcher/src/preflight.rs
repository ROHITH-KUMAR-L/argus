//! `argus-worker --preflight`: report the worker's effective security state
//! from inside the container. The controller compares this against the
//! required hardening (code_execution_agent.md §13); this mode never decides.

use serde_json::{json, Value};
use std::fs;
use std::io::ErrorKind;

fn status_field(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|l| {
        l.strip_prefix(&format!("{key}:"))
            .map(|v| v.trim().to_string())
    })
}

fn try_write(path: &str) -> Value {
    match fs::write(path, b"x") {
        Ok(()) => {
            let _ = fs::remove_file(path);
            json!({"writable": true})
        }
        Err(e) => {
            json!({"writable": false, "errno": e.raw_os_error(), "kind": format!("{:?}", e.kind())})
        }
    }
}

fn exists(path: &str) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(e) => e.kind() != ErrorKind::NotFound,
    }
}

fn read_trim(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

pub fn report() -> Value {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mounts: Vec<Value> = fs::read_to_string("/proc/self/mountinfo")
        .unwrap_or_default()
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split(' ').collect();
            let sep = f.iter().position(|x| *x == "-")?;
            Some(json!({
                "mount_point": f.get(4)?,
                "options": f.get(5)?,
                "fs_type": f.get(sep + 1)?,
                "source": f.get(sep + 2)?,
                "super_options": f.get(sep + 3).unwrap_or(&""),
            }))
        })
        .collect();
    let net: Vec<String> = fs::read_dir("/sys/class/net")
        .map(|d| {
            d.flatten()
                .map(|e| e.file_name().to_string_lossy().to_string())
                .collect()
        })
        .unwrap_or_default();
    let env_names: Vec<String> = std::env::vars().map(|(k, _)| k).collect();
    let docker_socket = ["/var/run/docker.sock", "/run/docker.sock"]
        .iter()
        .any(|p| exists(p));
    json!({
        "preflight_version": "1.0",
        "pid": std::process::id(),
        "uid": status_field(&status, "Uid"),
        "gid": status_field(&status, "Gid"),
        "cap_eff": status_field(&status, "CapEff"),
        "cap_prm": status_field(&status, "CapPrm"),
        "cap_bnd": status_field(&status, "CapBnd"),
        "no_new_privs": status_field(&status, "NoNewPrivs"),
        "seccomp_mode": status_field(&status, "Seccomp"),
        "landlock_abi": linux_confinement::landlock_abi(),
        "root_write": try_write("/etc/.argus-preflight"),
        "usr_write": try_write("/usr/.argus-preflight"),
        "tmp_write": try_write("/tmp/.argus-preflight"),
        "workspace_write": try_write("/workspace/task/.argus-preflight"),
        "network_interfaces": net,
        "docker_socket_present": docker_socket,
        "host_paths_present": {
            "/host": exists("/host"),
            "/home_has_entries": fs::read_dir("/home").map(|mut d| d.next().is_some()).unwrap_or(false),
            "/root_readable": fs::read_dir("/root").is_ok(),
        },
        "mounts": mounts,
        "env_names": env_names,
        "cgroup": {
            "memory_max": read_trim("/sys/fs/cgroup/memory.max"),
            "memory_swap_max": read_trim("/sys/fs/cgroup/memory.swap.max"),
            "pids_max": read_trim("/sys/fs/cgroup/pids.max"),
            "cpu_max": read_trim("/sys/fs/cgroup/cpu.max"),
        },
        "limits": read_trim("/proc/self/limits"),
    })
}
