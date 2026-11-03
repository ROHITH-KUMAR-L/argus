//! Supervisor lifecycle tests (benign commands only; hostile cases run in containers).
//! Tests are serialized: cleanup reaps every child of the test process.

use process_supervisor::{run, Rlimits, RunSpec, Termination};
use std::sync::Mutex;
use std::time::{Duration, Instant};

static SERIAL: Mutex<()> = Mutex::new(());

fn spec(argv: &[&str]) -> RunSpec {
    RunSpec {
        argv: argv.iter().map(|s| s.to_string()).collect(),
        cwd: "/".into(),
        env: vec![("PATH".into(), "/usr/bin:/bin".into())],
        stdin: None,
        timeout: Duration::from_secs(10),
        rlimits: None,
        output_cap: 64 * 1024,
        pre_exec: None,
    }
}

fn alive(pid: i32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
        && !std::fs::read_to_string(format!("/proc/{pid}/stat"))
            .unwrap_or_default()
            .contains(") Z ")
}

fn lock() -> std::sync::MutexGuard<'static, ()> {
    process_supervisor::set_child_subreaper().unwrap();
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

#[test]
fn argv_is_not_shell_interpreted() {
    let _g = lock();
    let o = run(spec(&["/usr/bin/echo", "a; rm -rf / $(id) `x` | y"])).unwrap();
    assert_eq!(o.exit_code, Some(0));
    assert_eq!(
        String::from_utf8(o.stdout).unwrap(),
        "a; rm -rf / $(id) `x` | y\n"
    );
}

#[test]
fn environment_is_cleared() {
    let _g = lock();
    std::env::set_var("ARGUS_TEST_SECRET", "should-not-leak");
    let o = run(spec(&["/usr/bin/env"])).unwrap();
    let out = String::from_utf8(o.stdout).unwrap();
    assert!(!out.contains("should-not-leak"));
    assert_eq!(out.trim(), "PATH=/usr/bin:/bin");
}

#[test]
fn stdin_and_exit_code() {
    let _g = lock();
    let mut s = spec(&["/usr/bin/sh", "-c", "read x; echo got:$x; exit 7"]);
    s.stdin = Some(b"hello\n".to_vec());
    let o = run(s).unwrap();
    assert_eq!(o.exit_code, Some(7));
    assert_eq!(String::from_utf8(o.stdout).unwrap(), "got:hello\n");
}

#[test]
fn aud_011_output_is_bounded_and_flagged() {
    let _g = lock();
    let mut s = spec(&[
        "/usr/bin/sh",
        "-c",
        "head -c 5000000 /dev/zero; head -c 300 /dev/zero >&2",
    ]);
    s.output_cap = 4096;
    let o = run(s).unwrap();
    assert_eq!(o.stdout.len(), 4096);
    assert!(o.stdout_truncated);
    assert_eq!(o.stderr.len(), 300);
    assert!(!o.stderr_truncated);
    assert_eq!(o.exit_code, Some(0)); // the child never blocked on a full pipe
}

#[test]
fn timeout_kills_whole_tree() {
    let _g = lock();
    let mut s = spec(&["/usr/bin/sh", "-c", "sleep 60 & sleep 60 & echo $!; wait"]);
    s.timeout = Duration::from_millis(300);
    let t0 = Instant::now();
    let o = run(s).unwrap();
    assert!(t0.elapsed() < Duration::from_secs(5));
    assert_eq!(o.termination, Termination::TimedOut);
    assert_eq!(o.limit_hit, Some("wall_time_seconds"));
    let bg: i32 = String::from_utf8(o.stdout).unwrap().trim().parse().unwrap();
    assert!(!alive(bg), "background child {bg} survived");
}

#[test]
fn daemonized_and_setsid_descendants_do_not_survive() {
    let _g = lock();
    // Grandchild escapes the process group with setsid and outlives its parent.
    let o = run(spec(&[
        "/usr/bin/sh",
        "-c",
        "setsid sh -c 'sleep 60' >/dev/null 2>&1 & (sleep 60 &) ; sleep 0.2; pgrep -P $$ -f 'sleep 60' >/dev/null; ps -o pid= --ppid 1 >/dev/null 2>&1; exit 0",
    ]))
    .unwrap();
    assert_eq!(o.exit_code, Some(0));
    assert!(
        o.descendants_killed >= 1,
        "expected reparented descendants to be killed: {o:?}"
    );
    // Nothing that names our marker is still running as our descendant.
    std::thread::sleep(Duration::from_millis(50));
    let me = std::process::id().to_string();
    for e in std::fs::read_dir("/proc").unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        if let Ok(stat) = std::fs::read_to_string(format!("/proc/{name}/stat")) {
            if let Some(rest) = stat.rfind(')').map(|i| &stat[i + 2..]) {
                let ppid = rest.split_whitespace().nth(1).unwrap_or("");
                assert!(
                    ppid != me || stat.contains(") Z "),
                    "descendant {name} survived"
                );
            }
        }
    }
}

#[test]
fn res_cpu_limit() {
    let _g = lock();
    let mut s = spec(&["/usr/bin/sh", "-c", "while :; do :; done"]);
    s.rlimits = Some(Rlimits {
        cpu_seconds: 1,
        address_space_bytes: 1 << 30,
        file_size_bytes: 1 << 20,
        open_files: 64,
        processes: 0,
    });
    let o = run(s).unwrap();
    assert_eq!(o.signal, Some(libc::SIGXCPU), "{o:?}");
    assert_eq!(o.limit_hit, Some("cpu_seconds"));
}

#[test]
fn res_file_size_limit() {
    let _g = lock();
    let dir = tempfile::tempdir().unwrap();
    let mut s = spec(&["/usr/bin/sh", "-c", "exec head -c 100000 /dev/zero > big"]);
    s.cwd = dir.path().to_str().unwrap().into();
    s.rlimits = Some(Rlimits {
        cpu_seconds: 10,
        address_space_bytes: 1 << 30,
        file_size_bytes: 4096,
        open_files: 64,
        processes: 0,
    });
    let o = run(s).unwrap();
    assert_eq!(o.limit_hit, Some("file_size_bytes"), "{o:?}");
    assert!(std::fs::metadata(dir.path().join("big")).unwrap().len() <= 4096);
}

#[test]
fn res_open_files_limit() {
    let _g = lock();
    let mut s = spec(&[
        "/usr/bin/sh",
        "-c",
        "exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null && echo opened",
    ]);
    s.rlimits = Some(Rlimits {
        cpu_seconds: 10,
        address_space_bytes: 1 << 30,
        file_size_bytes: 1 << 20,
        open_files: 5,
        processes: 0,
    });
    let o = run(s).unwrap();
    assert_ne!(o.exit_code, Some(0));
    assert!(!String::from_utf8_lossy(&o.stdout).contains("opened"));
}

#[test]
fn failing_pre_exec_hook_prevents_execution() {
    let _g = lock();
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("ran");
    let mut s = spec(&["/usr/bin/touch", marker.to_str().unwrap()]);
    s.pre_exec = Some(Box::new(|| {
        Err(std::io::Error::other("confinement failed"))
    }));
    assert!(run(s).is_err());
    assert!(
        !marker.exists(),
        "command ran despite failing pre-exec hook"
    );
}

#[test]
fn missing_executable_is_an_error() {
    let _g = lock();
    assert!(run(spec(&["/nonexistent/binary"])).is_err());
    assert!(run(spec(&[])).is_err());
}
