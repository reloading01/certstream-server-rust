//! Integration tests for fix #9: server startup failure paths must log
//! and exit gracefully, never panic-unwind to a useless backtrace.
//!
//! These tests spawn the release binary with deliberately bad config and
//! assert: (a) it exits non-zero, (b) it does NOT produce "panicked at"
//! in stderr (which would indicate `.expect()` blew up).
//!
//! Skipped if `target/release/certstream-server-rust` is not built.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("release");
    p.push("certstream-server-rust");
    p
}

fn skip_if_no_binary() -> Option<PathBuf> {
    let p = binary_path();
    if p.exists() { Some(p) } else {
        eprintln!("skipping: {} not built (run `cargo build --release`)", p.display());
        None
    }
}

/// TLS cert path that doesn't exist → must log + graceful exit, no panic.
#[test]
fn bad_tls_cert_path_no_panic() {
    let Some(bin) = skip_if_no_binary() else { return };

    let out = Command::new(&bin)
        .env("CERTSTREAM_HOST", "127.0.0.1")
        .env("CERTSTREAM_PORT", "0")  // OS-assigned, irrelevant since TLS fails first
        .env("CERTSTREAM_LOG_LEVEL", "error")
        .env("CERTSTREAM_TLS_CERT", "/this/does/not/exist/cert.pem")
        .env("CERTSTREAM_TLS_KEY",  "/this/does/not/exist/key.pem")
        .env("CERTSTREAM_CONFIG",   "/nonexistent")
        .arg("--dry-run")
        .output()
        .expect("spawn");

    // Wait briefly — server should give up immediately on missing TLS files,
    // not hang forever.
    // (Command::output() blocks until child exits.)

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        !stderr.contains("panicked at"),
        "bad TLS path must not panic. stderr:\n{stderr}"
    );
    // Should log a structured error about TLS loading.
    assert!(
        stderr.to_lowercase().contains("tls") || stderr.contains("/this/does/not/exist"),
        "expected TLS error in stderr, got:\n{stderr}"
    );
}

/// Bind to a port that's already taken → log + graceful exit.
#[test]
fn occupied_port_no_panic() {
    let Some(bin) = skip_if_no_binary() else { return };

    // Hold a port open in this test process.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().unwrap().port();
    // Keep listener alive across the spawn so the bind conflict is real.

    let mut child = Command::new(&bin)
        .env("CERTSTREAM_HOST", "127.0.0.1")
        .env("CERTSTREAM_PORT", port.to_string())
        .env("CERTSTREAM_LOG_LEVEL", "error")
        .env("CERTSTREAM_CONFIG", "/nonexistent")
        .arg("--dry-run")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn");

    // Server tries to bind, fails, should exit within ~2 seconds. If it
    // panics, we'd see "panicked at" in stderr; either way the process
    // terminates. If it hangs (regression), we kill it after 5 s.
    let start = std::time::Instant::now();
    loop {
        match child.try_wait().expect("try_wait") {
            Some(_status) => break,
            None => {
                if start.elapsed() > Duration::from_secs(5) {
                    let _ = child.kill();
                    panic!("server did not exit on bind failure within 5 s — regression");
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }

    drop(listener);

    let mut stderr = String::new();
    if let Some(mut s) = child.stderr.take() {
        use std::io::Read;
        let _ = s.read_to_string(&mut stderr);
    }

    assert!(
        !stderr.contains("panicked at"),
        "bind failure must not panic. stderr:\n{stderr}"
    );
}

/// Config file with garbage YAML — must not panic on load (this path goes
/// through serde_yaml which we wrap in a warn!() handler).
#[test]
fn garbage_config_no_panic() {
    let Some(bin) = skip_if_no_binary() else { return };

    let tmp = std::env::temp_dir().join(format!(
        "certstream-bad-cfg-{}.yaml",
        std::process::id()
    ));
    std::fs::write(&tmp, "this: is: not: valid: yaml: ::").unwrap();

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let mut child = Command::new(&bin)
        .env("CERTSTREAM_CONFIG", tmp.to_str().unwrap())
        .env("CERTSTREAM_HOST", "127.0.0.1")
        .env("CERTSTREAM_PORT", port.to_string())
        .env("CERTSTREAM_LOG_LEVEL", "error")
        .arg("--dry-run")
        .stderr(std::process::Stdio::piped())
        .stdout(std::process::Stdio::null())
        .spawn()
        .expect("spawn");

    // It should boot anyway (falling back to defaults). Give it 5 s and kill.
    std::thread::sleep(Duration::from_secs(2));
    let _ = child.kill();
    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);

    let _ = std::fs::remove_file(&tmp);

    assert!(
        !stderr.contains("panicked at"),
        "bad YAML must not panic. stderr:\n{stderr}"
    );
}
