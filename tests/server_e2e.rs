//! End-to-end integration test: spawn the release binary in dry-run mode
//! (so it doesn't actually hit Google's CT list), hit /health and /metrics,
//! and tear down. Validates the wiring from `Config::load → Router → Axum`
//! that unit tests can't reach.
//!
//! Skipped if the release binary isn't built — run `cargo build --release`
//! before invoking `cargo test --test server_e2e`. Uses `reqwest` async
//! (already a runtime dep) to avoid pulling in a new blocking HTTP client.

use std::net::TcpListener;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

fn binary_path() -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("target");
    p.push("release");
    p.push("certstream-server-rust");
    p
}

/// Pick an unused TCP port by binding ephemeral and immediately releasing.
/// Not race-free vs other processes but adequate for a one-shot test.
fn pick_port() -> u16 {
    let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    l.local_addr().unwrap().port()
}

struct ServerHandle(Child);
impl Drop for ServerHandle {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

async fn wait_until_healthy(client: &reqwest::Client, port: u16, deadline: Duration) -> bool {
    let start = Instant::now();
    let url = format!("http://127.0.0.1:{port}/health");
    while start.elapsed() < deadline {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

#[tokio::test]
async fn server_serves_health_and_metrics() {
    let bin = binary_path();
    if !bin.exists() {
        eprintln!(
            "skipping: {} not built (run `cargo build --release`)",
            bin.display()
        );
        return;
    }

    let port = pick_port();
    let child = Command::new(&bin)
        .env("CERTSTREAM_HOST", "127.0.0.1")
        .env("CERTSTREAM_PORT", port.to_string())
        .env("CERTSTREAM_LOG_LEVEL", "warn")
        .env("CERTSTREAM_CONFIG", "/nonexistent")
        .arg("--dry-run")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn server");
    let _guard = ServerHandle(child);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .unwrap();

    assert!(
        wait_until_healthy(&client, port, Duration::from_secs(15)).await,
        "server never became healthy on port {port}"
    );

    // /health is bare-OK
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health"))
        .send()
        .await
        .expect("/health");
    assert_eq!(resp.status(), 200);

    // /metrics returns prometheus text and includes counters we pre-initialised
    let resp = client
        .get(format!("http://127.0.0.1:{port}/metrics"))
        .send()
        .await
        .expect("/metrics");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.expect("read metrics");
    for needle in [
        "certstream_worker_panics",
        "certstream_duplicates_filtered",
        "certstream_connection_limit_rejected",
    ] {
        assert!(
            body.contains(needle),
            "/metrics missing `{needle}` — counter pre-init regressed?"
        );
    }

    // /health/deep returns JSON with `status` field
    let resp = client
        .get(format!("http://127.0.0.1:{port}/health/deep"))
        .send()
        .await
        .expect("/health/deep");
    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("\"status\""));

    // Unknown route returns the 404 JSON we ship
    let resp = client
        .get(format!("http://127.0.0.1:{port}/this-does-not-exist"))
        .send()
        .await
        .expect("404");
    assert_eq!(resp.status(), 404);
}
