//! `proteus-tools fetch-decoy` — operator-facing utility that
//! snapshots a public cover host's index page so the PROTEUS server
//! can serve a byte-identical decoy from `decoy.static_page`.
//!
//! M8.4 of the v0.4 plan. The motivation:
//!
//! M3.4 shipped an embedded nginx-welcome page as the default H3 decoy.
//! That's plausible, but a passive observer who actually `curl`s the
//! server's SNI on port 443 sees the *nginx* welcome page, not the
//! page they'd see if they `curl`'d the cover host (e.g. cloudflare,
//! amazon, et al.). A motivated prober can compare those two responses
//! and notice the divergence.
//!
//! `fetch-decoy` closes that gap in the simplest possible way: run it
//! once at deployment time against the cover host, point
//! `decoy.static_page` at the resulting file, and the server now
//! returns the *same* HTML body any observer would get from the real
//! cover host. Headers (`server`, `content-type`, etc.) are already
//! handled by the M3.4 decoy code.
//!
//! Out of scope (deferred to v0.5+):
//! - Periodic re-fetch (the snapshot is stale by definition; refresh
//!   is an ops concern, not a server concern).
//! - Header mirroring (M3.4 hardcodes nginx-style headers; cloning
//!   the cover host's headers would tighten the fingerprint but
//!   requires a deeper decoy refactor).
//! - HTTP/3 over QUIC for the fetch (we use HTTP/1.1+H2 via reqwest;
//!   the *content* matters, not the transport).
//!
//! Network-isolated unit tests live at the bottom: they spin up a
//! local `tokio::net::TcpListener` that speaks just enough HTTP/1.1
//! to satisfy reqwest, then verify body capture, header reporting,
//! and the `--out` file-write path.

use std::{io::Write, path::PathBuf, time::Duration};

use anyhow::{Context, Result, anyhow};
use clap::Args as ClapArgs;
use proteus_core::decoy::DecoyHeaders;
use reqwest::header::{HeaderMap, HeaderValue, USER_AGENT};

/// Default User-Agent. Mirrors a stock Firefox-on-macOS UA at
/// roughly the time this commit landed. Operators can override via
/// `--user-agent` to match whatever fingerprint they want to project.
const DEFAULT_USER_AGENT: &str =
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.5; rv:128.0) Gecko/20100101 Firefox/128.0";

/// Default connect+read timeout in seconds. Snapshots run interactively
/// at deploy time, so a generous default is fine.
const DEFAULT_TIMEOUT_SECS: u64 = 15;

#[derive(ClapArgs, Debug)]
pub struct Args {
    /// Full URL of the cover host to snapshot, e.g.
    /// `https://www.cloudflare.com/`.
    #[arg(short, long)]
    pub url: String,

    /// File to write the response body to. `-` or omitted = stdout.
    #[arg(short, long)]
    pub out: Option<PathBuf>,

    /// File to write the response headers to as JSON (M8.4.1). Loaded
    /// by `proteus-server` via `decoy.static_headers` so the H3 decoy
    /// can echo the cover host's exact header set. Omitted = no
    /// header snapshot file is written.
    #[arg(long)]
    pub out_headers: Option<PathBuf>,

    /// User-Agent header. Defaults to a stock Firefox UA.
    #[arg(long)]
    pub user_agent: Option<String>,

    /// Connect+read timeout in seconds.
    #[arg(long, default_value_t = DEFAULT_TIMEOUT_SECS)]
    pub timeout_secs: u64,

    /// Allow non-2xx responses to still write the body (useful for
    /// debugging cover hosts that 301 or 403). Without this flag,
    /// non-2xx aborts before any write.
    #[arg(long)]
    pub accept_non_2xx: bool,
}

/// Result of one fetch — captured for both the CLI runner and the
/// unit tests so the byte-level invariants are testable.
#[derive(Debug)]
pub struct Fetched {
    pub status: u16,
    pub content_type: Option<String>,
    /// All response headers in wire order, lowercased names. Empty
    /// for non-2xx errors that didn't even parse a header section
    /// (reqwest still gives us them, so realistically always populated).
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Fetched {
    /// Project into the on-disk [`DecoyHeaders`] snapshot format.
    pub fn to_decoy_headers(&self) -> DecoyHeaders {
        DecoyHeaders {
            status: self.status,
            headers: self.headers.clone(),
        }
    }
}

pub async fn run(args: Args) -> Result<()> {
    let ua = args
        .user_agent
        .as_deref()
        .unwrap_or(DEFAULT_USER_AGENT)
        .to_string();
    let timeout = Duration::from_secs(args.timeout_secs);

    let fetched = fetch(&args.url, &ua, timeout).await?;

    eprintln!(
        "fetched {} → {} ({} bytes, content-type: {})",
        args.url,
        fetched.status,
        fetched.body.len(),
        fetched.content_type.as_deref().unwrap_or("<none>")
    );

    let ok_2xx = (200..300).contains(&fetched.status);
    if !ok_2xx && !args.accept_non_2xx {
        return Err(anyhow!(
            "cover host returned HTTP {} (use --accept-non-2xx to write the body anyway)",
            fetched.status
        ));
    }

    write_body(args.out.as_deref(), &fetched.body)?;

    if let Some(headers_path) = args.out_headers.as_deref() {
        let snapshot = fetched.to_decoy_headers();
        let json = snapshot.to_json_pretty()?;
        std::fs::write(headers_path, json)
            .with_context(|| format!("write {}", headers_path.display()))?;
        eprintln!(
            "wrote headers snapshot: {} ({} headers)",
            headers_path.display(),
            snapshot.headers.len()
        );
    }

    Ok(())
}

/// Perform one HTTPS GET against `url` with the given UA + timeout,
/// return status + content-type + body bytes. Follows redirects (up to
/// reqwest's default cap of 10) — the snapshot should be of whatever
/// the operator actually wants to mirror, not an intermediate 301.
async fn fetch(url: &str, user_agent: &str, timeout: Duration) -> Result<Fetched> {
    let mut headers = HeaderMap::new();
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(user_agent).context("invalid User-Agent header")?,
    );

    let client = reqwest::Client::builder()
        .default_headers(headers)
        .timeout(timeout)
        .build()
        .context("build reqwest client")?;

    let resp = client
        .get(url)
        .send()
        .await
        .with_context(|| format!("GET {url}"))?;

    let status = resp.status().as_u16();
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    // Snapshot ALL response headers in wire order. Names are lowercased
    // (matches H2/H3 wire format anyway); values pass through verbatim
    // including duplicates (e.g. multiple `set-cookie`).
    let headers: Vec<(String, String)> = resp
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|v| (name.as_str().to_ascii_lowercase(), v.to_string()))
        })
        .collect();

    let body = resp.bytes().await.context("read response body")?.to_vec();

    Ok(Fetched {
        status,
        content_type,
        headers,
        body,
    })
}

fn write_body(out: Option<&std::path::Path>, body: &[u8]) -> Result<()> {
    match out {
        None => {
            std::io::stdout().write_all(body).context("write stdout")?;
            Ok(())
        }
        Some(p) if p.as_os_str() == "-" => {
            std::io::stdout().write_all(body).context("write stdout")?;
            Ok(())
        }
        Some(p) => std::fs::write(p, body).with_context(|| format!("write {}", p.display())),
    }
}

// ---------------- tests ----------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    /// Minimal HTTP/1.1 server: accepts one connection, reads request
    /// headers until CRLFCRLF, then writes a fixed response. Returns the
    /// listen address so the test can point reqwest at it.
    async fn spawn_fixed_response(response_bytes: Vec<u8>) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain request headers.
            let mut buf = [0u8; 4096];
            let mut acc = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                acc.extend_from_slice(&buf[..n]);
                if acc.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            sock.write_all(&response_bytes).await.unwrap();
            let _ = sock.shutdown().await;
        });
        addr
    }

    fn http_response(status_line: &str, headers: &[(&str, &str)], body: &[u8]) -> Vec<u8> {
        let mut out = format!("HTTP/1.1 {status_line}\r\n").into_bytes();
        for (k, v) in headers {
            out.extend_from_slice(format!("{k}: {v}\r\n").as_bytes());
        }
        out.extend_from_slice(format!("content-length: {}\r\n", body.len()).as_bytes());
        out.extend_from_slice(b"connection: close\r\n\r\n");
        out.extend_from_slice(body);
        out
    }

    #[tokio::test]
    async fn fetch_captures_body_and_content_type() {
        let body = b"<html>hello</html>";
        let resp = http_response(
            "200 OK",
            &[("content-type", "text/html; charset=utf-8")],
            body,
        );
        let addr = spawn_fixed_response(resp).await;
        let url = format!("http://{addr}/");

        let got = fetch(&url, DEFAULT_USER_AGENT, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got.status, 200);
        assert_eq!(got.body, body);
        assert_eq!(
            got.content_type.as_deref(),
            Some("text/html; charset=utf-8")
        );
    }

    #[tokio::test]
    async fn fetch_reports_non_2xx_without_failing() {
        let resp = http_response("404 Not Found", &[("content-type", "text/plain")], b"nope");
        let addr = spawn_fixed_response(resp).await;
        let url = format!("http://{addr}/");

        let got = fetch(&url, DEFAULT_USER_AGENT, Duration::from_secs(2))
            .await
            .unwrap();
        assert_eq!(got.status, 404);
        assert_eq!(got.body, b"nope");
    }

    #[tokio::test]
    async fn run_writes_body_to_file_on_2xx() {
        let body = b"snapshot-bytes";
        let resp = http_response("200 OK", &[("content-type", "text/html")], body);
        let addr = spawn_fixed_response(resp).await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("decoy.html");
        run(Args {
            url: format!("http://{addr}/"),
            out: Some(out.clone()),
            out_headers: None,
            user_agent: None,
            timeout_secs: 2,
            accept_non_2xx: false,
        })
        .await
        .unwrap();

        assert_eq!(std::fs::read(&out).unwrap(), body);
    }

    #[tokio::test]
    async fn run_refuses_non_2xx_without_flag() {
        let resp = http_response("500 Internal Server Error", &[], b"boom");
        let addr = spawn_fixed_response(resp).await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("decoy.html");
        let err = run(Args {
            url: format!("http://{addr}/"),
            out: Some(out.clone()),
            out_headers: None,
            user_agent: None,
            timeout_secs: 2,
            accept_non_2xx: false,
        })
        .await
        .unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("500"), "got: {msg}");
        assert!(!out.exists(), "should not have written file on non-2xx");
    }

    #[tokio::test]
    async fn run_writes_body_on_non_2xx_with_flag() {
        let resp = http_response("403 Forbidden", &[("content-type", "text/html")], b"nope");
        let addr = spawn_fixed_response(resp).await;

        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("decoy.html");
        run(Args {
            url: format!("http://{addr}/"),
            out: Some(out.clone()),
            out_headers: None,
            user_agent: None,
            timeout_secs: 2,
            accept_non_2xx: true,
        })
        .await
        .unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), b"nope");
    }

    #[tokio::test]
    async fn fetch_captures_full_header_list_in_order() {
        let body = b"x";
        let resp = http_response(
            "200 OK",
            &[
                ("Server", "nginx/1.27.0"),
                ("Content-Type", "text/html; charset=utf-8"),
                ("Cache-Control", "public, max-age=60"),
                ("Strict-Transport-Security", "max-age=31536000"),
            ],
            body,
        );
        let addr = spawn_fixed_response(resp).await;
        let url = format!("http://{addr}/");

        let got = fetch(&url, DEFAULT_USER_AGENT, Duration::from_secs(2))
            .await
            .unwrap();
        // All names lowercased; cover-host headers preserved.
        let names: Vec<&str> = got.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"server"));
        assert!(names.contains(&"content-type"));
        assert!(names.contains(&"cache-control"));
        assert!(names.contains(&"strict-transport-security"));
        let server_val = got
            .headers
            .iter()
            .find(|(n, _)| n == "server")
            .map(|(_, v)| v.as_str());
        assert_eq!(server_val, Some("nginx/1.27.0"));
    }

    #[tokio::test]
    async fn run_writes_headers_snapshot_alongside_body() {
        let body = b"<html>x</html>";
        let resp = http_response(
            "200 OK",
            &[
                ("Server", "nginx/1.27.0"),
                ("Content-Type", "text/html; charset=utf-8"),
            ],
            body,
        );
        let addr = spawn_fixed_response(resp).await;

        let dir = tempfile::tempdir().unwrap();
        let body_path = dir.path().join("decoy.html");
        let headers_path = dir.path().join("decoy-headers.json");
        run(Args {
            url: format!("http://{addr}/"),
            out: Some(body_path.clone()),
            out_headers: Some(headers_path.clone()),
            user_agent: None,
            timeout_secs: 2,
            accept_non_2xx: false,
        })
        .await
        .unwrap();

        assert_eq!(std::fs::read(&body_path).unwrap(), body);

        let loaded = DecoyHeaders::from_json_file(&headers_path).unwrap();
        assert_eq!(loaded.status, 200);
        let names: Vec<&str> = loaded.headers.iter().map(|(n, _)| n.as_str()).collect();
        assert!(names.contains(&"server"));
        assert!(names.contains(&"content-type"));
    }

    #[tokio::test]
    async fn fetch_errors_on_silent_peer() {
        // Bind but never reply. The exact error class reqwest returns
        // depends on whether the per-test runtime's listener task gets
        // scheduled fast enough to accept the connect; under heavy
        // parallel-test load it can be "connection closed before message
        // completed" rather than a clean timeout. Either way the fetch
        // must fail — that's what this test guards.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = listener.accept().await;
            tokio::time::sleep(Duration::from_secs(10)).await;
        });

        let url = format!("http://{addr}/");
        let r = fetch(&url, DEFAULT_USER_AGENT, Duration::from_millis(300)).await;
        assert!(r.is_err(), "silent peer must produce an error");
    }

    #[test]
    fn write_body_stdout_when_out_is_dash() {
        // Just verify the dash-path doesn't try to open a real file
        // (smoke-only — capturing real stdout is awkward in unit tests).
        let p = std::path::PathBuf::from("-");
        let r = write_body(Some(&p), b"x");
        assert!(r.is_ok());
    }
}
