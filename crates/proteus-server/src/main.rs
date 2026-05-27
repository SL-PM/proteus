//! PROTEUS server (v0.3 research prototype).
//!
//! M17: auth + replay cache + policy + TCP/UDP proxy, plus atomic
//! counters for auth/replay/policy/proxy events surfaced via a
//! periodic stderr snapshot (every 30s). Counters live in
//! `proteus_core::metrics`.
//!
//! For each connection:
//!   1. accept control stream, run auth + replay check
//!   2. on success: AUTH_RESPONSE(ok), then loop `accept_bi()` for
//!      additional bidi streams. Each is treated as a proxy stream:
//!      read PROXY_OPEN, resolve the target host, run the policy
//!      check, then either bridge to TCP/UDP or PROXY_REJECT.
//!   3. on auth failure: `H3_GENERAL_PROTOCOL_ERROR` close (no plaintext)
//!
//! Decoy (M13) and hardening (M18) are the last v0.3 protocol pieces.

use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    auth::{
        AuthRequest, AuthResponse, ClientRegistry, EXPORTER_LABEL, EXPORTER_LEN, STATUS_AUTH_FAILED,
    },
    config::ServerConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    metrics::Metrics,
    policy::PolicyChecker,
    proxy::{self, ProxyOpen, ProxyReject, reject as reject_codes},
    ratelimit::AuthRateLimiter,
    replay::ReplayCache,
    tls,
};
use tokio::net::{TcpStream, UdpSocket};

/// QUIC application close code on auth failure — same family as
/// `H3_GENERAL_PROTOCOL_ERROR` per spec v0.2 §8.4.
const AUTH_FAIL_CLOSE_CODE: u32 = 0x0101;

/// Max time to wait for the first AUTH_REQUEST frame after the
/// control stream is accepted. Slow-loris hardening (M18).
const AUTH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// ALPN we advertise alongside `proteus/0.3` for the M13 decoy.
const H3_ALPN: &[u8] = b"h3";

/// Maximum PROTEUS auth attempts per peer IP per window. M18.1.
const RATE_LIMIT_MAX: usize = 30;
/// Rolling window for the auth rate limit.
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// How often to sweep expired rate-limit buckets.
const RATE_LIMIT_SWEEP_INTERVAL: Duration = Duration::from_secs(120);

/// Per spec v0.2 §8.3.
const REPLAY_TTL: Duration = Duration::from_secs(300);

/// How often to sweep expired entries from the replay cache.
const REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How often the metrics snapshot is written to stderr.
const METRICS_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Parser, Debug)]
#[command(
    name = "proteus-server",
    version,
    about = "PROTEUS server (v0.3 research prototype)",
    long_about = "v0.3 research prototype — DPI-detectable by design. \
                  Do not deploy. See docs/THREAT-MODEL-v0.3.md."
)]
struct Cli {
    /// Path to YAML config file.
    #[arg(short, long)]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ServerConfig::from_yaml_file(&cli.config)?;

    tls::install_crypto_provider();
    let (qcfg, cert) = tls::server_config(cfg.tls.as_ref())?;
    let endpoint = quinn::Endpoint::server(qcfg, cfg.listen.addr)
        .with_context(|| format!("bind {}", cfg.listen.addr))?;

    let registry = Arc::new(ClientRegistry::from_config_map(cfg.clients.as_ref())?);
    let replay = Arc::new(ReplayCache::new(REPLAY_TTL));
    let policy: Option<Arc<PolicyChecker>> = cfg
        .policy
        .as_ref()
        .map(|p| Arc::new(PolicyChecker::from_config(p)));
    let metrics = Arc::new(Metrics::new());
    let rate_limiter = Arc::new(AuthRateLimiter::new(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW));

    // M3.4: load decoy HTML from disk if `decoy.static_page` is set;
    // otherwise fall back to the embedded nginx welcome page.
    let decoy_html: Arc<Vec<u8>> = match cfg.decoy.as_ref() {
        Some(d) => {
            let bytes = std::fs::read(&d.static_page)
                .with_context(|| format!("read decoy {}", d.static_page.display()))?;
            Arc::new(bytes)
        }
        None => Arc::new(DEFAULT_DECOY_HTML.to_vec()),
    };

    println!("proteus-server v{}", env!("CARGO_PKG_VERSION"));
    println!("listening on: {}", endpoint.local_addr()?);
    println!("cert sha256:  {}", tls::cert_sha256_hex(&cert));
    println!("clients:      {}", registry.len());
    println!("replay ttl:   {}s", REPLAY_TTL.as_secs());
    println!(
        "policy:       {}",
        if policy.is_some() {
            "enabled"
        } else {
            "disabled (no `policy:` section in config)"
        }
    );
    println!(
        "metrics:      snapshot every {}s to stderr",
        METRICS_SNAPSHOT_INTERVAL.as_secs()
    );
    println!(
        "rate limit:   {} auth attempts per {}s per peer IP",
        rate_limiter.max_per_window(),
        rate_limiter.window().as_secs()
    );
    println!(
        "decoy:        {} ({} bytes)",
        if cfg.decoy.is_some() {
            "file"
        } else {
            "embedded default (nginx welcome)"
        },
        decoy_html.len()
    );
    if registry.is_empty() {
        eprintln!("warning: no clients configured; all auth attempts will be rejected");
    }
    println!();
    println!("auth + replay + policy + TCP/UDP proxy + metrics. Ctrl-C to stop.");

    spawn_replay_sweeper(replay.clone());
    spawn_metrics_logger(metrics.clone());
    spawn_rate_limit_sweeper(rate_limiter.clone());

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let replay = replay.clone();
        let policy = policy.clone();
        let metrics = metrics.clone();
        let rate_limiter = rate_limiter.clone();
        let decoy_html = decoy_html.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(
                incoming,
                registry,
                replay,
                policy,
                metrics,
                rate_limiter,
                decoy_html,
            )
            .await
            {
                eprintln!("conn error: {e:#}");
            }
        });
    }
    Ok(())
}

fn spawn_replay_sweeper(replay: Arc<ReplayCache>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REPLAY_SWEEP_INTERVAL);
        tick.tick().await; // skip the immediate fire
        loop {
            tick.tick().await;
            let dropped = replay.sweep();
            if dropped > 0 {
                eprintln!(
                    "replay-cache: swept {dropped} expired entries (now {})",
                    replay.len()
                );
            }
        }
    });
}

fn spawn_metrics_logger(metrics: Arc<Metrics>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(METRICS_SNAPSHOT_INTERVAL);
        tick.tick().await; // skip the immediate fire
        loop {
            tick.tick().await;
            eprintln!("--- metrics ---\n{}", metrics.snapshot());
        }
    });
}

fn spawn_rate_limit_sweeper(rate_limiter: Arc<AuthRateLimiter>) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(RATE_LIMIT_SWEEP_INTERVAL);
        tick.tick().await; // skip the immediate fire
        loop {
            tick.tick().await;
            let dropped = rate_limiter.sweep();
            if dropped > 0 {
                eprintln!(
                    "rate-limit: swept {dropped} expired buckets (now {})",
                    rate_limiter.len()
                );
            }
        }
    });
}

async fn handle_conn(
    incoming: quinn::Incoming,
    registry: Arc<ClientRegistry>,
    replay: Arc<ReplayCache>,
    policy: Option<Arc<PolicyChecker>>,
    metrics: Arc<Metrics>,
    rate_limiter: Arc<AuthRateLimiter>,
    decoy_html: Arc<Vec<u8>>,
) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();

    // M13: if the client negotiated `h3` instead of `proteus/0.3`,
    // hand the connection to the embedded H3 decoy and exit before
    // touching the auth path.
    if negotiated_alpn(&conn).as_deref() == Some(H3_ALPN) {
        println!("accepted {peer}: h3 decoy");
        if let Err(e) = serve_h3_decoy(conn, decoy_html).await {
            eprintln!("h3 decoy {peer}: {e:#}");
        }
        return Ok(());
    }

    // M18.1: cap PROTEUS auth attempts per peer IP.
    if let Err(e) = rate_limiter.check_and_record(peer.ip()) {
        eprintln!("{peer}: rate-limited: {e}");
        metrics.rate_limited_inc();
        conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
        return Ok(());
    }

    println!("accepted {peer}");

    // ----- auth on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.context("accept_bi ctrl")?;
    let auth_frame = match tokio::time::timeout(AUTH_READ_TIMEOUT, read_frame(&mut ctrl_recv)).await
    {
        Ok(r) => r.context("read AUTH_REQUEST frame")?,
        Err(_) => {
            eprintln!(
                "{peer}: AUTH_REQUEST not received within {}s; closing",
                AUTH_READ_TIMEOUT.as_secs()
            );
            conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
            return Ok(());
        }
    };
    if auth_frame.frame_type != FrameType::AuthRequest {
        eprintln!(
            "{peer}: expected AuthRequest, got {:?}",
            auth_frame.frame_type
        );
        conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
        return Ok(());
    }
    metrics.auth_attempt();

    let req = match AuthRequest::decode(&auth_frame.payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{peer}: malformed AUTH_REQUEST: {e:#}");
            metrics.auth_failed_inc();
            conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
            return Ok(());
        }
    };

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    let client_id = match registry.verify(&req, &exporter) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{peer}: auth FAIL ({}): {e:#}", req.client_id);
            metrics.auth_failed_inc();
            reject_auth(&mut ctrl_send, &conn).await;
            return Ok(());
        }
    };

    if let Err(e) = replay.check_and_record(&client_id, &req.nonce) {
        eprintln!("{peer}: REPLAY rejected for {client_id}: {e:#}");
        metrics.replay_rejected_inc();
        reject_auth(&mut ctrl_send, &conn).await;
        return Ok(());
    }

    let resp_frame = Frame::new(FrameType::AuthResponse, AuthResponse::ok().encode()?)?;
    write_frame(&mut ctrl_send, &resp_frame)
        .await
        .context("write AUTH_RESPONSE")?;
    metrics.auth_success_inc();
    metrics.active_session_inc();
    println!("{peer}: auth OK as {client_id}");

    // ----- per-target proxy streams -----
    let peer_label = format!("{peer}/{client_id}");
    while let Ok((q_send, q_recv)) = conn.accept_bi().await {
        let label = peer_label.clone();
        let policy = policy.clone();
        let metrics = metrics.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_stream(q_send, q_recv, policy, metrics).await {
                eprintln!("proxy {label}: {e:#}");
            }
        });
    }
    metrics.active_session_dec();
    println!("{peer_label}: closed");
    Ok(())
}

async fn reject_auth(ctrl_send: &mut quinn::SendStream, conn: &quinn::Connection) {
    if let Ok(bytes) = AuthResponse::err(STATUS_AUTH_FAILED).encode()
        && let Ok(frame) = Frame::new(FrameType::AuthResponse, bytes)
    {
        let _ = write_frame(ctrl_send, &frame).await;
    }
    conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
}

async fn handle_proxy_stream(
    mut q_send: quinn::SendStream,
    mut q_recv: quinn::RecvStream,
    policy: Option<Arc<PolicyChecker>>,
    metrics: Arc<Metrics>,
) -> Result<()> {
    let open_frame = read_frame(&mut q_recv).await.context("read PROXY_OPEN")?;
    if open_frame.frame_type != FrameType::ProxyOpen {
        let _ = reject_proxy(&mut q_send, reject_codes::PROTOCOL_ERROR).await;
        bail!("expected PROXY_OPEN, got {:?}", open_frame.frame_type);
    }
    let open = match ProxyOpen::decode(&open_frame.payload) {
        Ok(o) => o,
        Err(e) => {
            let _ = reject_proxy(&mut q_send, reject_codes::PROTOCOL_ERROR).await;
            bail!("malformed PROXY_OPEN: {e:#}");
        }
    };

    match open.cmd.as_str() {
        "tcp" => {
            proxy_to_tcp(
                q_send,
                q_recv,
                open.host,
                open.port,
                policy.as_deref(),
                &metrics,
            )
            .await
        }
        "udp" => {
            proxy_to_udp(
                q_send,
                q_recv,
                open.host,
                open.port,
                policy.as_deref(),
                &metrics,
            )
            .await
        }
        other => {
            let _ = reject_proxy(&mut q_send, reject_codes::UNSUPPORTED_CMD).await;
            bail!("unsupported cmd {other:?}");
        }
    }
}

async fn reject_proxy(q_send: &mut quinn::SendStream, reason: u8) -> Result<()> {
    let frame = Frame::new(FrameType::ProxyReject, ProxyReject::new(reason).encode())?;
    write_frame(q_send, &frame)
        .await
        .context("write PROXY_REJECT")?;
    Ok(())
}

async fn resolve_target(host: &str, port: u16) -> Result<Vec<SocketAddr>> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
        .await
        .with_context(|| format!("resolve {host}:{port}"))?
        .collect();
    if addrs.is_empty() {
        bail!("{host}:{port} resolved to no addresses");
    }
    Ok(addrs)
}

async fn proxy_to_tcp(
    mut q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    host: String,
    port: u16,
    policy: Option<&PolicyChecker>,
    metrics: &Metrics,
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_tcp(port, &ips) {
            metrics.policy_rejected_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::POLICY_DENIED).await;
            bail!("policy denied tcp {host}:{port}: {e}");
        }
    }

    let tcp = match TcpStream::connect(&resolved[0]).await {
        Ok(s) => s,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            bail!("tcp connect {host}:{port} ({}): {e}", resolved[0]);
        }
    };
    println!("  proxy → tcp {host}:{port} ({})", resolved[0]);

    let accept = Frame::new(FrameType::ProxyAccept, Bytes::new())?;
    write_frame(&mut q_send, &accept)
        .await
        .context("write PROXY_ACCEPT")?;

    metrics.proxy_tcp_opened_inc();
    let (tcp_r, tcp_w) = tcp.into_split();
    proxy::bridge_quic_tcp(q_send, q_recv, tcp_r, tcp_w).await
}

async fn proxy_to_udp(
    mut q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    host: String,
    port: u16,
    policy: Option<&PolicyChecker>,
    metrics: &Metrics,
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_udp(port, &ips) {
            metrics.policy_rejected_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::POLICY_DENIED).await;
            bail!("policy denied udp {host}:{port}: {e}");
        }
    }

    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            bail!("udp bind: {e}");
        }
    };
    if let Err(e) = udp.connect(&resolved[0]).await {
        metrics.proxy_upstream_unreachable_inc();
        let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
        bail!("udp connect {host}:{port} ({}): {e}", resolved[0]);
    }
    println!("  proxy → udp {host}:{port} ({})", resolved[0]);

    let accept = Frame::new(FrameType::ProxyAccept, Bytes::new())?;
    write_frame(&mut q_send, &accept)
        .await
        .context("write PROXY_ACCEPT")?;

    metrics.proxy_udp_opened_inc();
    proxy::bridge_quic_udp(q_send, q_recv, udp).await
}

// ---------------- M13 H3 decoy ----------------

/// Pull the negotiated ALPN out of the Quinn handshake data. Used by
/// M13 to dispatch to the H3 decoy when the client offered `h3`.
fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    conn.handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|hd| hd.protocol)
}

/// Default HTML body the H3 decoy returns when no `decoy.static_page`
/// is set in the server config. Byte-identical to the nginx welcome
/// page so a prober sees a plausible default-nginx-install response.
/// Overridden at startup by an operator-supplied file if the config
/// has `decoy.static_page` — M3.4.
const DEFAULT_DECOY_HTML: &[u8] = b"<!DOCTYPE html>\n\
<html>\n\
<head>\n\
<title>Welcome to nginx!</title>\n\
<style>\n\
    body {\n\
        width: 35em;\n\
        margin: 0 auto;\n\
        font-family: Tahoma, Verdana, Arial, sans-serif;\n\
    }\n\
</style>\n\
</head>\n\
<body>\n\
<h1>Welcome to nginx!</h1>\n\
<p>If you see this page, the nginx web server is successfully installed and\n\
working. Further configuration is required.</p>\n\
\n\
<p>For online documentation and support please refer to\n\
<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\n\
Commercial support is available at\n\
<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\
\n\
<p><em>Thank you for using nginx.</em></p>\n\
</body>\n\
</html>\n";

/// M13 + M3.4 decoy — serve a static 200 OK to any H3 request on this
/// QUIC connection, using the operator-supplied HTML body (or the
/// embedded nginx welcome default). Headers (`server`, `accept-ranges`,
/// `content-type`) mirror a default nginx install so a passive prober
/// sees a coherent fake cover host. Shares the server cert with the
/// PROTEUS path. Spec v0.2 §11.
async fn serve_h3_decoy(conn: quinn::Connection, body: Arc<Vec<u8>>) -> Result<()> {
    let h3_q = h3_quinn::Connection::new(conn);
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> =
        h3::server::Connection::new(h3_q).await?;

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let (_req, mut stream) = match resolver.resolve_request().await {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("h3 decoy: resolve error: {e:#}");
                        continue;
                    }
                };
                let resp = http::Response::builder()
                    .status(200)
                    .header("server", "nginx/1.27.0")
                    .header("content-type", "text/html; charset=utf-8")
                    .header("accept-ranges", "bytes")
                    .body(())?;
                stream.send_response(resp).await?;
                stream
                    .send_data(bytes::Bytes::copy_from_slice(&body))
                    .await?;
                stream.finish().await?;
            }
            Ok(None) => break,
            Err(e) => {
                eprintln!("h3 decoy: accept error: {e:#}");
                break;
            }
        }
    }
    Ok(())
}
