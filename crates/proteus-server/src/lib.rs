//! PROTEUS server core, exposed as a library so integration tests can
//! spin up an in-process server, and the bin can stay thin.
//!
//! v0.4 M9.4 refactor: the entire accept loop + per-conn auth/policy/
//! proxy state used to live in `main.rs`. That made it impossible to
//! write integration tests for 0-RTT (M6.4) and connection migration
//! (M7.4) because there was no way to bind on `127.0.0.1:0`, read the
//! actual port back, run a client against it, then tear it down.
//!
//! Surface:
//! - [`Server::bind`] builds a QUIC endpoint + all server state from a
//!   parsed [`ServerConfig`].
//! - [`Server::local_addr`] returns the actual bound address (useful
//!   when `cfg.listen.addr` had port 0).
//! - [`Server::cert_sha256_hex`] returns the leaf cert pin, for client
//!   `cert_sha256` config.
//! - [`Server::metrics`] gives read-only access to counters so tests
//!   can assert on auth attempts, replay hits, etc.
//! - [`Server::run`] drives the accept loop + background sweepers
//!   forever. Returns when [`Server::shutdown`] is called or the
//!   endpoint errors out.
//! - [`Server::shutdown`] closes the QUIC endpoint with a generic
//!   close code; the `run` future resolves shortly after.

use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use proteus_core::{
    aead::{self, ProxyStreamAead},
    auth::{
        AuthRequest, AuthResponse, ClientRegistry, EXPORTER_LABEL, EXPORTER_LEN, STATUS_AUTH_FAILED,
    },
    config::ServerConfig,
    frame::{Frame, FrameType, read_frame, read_frame_aead, write_frame, write_frame_aead},
    metrics::Metrics,
    policy::PolicyChecker,
    proxy::{self, ProxyOpen, ProxyReject, reject as reject_codes},
    ratelimit::AuthRateLimiter,
    replay::ReplayCache,
    tls,
};
use tokio::net::{TcpStream, UdpSocket};

// ----------------- public constants -----------------

/// QUIC application close code on auth failure — same family as
/// `H3_GENERAL_PROTOCOL_ERROR` per spec v0.2 §8.4.
pub const AUTH_FAIL_CLOSE_CODE: u32 = 0x0101;

/// Max time to wait for the first AUTH_REQUEST frame after the
/// control stream is accepted. Slow-loris hardening (M18).
pub const AUTH_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// ALPN we advertise alongside `proteus/0.3` for the M13 decoy.
pub const H3_ALPN: &[u8] = b"h3";

/// Maximum PROTEUS auth attempts per peer IP per window. M18.1.
pub const RATE_LIMIT_MAX: usize = 30;
/// Rolling window for the auth rate limit.
pub const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
/// How often to sweep expired rate-limit buckets.
pub const RATE_LIMIT_SWEEP_INTERVAL: Duration = Duration::from_secs(120);

/// Per spec v0.2 §8.3.
pub const REPLAY_TTL: Duration = Duration::from_secs(300);

/// How often to sweep expired entries from the replay cache.
pub const REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

/// How often the metrics snapshot is written to stderr.
pub const METRICS_SNAPSHOT_INTERVAL: Duration = Duration::from_secs(30);

// ----------------- Server struct -----------------

/// Bag of shared per-connection state. Cloned cheaply into every
/// `tokio::spawn`ed `handle_conn`.
#[derive(Clone)]
struct ServerState {
    registry: Arc<ClientRegistry>,
    replay: Arc<ReplayCache>,
    policy: Option<Arc<PolicyChecker>>,
    metrics: Arc<Metrics>,
    rate_limiter: Arc<AuthRateLimiter>,
    decoy_html: Arc<Vec<u8>>,
}

/// Built, bound, ready-to-run PROTEUS server.
///
/// Usage:
/// ```ignore
/// let server = Server::bind(cfg)?;
/// println!("listening on {}", server.local_addr());
/// server.run().await
/// ```
pub struct Server {
    endpoint: quinn::Endpoint,
    local_addr: SocketAddr,
    cert_sha256: String,
    state: ServerState,
}

impl Server {
    /// Construct the server: install crypto provider (idempotent),
    /// build TLS config from `cfg.tls` (or self-signed fallback),
    /// bind the QUIC endpoint, and assemble all per-connection
    /// state. Does NOT start accepting connections — call
    /// [`Server::run`] for that.
    pub fn bind(cfg: ServerConfig) -> Result<Self> {
        tls::install_crypto_provider();
        let (qcfg, cert) = tls::server_config(cfg.tls.as_ref())?;
        let endpoint = quinn::Endpoint::server(qcfg, cfg.listen.addr)
            .with_context(|| format!("bind {}", cfg.listen.addr))?;
        let local_addr = endpoint.local_addr().context("query bound local_addr")?;

        let registry = Arc::new(ClientRegistry::from_config_map(cfg.clients.as_ref())?);
        let replay = Arc::new(ReplayCache::new(REPLAY_TTL));
        let policy: Option<Arc<PolicyChecker>> = cfg
            .policy
            .as_ref()
            .map(|p| Arc::new(PolicyChecker::from_config(p)));
        let metrics = Arc::new(Metrics::new());
        let rate_limiter = Arc::new(AuthRateLimiter::new(RATE_LIMIT_MAX, RATE_LIMIT_WINDOW));

        // M3.4 + M8.4: load decoy HTML from disk if `decoy.static_page`
        // is set; otherwise fall back to the embedded nginx welcome page.
        let decoy_html: Arc<Vec<u8>> = match cfg.decoy.as_ref() {
            Some(d) => {
                let bytes = std::fs::read(&d.static_page)
                    .with_context(|| format!("read decoy {}", d.static_page.display()))?;
                Arc::new(bytes)
            }
            None => Arc::new(DEFAULT_DECOY_HTML.to_vec()),
        };

        Ok(Self {
            endpoint,
            local_addr,
            cert_sha256: tls::cert_sha256_hex(&cert),
            state: ServerState {
                registry,
                replay,
                policy,
                metrics,
                rate_limiter,
                decoy_html,
            },
        })
    }

    /// Actual address the QUIC endpoint is listening on. Differs from
    /// `cfg.listen.addr` when port 0 was requested.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Lowercase hex SHA-256 of the server's leaf cert, suitable for
    /// pinning in a client config's `server.cert_sha256`.
    pub fn cert_sha256_hex(&self) -> &str {
        &self.cert_sha256
    }

    /// Read-only handle to the server's metrics counters. Useful in
    /// integration tests for asserting on auth/replay/policy events.
    pub fn metrics(&self) -> Arc<Metrics> {
        self.state.metrics.clone()
    }

    /// Number of configured client entries.
    pub fn clients_len(&self) -> usize {
        self.state.registry.len()
    }

    /// Whether a `policy:` section was present in the config.
    pub fn policy_enabled(&self) -> bool {
        self.state.policy.is_some()
    }

    /// Did the operator point `decoy.static_page` at a file (true), or
    /// are we serving the embedded nginx default (false)?
    pub fn decoy_is_file_backed(&self, cfg: &ServerConfig) -> bool {
        // Convenience accessor — pure function of the config we were
        // built from, but we don't keep the full cfg around so the
        // caller passes it back in.
        cfg.decoy.is_some()
    }

    /// Decoy body length in bytes.
    pub fn decoy_body_len(&self) -> usize {
        self.state.decoy_html.len()
    }

    /// Reference to the underlying Quinn endpoint. Tests can use this
    /// to wait for ongoing connections to drain, etc.
    pub fn endpoint(&self) -> &quinn::Endpoint {
        &self.endpoint
    }

    /// Trigger a graceful shutdown. Closes all active connections
    /// with `AUTH_FAIL_CLOSE_CODE` and unblocks the `run` future.
    pub fn shutdown(&self) {
        self.endpoint
            .close(AUTH_FAIL_CLOSE_CODE.into(), b"shutdown");
    }

    /// Run the accept loop + background sweepers. Returns when
    /// `shutdown` is called or the endpoint errors out.
    pub async fn run(self) -> Result<()> {
        spawn_replay_sweeper(self.state.replay.clone());
        spawn_metrics_logger(self.state.metrics.clone());
        spawn_rate_limit_sweeper(self.state.rate_limiter.clone());

        let endpoint = self.endpoint.clone();
        while let Some(incoming) = endpoint.accept().await {
            let state = self.state.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_conn(incoming, state).await {
                    eprintln!("conn error: {e:#}");
                }
            });
        }
        Ok(())
    }
}

// ----------------- background sweepers -----------------

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

// ----------------- per-connection handler -----------------

async fn handle_conn(incoming: quinn::Incoming, state: ServerState) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();

    // M13: if the client negotiated `h3` instead of `proteus/0.3`,
    // hand the connection to the embedded H3 decoy and exit before
    // touching the auth path.
    if negotiated_alpn(&conn).as_deref() == Some(H3_ALPN) {
        println!("accepted {peer}: h3 decoy");
        if let Err(e) = serve_h3_decoy(conn, state.decoy_html.clone()).await {
            eprintln!("h3 decoy {peer}: {e:#}");
        }
        return Ok(());
    }

    // M18.1: cap PROTEUS auth attempts per peer IP.
    if let Err(e) = state.rate_limiter.check_and_record(peer.ip()) {
        eprintln!("{peer}: rate-limited: {e}");
        state.metrics.rate_limited_inc();
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
    state.metrics.auth_attempt();

    let req = match AuthRequest::decode(&auth_frame.payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{peer}: malformed AUTH_REQUEST: {e:#}");
            state.metrics.auth_failed_inc();
            conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
            return Ok(());
        }
    };

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    let client_id = match state.registry.verify(&req, &exporter) {
        Ok(id) => id,
        Err(e) => {
            eprintln!("{peer}: auth FAIL ({}): {e:#}", req.client_id);
            state.metrics.auth_failed_inc();
            reject_auth(&mut ctrl_send, &conn).await;
            return Ok(());
        }
    };

    if let Err(e) = state.replay.check_and_record(&client_id, &req.nonce) {
        eprintln!("{peer}: REPLAY rejected for {client_id}: {e:#}");
        state.metrics.replay_rejected_inc();
        reject_auth(&mut ctrl_send, &conn).await;
        return Ok(());
    }

    let resp_frame = Frame::new(FrameType::AuthResponse, AuthResponse::ok().encode()?)?;
    write_frame(&mut ctrl_send, &resp_frame)
        .await
        .context("write AUTH_RESPONSE")?;
    state.metrics.auth_success_inc();
    state.metrics.active_session_inc();
    println!("{peer}: auth OK as {client_id}");

    // M5.4.1: derive the inner-AEAD session key. Each per-target
    // stream further derives its own subkey from this via the QUIC
    // stream id (`ProxyStreamAead::for_server`).
    let session_key: Arc<[u8; aead::KEY_LEN]> = Arc::new(
        aead::InnerAead::derive_key(&exporter, &req.nonce)
            .expect("derive_key: exporter + nonce are non-empty post-auth"),
    );

    // ----- per-target proxy streams -----
    let peer_label = format!("{peer}/{client_id}");
    while let Ok((q_send, q_recv)) = conn.accept_bi().await {
        let label = peer_label.clone();
        let policy = state.policy.clone();
        let metrics = state.metrics.clone();
        let session_key = session_key.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_stream(q_send, q_recv, policy, metrics, session_key).await
            {
                eprintln!("proxy {label}: {e:#}");
            }
        });
    }
    state.metrics.active_session_dec();
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
    session_key: Arc<[u8; aead::KEY_LEN]>,
) -> Result<()> {
    // M5.4.1: every frame on a per-target proxy stream is AEAD-wrapped
    // post-auth. Derive this stream's key + (send, recv) pair from the
    // session key plus the QUIC stream id.
    let stream_id = q_send.id().index();
    let mut sa = ProxyStreamAead::for_server(&session_key, stream_id);

    let open_frame = read_frame_aead(&mut q_recv, &mut sa.recv)
        .await
        .context("read PROXY_OPEN")?;
    if open_frame.frame_type != FrameType::ProxyOpen {
        let _ = reject_proxy(
            &mut q_send,
            reject_codes::PROTOCOL_ERROR,
            &mut sa.send,
            stream_id,
        )
        .await;
        bail!("expected PROXY_OPEN, got {:?}", open_frame.frame_type);
    }
    let open = match ProxyOpen::decode(&open_frame.payload) {
        Ok(o) => o,
        Err(e) => {
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::PROTOCOL_ERROR,
                &mut sa.send,
                stream_id,
            )
            .await;
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
                sa.send,
                sa.recv,
                stream_id,
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
                sa.send,
                sa.recv,
                stream_id,
            )
            .await
        }
        other => {
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::UNSUPPORTED_CMD,
                &mut sa.send,
                stream_id,
            )
            .await;
            bail!("unsupported cmd {other:?}");
        }
    }
}

async fn reject_proxy(
    q_send: &mut quinn::SendStream,
    reason: u8,
    aead_send: &mut aead::InnerAead,
    stream_id: u64,
) -> Result<()> {
    let frame = Frame {
        frame_type: FrameType::ProxyReject,
        flags: 0,
        stream_id,
        payload: ProxyReject::new(reason).encode(),
    };
    write_frame_aead(q_send, &frame, aead_send)
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

#[allow(clippy::too_many_arguments)]
async fn proxy_to_tcp(
    mut q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    host: String,
    port: u16,
    policy: Option<&PolicyChecker>,
    metrics: &Metrics,
    mut aead_send: aead::InnerAead,
    aead_recv: aead::InnerAead,
    stream_id: u64,
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::UPSTREAM_UNREACHABLE,
                &mut aead_send,
                stream_id,
            )
            .await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_tcp(port, &ips) {
            metrics.policy_rejected_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::POLICY_DENIED,
                &mut aead_send,
                stream_id,
            )
            .await;
            bail!("policy denied tcp {host}:{port}: {e}");
        }
    }

    let tcp = match TcpStream::connect(&resolved[0]).await {
        Ok(s) => s,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::UPSTREAM_UNREACHABLE,
                &mut aead_send,
                stream_id,
            )
            .await;
            bail!("tcp connect {host}:{port} ({}): {e}", resolved[0]);
        }
    };
    println!("  proxy → tcp {host}:{port} ({})", resolved[0]);

    let accept = Frame {
        frame_type: FrameType::ProxyAccept,
        flags: 0,
        stream_id,
        payload: Bytes::new(),
    };
    write_frame_aead(&mut q_send, &accept, &mut aead_send)
        .await
        .context("write PROXY_ACCEPT")?;

    metrics.proxy_tcp_opened_inc();
    let (tcp_r, tcp_w) = tcp.into_split();
    proxy::bridge_quic_tcp(q_send, q_recv, tcp_r, tcp_w, aead_send, aead_recv).await
}

#[allow(clippy::too_many_arguments)]
async fn proxy_to_udp(
    mut q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    host: String,
    port: u16,
    policy: Option<&PolicyChecker>,
    metrics: &Metrics,
    mut aead_send: aead::InnerAead,
    aead_recv: aead::InnerAead,
    stream_id: u64,
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::UPSTREAM_UNREACHABLE,
                &mut aead_send,
                stream_id,
            )
            .await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_udp(port, &ips) {
            metrics.policy_rejected_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::POLICY_DENIED,
                &mut aead_send,
                stream_id,
            )
            .await;
            bail!("policy denied udp {host}:{port}: {e}");
        }
    }

    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            metrics.proxy_upstream_unreachable_inc();
            let _ = reject_proxy(
                &mut q_send,
                reject_codes::UPSTREAM_UNREACHABLE,
                &mut aead_send,
                stream_id,
            )
            .await;
            bail!("udp bind: {e}");
        }
    };
    if let Err(e) = udp.connect(&resolved[0]).await {
        metrics.proxy_upstream_unreachable_inc();
        let _ = reject_proxy(
            &mut q_send,
            reject_codes::UPSTREAM_UNREACHABLE,
            &mut aead_send,
            stream_id,
        )
        .await;
        bail!("udp connect {host}:{port} ({}): {e}", resolved[0]);
    }
    println!("  proxy → udp {host}:{port} ({})", resolved[0]);

    let accept = Frame {
        frame_type: FrameType::ProxyAccept,
        flags: 0,
        stream_id,
        payload: Bytes::new(),
    };
    write_frame_aead(&mut q_send, &accept, &mut aead_send)
        .await
        .context("write PROXY_ACCEPT")?;

    metrics.proxy_udp_opened_inc();
    proxy::bridge_quic_udp(q_send, q_recv, udp, aead_send, aead_recv).await
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
/// has `decoy.static_page` — M3.4 / M8.4.
pub const DEFAULT_DECOY_HTML: &[u8] = b"<!DOCTYPE html>\n\
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
