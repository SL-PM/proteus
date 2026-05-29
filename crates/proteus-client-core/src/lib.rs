//! PROTEUS client engine as a library (v0.6 client app).
//!
//! Extracted from the `proteus-client` CLI so the same connect/auth/
//! SOCKS5 engine drives both the CLI and the Tauri GUI. Exposes:
//!
//! - [`connect`] — dial + authenticate + start the SOCKS5 listener,
//!   returning a [`RunningClient`] handle.
//! - [`RunningClient::stats`] — live link stats (up/down bytes + rate,
//!   ping) read straight from the QUIC connection: `Connection::rtt`
//!   for ping and `Connection::stats().udp_tx/udp_rx` for throughput.
//!   No protocol changes, no per-stream instrumentation.
//! - [`RunningClient::stop`] — tear the SOCKS5 listener + connection down.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Instant,
};

use anyhow::{Context, Result, bail};
use proteus_core::{
    aead::{self, ProxyStreamAead},
    auth::{
        AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN, SigningKey, load_signing_key,
        parse_signing_key_b64,
    },
    config::ClientConfig,
    fingerprint::Distribution,
    frame::{
        Frame, FrameType, read_frame, write_frame_aead_maybe_padded, write_frame_maybe_padded,
    },
    jitter::{Jitter, JitterPlan},
    proxy::{self, ProxyOpen},
    subscription::Subscription,
    tls,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

// SOCKS5 wire constants (RFC 1928).
const SOCKS5_VER: u8 = 0x05;
const SOCKS5_AUTH_NONE: u8 = 0x00;
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8 = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8 = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

/// Per-stream shaping derived from the client config, shared into every
/// spawned SOCKS5 handler.
#[derive(Clone)]
struct Shaping {
    session_key: Arc<[u8; aead::KEY_LEN]>,
    pad_buckets: Option<Arc<Vec<usize>>>,
    jitter: Option<JitterPlan>,
    profile_dist: Option<Arc<Distribution>>,
}

/// A live snapshot of the connection's link stats.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// True while the QUIC connection is open.
    pub connected: bool,
    /// SOCKS5 listener address apps point at.
    pub socks5_addr: SocketAddr,
    /// Cumulative bytes sent / received on the wire (incl. QUIC overhead).
    pub up_bytes: u64,
    pub down_bytes: u64,
    /// Throughput since the previous `stats()` call, bytes/second.
    pub up_bps: f64,
    pub down_bps: f64,
    /// Current smoothed round-trip time, milliseconds.
    pub ping_ms: f64,
}

struct Sample {
    at: Instant,
    up: u64,
    down: u64,
}

/// A connected, running PROTEUS client: an authenticated QUIC link plus
/// a SOCKS5 listener. Poll [`stats`](Self::stats) for the UI; call
/// [`stop`](Self::stop) to disconnect.
pub struct RunningClient {
    endpoint: quinn::Endpoint,
    conn: Arc<quinn::Connection>,
    socks5_addr: SocketAddr,
    accept_task: tokio::task::JoinHandle<()>,
    last: Mutex<Sample>,
}

impl RunningClient {
    /// The SOCKS5 listener address (useful when the config requested
    /// an ephemeral port).
    pub fn socks5_addr(&self) -> SocketAddr {
        self.socks5_addr
    }

    /// Read a fresh stats snapshot. Rates are computed against the
    /// previous call, so any polling cadence yields correct bytes/sec.
    pub fn stats(&self) -> Stats {
        let s = self.conn.stats();
        let up = s.udp_tx.bytes;
        let down = s.udp_rx.bytes;
        let now = Instant::now();

        let (up_bps, down_bps) = {
            let mut last = self.last.lock().expect("stats lock");
            let dt = now
                .saturating_duration_since(last.at)
                .as_secs_f64()
                .max(1e-3);
            let u = up.saturating_sub(last.up) as f64 / dt;
            let d = down.saturating_sub(last.down) as f64 / dt;
            *last = Sample { at: now, up, down };
            (u, d)
        };

        Stats {
            connected: self.conn.close_reason().is_none(),
            socks5_addr: self.socks5_addr,
            up_bytes: up,
            down_bytes: down,
            up_bps,
            down_bps,
            ping_ms: self.conn.rtt().as_secs_f64() * 1000.0,
        }
    }

    /// Disconnect: stop accepting SOCKS5 connections and close the link.
    pub async fn stop(self) {
        self.accept_task.abort();
        self.conn.close(0u32.into(), b"client stop");
        self.endpoint.close(0u32.into(), b"");
        self.endpoint.wait_idle().await;
    }
}

/// Everything `connect_inner` needs: server endpoint + identity (inline
/// signing key) + local SOCKS5 address + pre-built per-stream shaping.
struct ConnectParams {
    server_addr: SocketAddr,
    sni: String,
    cert_sha256: String,
    client_id: String,
    sk: SigningKey,
    socks5_listen: SocketAddr,
    pad_buckets: Option<Arc<Vec<usize>>>,
    jitter: Option<JitterPlan>,
    profile_dist: Option<Arc<Distribution>>,
}

/// Dial the PROTEUS server from a parsed config file, authenticate, and
/// start the SOCKS5 listener. Returns once auth succeeds and the
/// listener is bound; the accept loop runs in a background task.
pub async fn connect(cfg: ClientConfig) -> Result<RunningClient> {
    let sk = load_signing_key(&cfg.identity.private_key)?;

    // v0.5 M16.5: profile-driven sizing takes precedence over bucket
    // padding (its candidate sizes serve as pad_buckets; profile_dist
    // carries the sampling weights).
    cfg.profile_padding.validate()?;
    let profile_dist: Option<Arc<Distribution>> = if cfg.profile_padding.enabled {
        Some(Arc::new(cfg.profile_padding.to_distribution()))
    } else {
        None
    };
    let pad_buckets: Option<Arc<Vec<usize>>> = if cfg.profile_padding.enabled {
        Some(Arc::new(cfg.profile_padding.candidate_sizes()))
    } else if cfg.padding.enabled {
        Some(Arc::new(cfg.padding.effective_buckets().to_vec()))
    } else {
        None
    };

    cfg.timing_jitter.validate()?;
    let jitter: Option<JitterPlan> = if cfg.timing_jitter.enabled {
        Some(JitterPlan::new(
            Jitter::new(cfg.timing_jitter.min_ms, cfg.timing_jitter.max_ms),
            cfg.timing_jitter.burst,
        ))
    } else {
        None
    };

    connect_inner(ConnectParams {
        server_addr: cfg.server.addr,
        sni: cfg.server.sni,
        cert_sha256: cfg.server.cert_sha256,
        client_id: cfg.identity.client_id,
        sk,
        socks5_listen: cfg.socks5.listen,
        pad_buckets,
        jitter,
        profile_dist,
    })
    .await
}

/// Dial from a `proteus://…` subscription blob (one-click import), with
/// the SOCKS5 listener on `socks5_listen`. DPI camouflage is ON by default
/// for subscription clients (bucket padding + light timing jitter on the
/// upload direction); the server shapes the download direction itself.
pub async fn connect_subscription(url: &str, socks5_listen: SocketAddr) -> Result<RunningClient> {
    let sub = Subscription::from_url(url)?;
    let sk = parse_signing_key_b64(&sub.private_key_b64)?;
    let server_addr: SocketAddr = sub.server_addr.parse().with_context(|| {
        format!(
            "subscription server_addr {:?} is not host:port",
            sub.server_addr
        )
    })?;
    // v0.6 DPI camouflage: subscription clients shape by default — bucket-
    // pad the upload direction + light timing jitter (small range + burst,
    // so bulk throughput is barely affected). The server shapes the
    // download direction via its own config; receivers auto-depad, so no
    // negotiation is needed.
    let pad_buckets = Some(std::sync::Arc::new(
        proteus_core::padding::DEFAULT_BUCKETS.to_vec(),
    ));
    let jitter = Some(JitterPlan::new(Jitter::new(0, 1), 64));
    connect_inner(ConnectParams {
        server_addr,
        sni: sub.sni,
        cert_sha256: sub.cert_sha256,
        client_id: sub.client_id,
        sk,
        socks5_listen,
        pad_buckets,
        jitter,
        profile_dist: None,
    })
    .await
}

async fn connect_inner(p: ConnectParams) -> Result<RunningClient> {
    tls::install_crypto_provider();
    let qcfg = tls::client_config(&p.cert_sha256)?;

    let local: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let mut endpoint = quinn::Endpoint::client(local).context("bind client UDP")?;
    endpoint.set_default_client_config(qcfg);

    let conn = endpoint
        .connect(p.server_addr, &p.sni)
        .context("connect setup")?
        .await
        .context("handshake")?;

    // ----- authenticate once on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    let req = AuthRequest::sign(&p.client_id, &p.sk, &exporter)?;
    write_frame_maybe_padded(
        &mut ctrl_send,
        &Frame::new(FrameType::AuthRequest, req.encode()?)?,
        p.pad_buckets.as_deref().map(|v| v.as_slice()),
    )
    .await
    .context("write AUTH_REQUEST")?;

    let resp_frame = read_frame(&mut ctrl_recv)
        .await
        .context("read AUTH_RESPONSE")?;
    if resp_frame.frame_type != FrameType::AuthResponse {
        bail!("expected AuthResponse, got {:?}", resp_frame.frame_type);
    }
    let resp = AuthResponse::decode(&resp_frame.payload)?;
    if resp.status != 0 {
        bail!("auth rejected by server (status={})", resp.status);
    }

    // M5.4.1: derive the inner-AEAD session key.
    let session_key: Arc<[u8; aead::KEY_LEN]> = Arc::new(
        aead::InnerAead::derive_key(&exporter, &req.nonce)
            .expect("derive_key: exporter + nonce are non-empty post-auth"),
    );

    let conn = Arc::new(conn);
    let shaping = Shaping {
        session_key,
        pad_buckets: p.pad_buckets,
        jitter: p.jitter,
        profile_dist: p.profile_dist,
    };

    // ----- SOCKS5 listener + accept loop -----
    let listener = TcpListener::bind(p.socks5_listen)
        .await
        .with_context(|| format!("bind SOCKS5 {}", p.socks5_listen))?;
    let socks5_addr = listener.local_addr().context("socks5 local_addr")?;

    let accept_conn = conn.clone();
    let accept_task = tokio::spawn(async move {
        while let Ok((sock, peer)) = listener.accept().await {
            let conn = accept_conn.clone();
            let shaping = shaping.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_socks5(sock, conn, shaping).await {
                    eprintln!("socks5 {peer}: {e:#}");
                }
            });
        }
    });

    let s = conn.stats();
    let last = Mutex::new(Sample {
        at: Instant::now(),
        up: s.udp_tx.bytes,
        down: s.udp_rx.bytes,
    });

    Ok(RunningClient {
        endpoint,
        conn,
        socks5_addr,
        accept_task,
        last,
    })
}

async fn handle_socks5(
    mut sock: TcpStream,
    qconn: Arc<quinn::Connection>,
    sh: Shaping,
) -> Result<()> {
    let pad_buckets = sh.pad_buckets.as_deref().map(|v| v.as_slice());

    // ----- Greeting -----
    let mut hdr = [0u8; 2];
    sock.read_exact(&mut hdr).await.context("read greeting")?;
    if hdr[0] != SOCKS5_VER {
        bail!("unsupported SOCKS version 0x{:02x}", hdr[0]);
    }
    let nmethods = hdr[1] as usize;
    let mut methods = vec![0u8; nmethods];
    sock.read_exact(&mut methods)
        .await
        .context("read methods")?;
    if !methods.contains(&SOCKS5_AUTH_NONE) {
        sock.write_all(&[SOCKS5_VER, SOCKS5_AUTH_NO_ACCEPTABLE])
            .await
            .ok();
        bail!("no acceptable SOCKS5 method (we offer only no-auth)");
    }
    sock.write_all(&[SOCKS5_VER, SOCKS5_AUTH_NONE])
        .await
        .context("write method select")?;

    // ----- Request -----
    let mut req = [0u8; 4];
    sock.read_exact(&mut req).await.context("read request")?;
    if req[0] != SOCKS5_VER {
        bail!("bad request version 0x{:02x}", req[0]);
    }
    if req[1] != SOCKS5_CMD_CONNECT {
        send_socks5_reply(&mut sock, SOCKS5_REP_CMD_NOT_SUPPORTED).await?;
        bail!("unsupported SOCKS command 0x{:02x} (only CONNECT)", req[1]);
    }
    let host = match req[3] {
        SOCKS5_ATYP_IPV4 => {
            let mut b = [0u8; 4];
            sock.read_exact(&mut b).await.context("read IPv4")?;
            Ipv4Addr::from(b).to_string()
        }
        SOCKS5_ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await.context("read domain len")?;
            let mut domain = vec![0u8; len[0] as usize];
            sock.read_exact(&mut domain)
                .await
                .context("read domain bytes")?;
            String::from_utf8(domain).context("domain not utf-8")?
        }
        SOCKS5_ATYP_IPV6 => {
            let mut b = [0u8; 16];
            sock.read_exact(&mut b).await.context("read IPv6")?;
            Ipv6Addr::from(b).to_string()
        }
        atyp => {
            send_socks5_reply(&mut sock, SOCKS5_REP_ATYP_NOT_SUPPORTED).await?;
            bail!("unsupported SOCKS5 atyp 0x{atyp:02x}");
        }
    };
    let mut port_buf = [0u8; 2];
    sock.read_exact(&mut port_buf).await.context("read port")?;
    let port = u16::from_be_bytes(port_buf);

    // ----- Open QUIC proxy stream + PROXY_OPEN (AEAD-wrapped) -----
    let (mut q_send, q_recv) = qconn.open_bi().await.context("open proxy bi")?;
    let stream_id = q_send.id().index();
    let mut sa = ProxyStreamAead::for_client(&sh.session_key, stream_id);

    let open = ProxyOpen::new_tcp(&host, port);
    let open_frame = Frame {
        frame_type: FrameType::ProxyOpen,
        flags: 0,
        stream_id,
        payload: open.encode()?,
    };
    write_frame_aead_maybe_padded(&mut q_send, &open_frame, &mut sa.send, pad_buckets)
        .await
        .context("write PROXY_OPEN")?;

    // Optimistic open (v0.6): don't block on PROXY_ACCEPT. Reply "success"
    // to the app right away so its first bytes (e.g. the TLS ClientHello)
    // pipeline straight behind PROXY_OPEN — saving one tunnel RTT per
    // connection. The bridge consumes the server's verdict frame
    // (PROXY_ACCEPT is skipped; PROXY_REJECT closes the stream).
    send_socks5_reply(&mut sock, SOCKS5_REP_SUCCESS).await?;

    // ----- Bridge SOCKS5 socket ↔ QUIC proxy stream -----
    let (tcp_r, tcp_w) = sock.into_split();
    let bridge_buckets = sh.pad_buckets.as_deref().map(|v| v.to_vec());
    let bridge_profile = sh.profile_dist.as_deref().cloned();
    // Idle padding is server-only; client passes None. Jitter (M7.5) +
    // profile sizing (M16.5) ARE applied client-side.
    proxy::bridge_quic_tcp(
        q_send,
        q_recv,
        tcp_r,
        tcp_w,
        sa.send,
        sa.recv,
        bridge_buckets,
        None,
        sh.jitter,
        bridge_profile,
    )
    .await
}

async fn send_socks5_reply(sock: &mut TcpStream, rep: u8) -> Result<()> {
    sock.write_all(&[SOCKS5_VER, rep, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .context("write SOCKS5 reply")
}
