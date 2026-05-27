//! PROTEUS server (v0.3 research prototype).
//!
//! M12: auth + replay cache + per-target proxy streams for TCP and UDP,
//! plus a server-side policy engine that vets each target before connect.
//! For each connection:
//!   1. accept control stream, run auth + replay check
//!   2. on success: AUTH_RESPONSE(ok), then loop `accept_bi()` for
//!      additional bidi streams. Each is treated as a proxy stream:
//!      read PROXY_OPEN, resolve the target host, run the policy check,
//!      then either bridge to TCP/UDP or PROXY_REJECT with a code.
//!   3. on auth failure: `H3_GENERAL_PROTOCOL_ERROR` close (no plaintext)
//!
//! Decoy (M13) is the last v0.3 protocol piece still missing.

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
    policy::PolicyChecker,
    proxy::{self, ProxyOpen, ProxyReject, reject as reject_codes},
    replay::ReplayCache,
    tls,
};
use tokio::net::{TcpStream, UdpSocket};

/// QUIC application close code on auth failure — same family as
/// `H3_GENERAL_PROTOCOL_ERROR` per spec v0.2 §8.4.
const AUTH_FAIL_CLOSE_CODE: u32 = 0x0101;

/// Per spec v0.2 §8.3.
const REPLAY_TTL: Duration = Duration::from_secs(300);

/// How often to sweep expired entries from the replay cache.
const REPLAY_SWEEP_INTERVAL: Duration = Duration::from_secs(60);

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
    if registry.is_empty() {
        eprintln!("warning: no clients configured; all auth attempts will be rejected");
    }
    println!();
    println!("auth + replay cache + policy + TCP/UDP proxy. Ctrl-C to stop.");

    spawn_replay_sweeper(replay.clone());

    while let Some(incoming) = endpoint.accept().await {
        let registry = registry.clone();
        let replay = replay.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_conn(incoming, registry, replay, policy).await {
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

async fn handle_conn(
    incoming: quinn::Incoming,
    registry: Arc<ClientRegistry>,
    replay: Arc<ReplayCache>,
    policy: Option<Arc<PolicyChecker>>,
) -> Result<()> {
    let conn = incoming.await.context("handshake")?;
    let peer = conn.remote_address();
    println!("accepted {peer}");

    // ----- auth on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.accept_bi().await.context("accept_bi ctrl")?;
    let auth_frame = read_frame(&mut ctrl_recv)
        .await
        .context("read AUTH_REQUEST frame")?;
    if auth_frame.frame_type != FrameType::AuthRequest {
        eprintln!(
            "{peer}: expected AuthRequest, got {:?}",
            auth_frame.frame_type
        );
        conn.close(AUTH_FAIL_CLOSE_CODE.into(), b"");
        return Ok(());
    }
    let req = match AuthRequest::decode(&auth_frame.payload) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("{peer}: malformed AUTH_REQUEST: {e:#}");
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
            reject_auth(&mut ctrl_send, &conn).await;
            return Ok(());
        }
    };

    if let Err(e) = replay.check_and_record(&client_id, &req.nonce) {
        eprintln!("{peer}: REPLAY rejected for {client_id}: {e:#}");
        reject_auth(&mut ctrl_send, &conn).await;
        return Ok(());
    }

    let resp_frame = Frame::new(FrameType::AuthResponse, AuthResponse::ok().encode()?)?;
    write_frame(&mut ctrl_send, &resp_frame)
        .await
        .context("write AUTH_RESPONSE")?;
    println!("{peer}: auth OK as {client_id}");

    // ----- per-target proxy streams -----
    let peer_label = format!("{peer}/{client_id}");
    while let Ok((q_send, q_recv)) = conn.accept_bi().await {
        let label = peer_label.clone();
        let policy = policy.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_proxy_stream(q_send, q_recv, policy).await {
                eprintln!("proxy {label}: {e:#}");
            }
        });
    }
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
        "tcp" => proxy_to_tcp(q_send, q_recv, open.host, open.port, policy.as_deref()).await,
        "udp" => proxy_to_udp(q_send, q_recv, open.host, open.port, policy.as_deref()).await,
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

/// Resolve a `host:port` string via tokio. Returns the full list of
/// `SocketAddr` so the caller can both run policy on every IP and pick
/// one to actually connect to.
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
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_tcp(port, &ips) {
            let _ = reject_proxy(&mut q_send, reject_codes::POLICY_DENIED).await;
            bail!("policy denied tcp {host}:{port}: {e}");
        }
    }

    let tcp = match TcpStream::connect(&resolved[0]).await {
        Ok(s) => s,
        Err(e) => {
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            bail!("tcp connect {host}:{port} ({}): {e}", resolved[0]);
        }
    };
    println!("  proxy → tcp {host}:{port} ({})", resolved[0]);

    let accept = Frame::new(FrameType::ProxyAccept, Bytes::new())?;
    write_frame(&mut q_send, &accept)
        .await
        .context("write PROXY_ACCEPT")?;

    let (tcp_r, tcp_w) = tcp.into_split();
    proxy::bridge_quic_tcp(q_send, q_recv, tcp_r, tcp_w).await
}

async fn proxy_to_udp(
    mut q_send: quinn::SendStream,
    q_recv: quinn::RecvStream,
    host: String,
    port: u16,
    policy: Option<&PolicyChecker>,
) -> Result<()> {
    let resolved = match resolve_target(&host, port).await {
        Ok(v) => v,
        Err(e) => {
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            return Err(e);
        }
    };

    if let Some(p) = policy {
        let ips: Vec<IpAddr> = resolved.iter().map(|s| s.ip()).collect();
        if let Err(e) = p.check_udp(port, &ips) {
            let _ = reject_proxy(&mut q_send, reject_codes::POLICY_DENIED).await;
            bail!("policy denied udp {host}:{port}: {e}");
        }
    }

    let udp = match UdpSocket::bind("0.0.0.0:0").await {
        Ok(s) => s,
        Err(e) => {
            let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
            bail!("udp bind: {e}");
        }
    };
    if let Err(e) = udp.connect(&resolved[0]).await {
        let _ = reject_proxy(&mut q_send, reject_codes::UPSTREAM_UNREACHABLE).await;
        bail!("udp connect {host}:{port} ({}): {e}", resolved[0]);
    }
    println!("  proxy → udp {host}:{port} ({})", resolved[0]);

    let accept = Frame::new(FrameType::ProxyAccept, Bytes::new())?;
    write_frame(&mut q_send, &accept)
        .await
        .context("write PROXY_ACCEPT")?;

    proxy::bridge_quic_udp(q_send, q_recv, udp).await
}
