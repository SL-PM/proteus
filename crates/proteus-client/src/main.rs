//! PROTEUS client (v0.3 research prototype).
//!
//! M9: dial QUIC, authenticate once, then run a SOCKS5 CONNECT listener
//! on `socks5.listen` (default `127.0.0.1:1080`). Each incoming SOCKS5
//! connection opens a new QUIC proxy stream to the PROTEUS server,
//! sends PROXY_OPEN with the target, replies the appropriate SOCKS5
//! status back to the local client, and on PROXY_ACCEPT bridges the
//! two sockets via [`proteus_core::proxy::bridge_quic_tcp`].
//!
//! Authentication is paid once at startup; per-target streams are
//! free thereafter. Only SOCKS5 CONNECT + no-auth is supported in v0.3;
//! UDP_ASSOCIATE / BIND / GSSAPI are out-of-scope.

use std::{
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use anyhow::{Context, Result, bail};
use clap::Parser;
use proteus_core::{
    aead::{self, ProxyStreamAead},
    auth::{AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN, load_signing_key},
    config::ClientConfig,
    frame::{
        Frame, FrameType, read_frame, read_frame_aead, write_frame_aead_maybe_padded,
        write_frame_maybe_padded,
    },
    proxy::{self, ProxyOpen, ProxyReject, reject as reject_codes},
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
const SOCKS5_REP_GENERAL_FAILURE: u8 = 0x01;
const SOCKS5_REP_RULESET: u8 = 0x02;
const SOCKS5_REP_HOST_UNREACHABLE: u8 = 0x04;
const SOCKS5_REP_CMD_NOT_SUPPORTED: u8 = 0x07;
const SOCKS5_REP_ATYP_NOT_SUPPORTED: u8 = 0x08;

#[derive(Parser, Debug)]
#[command(
    name = "proteus-client",
    version,
    about = "PROTEUS client (v0.3 research prototype)",
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
    let cfg = ClientConfig::from_yaml_file(&cli.config)?;
    let sk = load_signing_key(&cfg.identity.private_key)?;

    tls::install_crypto_provider();
    let qcfg = tls::client_config(&cfg.server.cert_sha256)?;

    let local: SocketAddr = "0.0.0.0:0".parse()?;
    let mut endpoint = quinn::Endpoint::client(local).context("bind client UDP")?;
    endpoint.set_default_client_config(qcfg);

    let conn = endpoint
        .connect(cfg.server.addr, &cfg.server.sni)
        .context("connect setup")?
        .await
        .context("handshake")?;
    println!("connected; remote={}", conn.remote_address());

    // ----- authenticate once on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;
    // v0.5 M16.5: profile-driven sizing takes precedence over bucket
    // padding (its candidate sizes serve as pad_buckets for buf +
    // fallback; profile_dist carries the sampling weights).
    cfg.profile_padding.validate()?;
    let profile_dist: Option<Arc<proteus_core::fingerprint::Distribution>> =
        if cfg.profile_padding.enabled {
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

    // v0.5-rc.2 M7.5: client-side send-path timing jitter. Validate the
    // range up front; build a sampler if enabled.
    cfg.timing_jitter.validate()?;
    let jitter: Option<proteus_core::jitter::JitterPlan> = if cfg.timing_jitter.enabled {
        Some(proteus_core::jitter::JitterPlan::new(
            proteus_core::jitter::Jitter::new(cfg.timing_jitter.min_ms, cfg.timing_jitter.max_ms),
            cfg.timing_jitter.burst,
        ))
    } else {
        None
    };

    let req = AuthRequest::sign(&cfg.identity.client_id, &sk, &exporter)?;
    write_frame_maybe_padded(
        &mut ctrl_send,
        &Frame::new(FrameType::AuthRequest, req.encode()?)?,
        pad_buckets.as_deref().map(|v| v.as_slice()),
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
    println!("auth OK as {}", cfg.identity.client_id);

    // M5.4.1: derive the inner-AEAD session key. Per-proxy-stream
    // subkeys come out of ProxyStreamAead::for_client.
    let session_key: Arc<[u8; aead::KEY_LEN]> = Arc::new(
        aead::InnerAead::derive_key(&exporter, &req.nonce)
            .expect("derive_key: exporter + nonce are non-empty post-auth"),
    );

    // ----- SOCKS5 listener -----
    let conn = Arc::new(conn);
    let listener = TcpListener::bind(cfg.socks5.listen)
        .await
        .with_context(|| format!("bind SOCKS5 {}", cfg.socks5.listen))?;
    println!("SOCKS5 CONNECT listening on {}", cfg.socks5.listen);
    println!("(Ctrl-C to stop)");

    loop {
        let (sock, peer) = listener.accept().await.context("accept SOCKS5")?;
        let conn = conn.clone();
        let session_key = session_key.clone();
        let pad_buckets = pad_buckets.clone();
        let profile_dist = profile_dist.clone();
        tokio::spawn(async move {
            if let Err(e) =
                handle_socks5(sock, conn, session_key, pad_buckets, jitter, profile_dist).await
            {
                eprintln!("socks5 {peer}: {e:#}");
            }
        });
    }
}

async fn handle_socks5(
    mut sock: TcpStream,
    qconn: Arc<quinn::Connection>,
    session_key: Arc<[u8; aead::KEY_LEN]>,
    padding_buckets: Option<Arc<Vec<usize>>>,
    jitter: Option<proteus_core::jitter::JitterPlan>,
    profile_dist: Option<Arc<proteus_core::fingerprint::Distribution>>,
) -> Result<()> {
    let pad_buckets = padding_buckets.as_deref().map(|v| v.as_slice());
    // ----- Greeting: [ver, nmethods, methods...] -----
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

    // ----- Request: [ver, cmd, rsv, atyp, dst.addr, dst.port] -----
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
    println!("SOCKS5 CONNECT {host}:{port}");

    // ----- Open QUIC proxy stream + PROXY_OPEN (AEAD-wrapped) -----
    let (mut q_send, mut q_recv) = qconn.open_bi().await.context("open proxy bi")?;
    let stream_id = q_send.id().index();
    let mut sa = ProxyStreamAead::for_client(&session_key, stream_id);

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

    // ----- Wait for PROXY_ACCEPT / PROXY_REJECT (AEAD-wrapped) -----
    let resp = read_frame_aead(&mut q_recv, &mut sa.recv)
        .await
        .context("read PROXY_ACCEPT/REJECT")?;
    let rep = match resp.frame_type {
        FrameType::ProxyAccept => SOCKS5_REP_SUCCESS,
        FrameType::ProxyReject => {
            let r = ProxyReject::decode(&resp.payload)?;
            eprintln!(
                "  proxy rejected {host}:{port}: {} (0x{:02x})",
                r.name(),
                r.reason
            );
            map_reject_to_socks5(r.reason)
        }
        other => {
            eprintln!("  unexpected reply on proxy stream: {other:?}");
            SOCKS5_REP_GENERAL_FAILURE
        }
    };
    send_socks5_reply(&mut sock, rep).await?;
    if rep != SOCKS5_REP_SUCCESS {
        return Ok(());
    }

    // ----- Bridge SOCKS5 socket ↔ QUIC proxy stream -----
    let (tcp_r, tcp_w) = sock.into_split();
    let bridge_buckets = padding_buckets.as_deref().map(|v| v.to_vec());
    let bridge_profile = profile_dist.as_deref().cloned();
    // Idle padding is server-only in v0.5-rc.1; client passes None.
    // Timing jitter (M7.5) + profile sizing (M16.5) ARE applied client-side.
    proxy::bridge_quic_tcp(
        q_send,
        q_recv,
        tcp_r,
        tcp_w,
        sa.send,
        sa.recv,
        bridge_buckets,
        None,
        jitter,
        bridge_profile,
    )
    .await
}

async fn send_socks5_reply(sock: &mut TcpStream, rep: u8) -> Result<()> {
    // [ver, rep, rsv=0, atyp=IPv4, bnd.addr=0.0.0.0, bnd.port=0]
    sock.write_all(&[SOCKS5_VER, rep, 0x00, SOCKS5_ATYP_IPV4, 0, 0, 0, 0, 0, 0])
        .await
        .context("write SOCKS5 reply")
}

fn map_reject_to_socks5(reason: u8) -> u8 {
    match reason {
        reject_codes::POLICY_DENIED => SOCKS5_REP_RULESET,
        reject_codes::UPSTREAM_UNREACHABLE => SOCKS5_REP_HOST_UNREACHABLE,
        reject_codes::UNSUPPORTED_CMD => SOCKS5_REP_CMD_NOT_SUPPORTED,
        reject_codes::PROTOCOL_ERROR => SOCKS5_REP_GENERAL_FAILURE,
        _ => SOCKS5_REP_GENERAL_FAILURE,
    }
}
