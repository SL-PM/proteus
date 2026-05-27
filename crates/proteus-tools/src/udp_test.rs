//! `proteus-tools udp-test` — one-shot UDP proxy echo via a running
//! PROTEUS server. Reuses `ClientConfig` from `proteus-core::config`,
//! authenticates the same way as `proteus-client`, then opens a single
//! `PROXY_OPEN cmd="udp"` stream, sends one DATA frame with the
//! payload, waits up to 5s for one DATA frame back, and exits.
//!
//! Used as the M10 verification harness — the SOCKS5 frontend in
//! `proteus-client` only supports TCP CONNECT in v0.3, so we need a
//! direct UDP entrypoint to exercise the wire path.

use std::{net::SocketAddr, path::PathBuf, time::Duration};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use proteus_core::{
    auth::{AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN, load_signing_key},
    config::ClientConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    proxy::{ProxyOpen, ProxyReject},
    tls,
};

const RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(clap::Args, Debug)]
pub struct Args {
    /// Path to client YAML config (same shape as proteus-client).
    #[arg(short, long)]
    pub config: PathBuf,

    /// UDP target HOST:PORT (e.g. 127.0.0.1:9998).
    #[arg(short, long)]
    pub target: String,

    /// Payload bytes to send.
    #[arg(short, long, default_value = "udp-test\n")]
    pub payload: String,
}

pub async fn run(args: Args) -> Result<()> {
    let cfg = ClientConfig::from_yaml_file(&args.config)?;
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

    // ----- auth -----
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;
    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;
    let req = AuthRequest::sign(&cfg.identity.client_id, &sk, &exporter)?;
    write_frame(
        &mut ctrl_send,
        &Frame::new(FrameType::AuthRequest, req.encode()?)?,
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

    // ----- UDP proxy stream -----
    let (host, port) = parse_target(&args.target)?;
    let (mut q_send, mut q_recv) = conn.open_bi().await.context("open udp proxy bi")?;
    let open = ProxyOpen::new_udp(&host, port);
    write_frame(
        &mut q_send,
        &Frame::new(FrameType::ProxyOpen, open.encode()?)?,
    )
    .await
    .context("write PROXY_OPEN")?;

    let resp_frame = read_frame(&mut q_recv)
        .await
        .context("read PROXY_ACCEPT/REJECT")?;
    match resp_frame.frame_type {
        FrameType::ProxyAccept => println!("UDP proxy accepted: {host}:{port}"),
        FrameType::ProxyReject => {
            let r = ProxyReject::decode(&resp_frame.payload)?;
            bail!("UDP proxy rejected: {} (0x{:02x})", r.name(), r.reason);
        }
        other => bail!("expected PROXY_ACCEPT/REJECT, got {other:?}"),
    }

    // Send one datagram-worth of payload as a single DATA frame.
    let payload = Bytes::copy_from_slice(args.payload.as_bytes());
    write_frame(&mut q_send, &Frame::new(FrameType::Data, payload.clone())?)
        .await
        .context("write DATA")?;
    q_send.finish().context("finish send")?;

    // Wait for one DATA frame back (the echo).
    let response = tokio::time::timeout(RESPONSE_TIMEOUT, read_frame(&mut q_recv))
        .await
        .context("timeout waiting for UDP echo response")??;
    if response.frame_type != FrameType::Data {
        bail!("expected DATA reply, got {:?}", response.frame_type);
    }

    println!("sent:     {:?}", payload.as_ref());
    println!("received: {:?}", response.payload.as_ref());
    if response.payload == payload {
        println!("UDP echo OK ({} bytes round-tripped)", payload.len());
    } else {
        bail!(
            "UDP echo mismatch (sent {} bytes, got {} bytes)",
            payload.len(),
            response.payload.len()
        );
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

fn parse_target(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("target must be HOST:PORT, got {s:?}"))?;
    let port: u16 = port.parse().context("invalid port")?;
    Ok((host.to_string(), port))
}
