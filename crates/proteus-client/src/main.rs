//! PROTEUS client (v0.3 research prototype).
//!
//! M8: dial QUIC, authenticate on the control stream, then optionally
//! run a TCP proxy echo demo through a per-target bidi stream.
//!
//! With `--target HOST:PORT`: open a proxy stream to that target, send
//! `"echo-test\n"`, expect the same bytes back, exit 0 on match.
//! Without `--target`: exit cleanly after a successful auth (useful for
//! sanity-checking server credentials in isolation).

use std::{net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use clap::Parser;
use proteus_core::{
    auth::{AuthRequest, AuthResponse, EXPORTER_LABEL, EXPORTER_LEN, load_signing_key},
    config::ClientConfig,
    frame::{Frame, FrameType, read_frame, write_frame},
    proxy::{ProxyOpen, ProxyReject},
    tls,
};

const ECHO_PAYLOAD: &[u8] = b"echo-test\n";

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

    /// Optional TCP proxy target HOST:PORT for the M8 echo demo.
    #[arg(short, long)]
    target: Option<String>,
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

    // ----- auth on the control stream -----
    let (mut ctrl_send, mut ctrl_recv) = conn.open_bi().await.context("open ctrl bi")?;

    let mut exporter = [0u8; EXPORTER_LEN];
    conn.export_keying_material(&mut exporter, EXPORTER_LABEL, b"")
        .map_err(|e| anyhow::anyhow!("exporter: {e:?}"))?;

    let req = AuthRequest::sign(&cfg.identity.client_id, &sk, &exporter)?;
    let req_frame = Frame::new(FrameType::AuthRequest, req.encode()?)?;
    write_frame(&mut ctrl_send, &req_frame)
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

    // ----- proxy echo demo (only with --target) -----
    if let Some(target) = cli.target.as_deref() {
        echo_demo(&conn, target).await?;
    } else {
        println!("(no --target; exiting after auth)");
    }

    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}

async fn echo_demo(conn: &quinn::Connection, target: &str) -> Result<()> {
    let (host, port) = parse_target(target)?;
    println!("opening proxy to {host}:{port}");

    let (mut q_send, mut q_recv) = conn.open_bi().await.context("open proxy bi")?;

    let open = ProxyOpen::new_tcp(host, port);
    let open_frame = Frame::new(FrameType::ProxyOpen, open.encode()?)?;
    write_frame(&mut q_send, &open_frame)
        .await
        .context("write PROXY_OPEN")?;

    let resp = read_frame(&mut q_recv)
        .await
        .context("read PROXY_ACCEPT/REJECT")?;
    match resp.frame_type {
        FrameType::ProxyAccept => println!("proxy accepted"),
        FrameType::ProxyReject => {
            let r = ProxyReject::decode(&resp.payload)?;
            bail!("proxy rejected: {} (0x{:02x})", r.name(), r.reason);
        }
        other => bail!("expected PROXY_ACCEPT/REJECT, got {other:?}"),
    }

    // Send echo payload and finish the send side.
    let payload_frame = Frame::new(FrameType::Data, Bytes::copy_from_slice(ECHO_PAYLOAD))?;
    write_frame(&mut q_send, &payload_frame)
        .await
        .context("write echo payload")?;
    q_send.finish().context("finish send")?;

    // Concatenate DATA frame payloads until we have the echo back (or EOF).
    let mut got = Vec::new();
    loop {
        let f = match read_frame(&mut q_recv).await {
            Ok(f) => f,
            Err(_) => break,
        };
        if f.frame_type != FrameType::Data {
            bail!("expected Data, got {:?}", f.frame_type);
        }
        got.extend_from_slice(&f.payload);
        if got.len() >= ECHO_PAYLOAD.len() {
            break;
        }
    }

    if got == ECHO_PAYLOAD {
        println!("echo OK ({} bytes round-tripped)", ECHO_PAYLOAD.len());
        Ok(())
    } else {
        bail!("echo mismatch: sent {ECHO_PAYLOAD:?}, got {got:?}");
    }
}

fn parse_target(s: &str) -> Result<(String, u16)> {
    let (host, port) = s
        .rsplit_once(':')
        .with_context(|| format!("target must be HOST:PORT, got {s:?}"))?;
    let port: u16 = port.parse().context("invalid port")?;
    Ok((host.to_string(), port))
}
