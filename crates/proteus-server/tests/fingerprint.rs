//! M12.5 — wire-fingerprint measurement harness.
//!
//! Turns v0.5 padding's "we think this helps" into a number, using the
//! pure `proteus_core::fingerprint` math (total-variation distance →
//! best-possible classifier accuracy).
//!
//! The well-posed question for *bucket* padding is NOT "does PROTEUS
//! look like real H3?" — that needs profile-matching we don't do, and a
//! real capture corpus we don't have. It is:
//!
//!   **Can a passive observer tell two different PROTEUS activities
//!   apart purely from server→client frame sizes?**
//!
//! That is exactly the leak padding addresses. We drive two workloads
//! (small vs. medium echo payloads) and measure the size-distribution
//! distinguishability with padding OFF vs ON. Padding should collapse
//! *fine-grained* differences (both land in the same bucket) → near-
//! coin-flip. We ALSO measure a *coarse* pair (small vs. large, which
//! straddle two buckets) to document padding's honest limit: it
//! quantizes, so across-bucket differences survive.
//!
//! Size-based (not timing-based) → deterministic, not flaky.

mod common;

use std::time::Duration;

use anyhow::{Result, anyhow};
use common::{TestServer, make_client_endpoint, open_tcp_proxy, read_raw_wire_frame, run_auth};
use proteus_core::{
    aead::ProxyStreamAead,
    fingerprint::{Distribution, optimal_classifier_accuracy},
    frame::{Frame, FrameType, write_frame_aead},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
};

async fn spawn_tcp_echo() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(v) => v,
                Err(_) => return,
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    let n = match sock.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    port
}

/// Send `payload` `repeats` times (ping-pong) through the proxy and
/// collect the raw wire `payload_len` of every server→client frame.
async fn collect_wire_sizes(
    q_send: &mut quinn::SendStream,
    q_recv: &mut quinn::RecvStream,
    sa: &mut ProxyStreamAead,
    stream_id: u64,
    payload_len: usize,
    repeats: usize,
) -> Result<Vec<u64>> {
    let payload = vec![0x5A; payload_len];
    let mut sizes = Vec::new();
    for _ in 0..repeats {
        let data = Frame {
            frame_type: FrameType::Data,
            flags: 0,
            stream_id,
            payload: bytes::Bytes::copy_from_slice(&payload),
        };
        write_frame_aead(q_send, &data, &mut sa.send).await?;

        // First echo frame must arrive promptly.
        let (_flags, wire_len) =
            tokio::time::timeout(Duration::from_secs(2), read_raw_wire_frame(q_recv))
                .await
                .map_err(|_| anyhow!("timeout waiting for echo"))??;
        sizes.push(wire_len as u64);
        // Drain any fragmentation follow-ons.
        while let Ok(Ok((_flags, n))) =
            tokio::time::timeout(Duration::from_millis(150), read_raw_wire_frame(q_recv)).await
        {
            sizes.push(n as u64);
        }
    }
    Ok(sizes)
}

/// Run one workload (a fixed payload size, repeated) against `server`
/// and return the observed server→client wire-size samples.
async fn workload(server: &TestServer, echo_port: u16, payload_len: usize) -> Result<Vec<u64>> {
    let endpoint = make_client_endpoint(&server.cert_sha256)?;
    let conn = endpoint.connect(server.addr, "localhost")?.await?;
    let session_key = run_auth(&conn, &server.client_id, &server.signing_key).await?;
    let (mut q_send, mut q_recv, mut sa, stream_id) =
        open_tcp_proxy(&conn, &session_key, "127.0.0.1", echo_port).await?;
    let sizes = collect_wire_sizes(
        &mut q_send,
        &mut q_recv,
        &mut sa,
        stream_id,
        payload_len,
        12,
    )
    .await?;
    conn.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(sizes)
}

#[tokio::test]
async fn padding_reduces_activity_distinguishability() -> Result<()> {
    let echo_port = spawn_tcp_echo().await;
    let off = TestServer::start("alice").await?; // padding OFF
    let on = TestServer::start_padded("alice").await?; // padding ON, default buckets

    // Small (5B) and medium (100B) both land in the 128 bucket when
    // padded; large (1000B) lands in the 1024 bucket.
    let small_off = workload(&off, echo_port, 5).await?;
    let mid_off = workload(&off, echo_port, 100).await?;
    let small_on = workload(&on, echo_port, 5).await?;
    let mid_on = workload(&on, echo_port, 100).await?;
    let large_on = workload(&on, echo_port, 1000).await?;

    let dist = |s: &[u64]| Distribution::from_samples(s.iter().copied());

    // (1) Fine-grained pair, padding OFF: small vs. medium are easily
    // told apart by wire size.
    let tv_off = dist(&small_off).total_variation(&dist(&mid_off));
    let acc_off = optimal_classifier_accuracy(tv_off);

    // (2) Same pair, padding ON: both collapse to bucket 128 → an
    // observer can't tell them apart.
    let tv_on_fine = dist(&small_on).total_variation(&dist(&mid_on));
    let acc_on_fine = optimal_classifier_accuracy(tv_on_fine);

    // (3) Coarse pair, padding ON: small (128) vs. large (1024) straddle
    // two buckets → still distinguishable (padding's honest limit).
    let tv_on_coarse = dist(&small_on).total_variation(&dist(&large_on));
    let acc_on_coarse = optimal_classifier_accuracy(tv_on_coarse);

    // Surfaced with `--nocapture` for the M12.5 sign-off.
    eprintln!("--- M12.5 distinguishability (best-classifier accuracy) ---");
    eprintln!("  small_off sizes: {small_off:?}");
    eprintln!("  mid_off   sizes: {mid_off:?}");
    eprintln!("  small_on  sizes: {small_on:?}");
    eprintln!("  mid_on    sizes: {mid_on:?}");
    eprintln!("  large_on  sizes: {large_on:?}");
    eprintln!("  OFF, small-vs-mid : TV={tv_off:.3}  acc={acc_off:.3}  (distinguishable)");
    eprintln!("  ON,  small-vs-mid : TV={tv_on_fine:.3}  acc={acc_on_fine:.3}  (collapsed)");
    eprintln!("  ON,  small-vs-large: TV={tv_on_coarse:.3}  acc={acc_on_coarse:.3}  (limit)");

    // Without padding, the two fine-grained activities are highly
    // distinguishable.
    assert!(
        acc_off >= 0.9,
        "expected small vs mid distinguishable without padding; acc={acc_off:.3}"
    );
    // Padding collapses the fine-grained difference toward a coin flip.
    assert!(
        acc_on_fine <= 0.6,
        "padding should collapse small vs mid; acc={acc_on_fine:.3}"
    );
    // But padding is a quantizer, not a uniformizer: across buckets the
    // difference survives. Documenting the honest limit.
    assert!(
        acc_on_coarse >= 0.9,
        "across-bucket pair should remain distinguishable; acc={acc_on_coarse:.3}"
    );
    Ok(())
}

/// M13.5 — timing axis. The size measurement above used the live wire
/// (deterministic). Live inter-arrival timing is wall-clock-noisy, so
/// here we measure the jitter *mechanism* deterministically instead:
/// model a perfectly regular send schedule (a strong timing
/// fingerprint — e.g. a periodic heartbeat at a fixed cadence) and
/// apply the real `Jitter` sampler with a seeded RNG, then compare the
/// resulting inter-arrival gap distribution with vs. without jitter.
///
/// Model: each frame becomes ready at `i·G` and is sent after an
/// independent jitter delay `d_i`, so the observed gap is
/// `G + d_i − d_{i-1}`. (This is the faithful per-frame-jitter effect:
/// inter-arrival = nominal cadence plus the difference of consecutive
/// delays.)
#[test]
fn jitter_destroys_a_regular_timing_signature() {
    use proteus_core::jitter::Jitter;
    use rand::{SeedableRng, rngs::StdRng};

    let mut rng = StdRng::seed_from_u64(0x7117_2026);
    let g_ms: i64 = 10; // a precise 10ms periodic cadence
    let n = 300usize;
    let jitter = Jitter::new(0, 8);

    // Without jitter: every gap is exactly the cadence → a sharp spike.
    let off_gaps: Vec<u64> = std::iter::repeat_n(g_ms as u64, n).collect();

    // With jitter: gap_i = G + d_i − d_{i-1} (clamped ≥ 0).
    let delays: Vec<i64> = (0..=n)
        .map(|_| jitter.next_delay_with(&mut rng).as_millis() as i64)
        .collect();
    let on_gaps: Vec<u64> = (1..=n)
        .map(|i| (g_ms + delays[i] - delays[i - 1]).max(0) as u64)
        .collect();

    let off = Distribution::from_samples(off_gaps.iter().copied());
    let on = Distribution::from_samples(on_gaps.iter().copied());
    let tv = off.total_variation(&on);

    let mean = |g: &[u64]| g.iter().sum::<u64>() as f64 / g.len() as f64;
    let (m_off, m_on) = (mean(&off_gaps), mean(&on_gaps));

    eprintln!("--- M13.5 timing-axis (inter-arrival gaps, ms) ---");
    eprintln!(
        "  off: distinct_bins={}  mean={m_off:.2}",
        off.distinct_bins()
    );
    eprintln!(
        "  on : distinct_bins={}  mean={m_on:.2}",
        on.distinct_bins()
    );
    eprintln!("  TV(off,on)={tv:.3}  (regularity destroyed)");

    // Regularity destroyed: a single-spike timing signature spreads out.
    assert_eq!(off.distinct_bins(), 1, "no-jitter cadence is a sharp spike");
    assert!(
        on.distinct_bins() >= 5,
        "jitter should spread the gap distribution; got {} bins",
        on.distinct_bins()
    );
    // Honest limit: jitter does NOT change the MEAN cadence — an analyst
    // measuring average inter-arrival still recovers ~G. (Uniform jitter
    // is a regularity-breaker, not a cadence-hider; matching a target
    // cadence needs profile-driven timing.)
    assert!(
        (m_off - m_on).abs() < 2.0,
        "mean cadence should be ~preserved: off={m_off:.2} on={m_on:.2}"
    );
}
