# PROTEUS — Capture Tooling (M15)

Three Bash scripts for recording and comparing PROTEUS vs real HTTP/3
traffic. Used together they produce the `captures/v0.3/*.pcap` files
and the comparison report that the [M14 acceptance criteria](../docs/m14-invalid-client.md#acceptance-criteria-for-m14-to-be-marked-done)
require.

## Prerequisites

- `tcpdump` (built-in on macOS; `apt install tcpdump` on Debian/Ubuntu)
- `tshark` (only needed for `compare-captures.sh`)
  - macOS: `brew install wireshark`
  - Linux: `apt install tshark`
- `curl` with HTTP/3 support for `capture-h3.sh`
  - macOS: a build with `--with-http3` (e.g. from homebrew-curl-http3)
  - Linux: distro curl 8.x+ usually has it; check with `curl --version | grep HTTP3`

The two `capture-*.sh` scripts require `sudo` for packet capture.

## Scripts

### `capture-proteus.sh [PORT] [SECONDS]`

Records loopback UDP traffic on the given PROTEUS server port. Default
port `4433`, duration `10s`. Writes to
`captures/v0.3/proteus-port<PORT>-<UTC>.pcap`.

Workflow (three terminals):

```sh
# T1: server
proteus-server --config /tmp/server.yaml

# T2: capture
sudo ./scripts/capture-proteus.sh 4433 15

# T3: trigger a rejection event during the 15s window
proteus-tools udp-test --config /tmp/client.yaml \
    --target 127.0.0.1:9998 --payload "x"
# (or: curl --socks5 ... ; or use a deliberately wrong key)
```

### `capture-h3.sh [HOST] [SECONDS]`

Records UDP traffic to a public cover host on the default route while
`curl --http3` pulls the root page. Default host
`www.cloudflare.com`, duration `5s`. Writes to
`captures/v0.3/h3-<host>-<UTC>.pcap`.

```sh
sudo ./scripts/capture-h3.sh www.cloudflare.com 5
```

If the system curl lacks HTTP/3 support, the script falls back to
HTTP/2 / 1.1 with a stderr warning. That capture is **not** a useful
H3 baseline — install a curl build with HTTP/3 first.

### `compare-captures.sh A.pcap B.pcap [out.md]`

Side-by-side Markdown table: packet count, min/avg/max frame size,
duration. Writes to stdout by default, or to a file if you pass one.

```sh
./scripts/compare-captures.sh \
    captures/v0.3/proteus-port4433-*.pcap \
    captures/v0.3/h3-www_cloudflare_com-*.pcap \
    docs/m14-comparison-report.md
```

## Sign-off workflow (M14 acceptance criteria)

1. Start `proteus-server` with a permissive config.
2. In a second terminal: `sudo ./scripts/capture-proteus.sh 4433 15`.
3. In a third terminal, generate one rejection event during the 15s
   window (`udp-test` with a wrong key, or a policy-denied target).
4. The capture script flushes its pcap automatically when its timer
   expires.
5. Separately: `sudo ./scripts/capture-h3.sh` to record a real H3 trace.
6. Generate the report:
   ```sh
   ./scripts/compare-captures.sh <proteus.pcap> <h3.pcap> \
       docs/m14-comparison-report.md
   ```
7. Where the metrics diverge most is where v0.5 fingerprint work
   (padding + timing profiles) will need to focus.

## Known limitations

- Loopback captures don't reflect real-network jitter, MTU, or
  middleboxes. Field-level capture from two machines is more
  realistic but requires coordination not scripted here.
- `tcpdump`'s ring-buffer (`-G/-W`) is not used; the scripts simply
  bound runtime with `sleep` and then SIGINT.
- `compare-captures.sh` reports aggregate stats only. Per-packet
  timing histograms, TLS-handshake bytes, and QUIC-frame-level
  analysis live behind the raw `tshark` commands listed at the
  bottom of the report.
