#!/usr/bin/env bash
# capture-h3.sh — record real HTTP/3 traffic to a public cover host (M15).
#
# Usage:
#   sudo ./scripts/capture-h3.sh [HOST] [SECONDS]
#
# Defaults: HOST=www.cloudflare.com, SECONDS=5.
# Output:   captures/v0.3/h3-<host>-<UTC>.pcap

set -euo pipefail

HOST="${1:-www.cloudflare.com}"
DURATION="${2:-5}"
OUT_DIR="captures/v0.3"
TS="$(date -u +%Y%m%d-%H%M%SZ)"
OUT="${OUT_DIR}/h3-${HOST//./_}-${TS}.pcap"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "this script needs root for tcpdump; rerun with sudo" >&2
  exit 1
fi
if ! command -v curl >/dev/null 2>&1; then
  echo "curl not found" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

case "$(uname)" in
  Darwin)
    IFACE=$(route get default 2>/dev/null | awk '/interface:/ {print $2}')
    ;;
  Linux)
    IFACE=$(ip route show default 2>/dev/null | awk '/default/ {print $5; exit}')
    ;;
esac
IFACE="${IFACE:-en0}"
echo "Default interface: ${IFACE}"

if ! curl --help all 2>/dev/null | grep -q -- '--http3'; then
  echo "WARN: this curl does not advertise --http3. The capture will reflect" >&2
  echo "      whatever protocol curl negotiates (likely HTTP/2 or 1.1)." >&2
  echo "      Install a curl build with HTTP/3 for a real H3 baseline." >&2
fi

echo "Capturing UDP traffic to ${HOST} on ${IFACE} for ${DURATION}s → ${OUT}"

tcpdump -i "$IFACE" -w "$OUT" "udp and host ${HOST}" >/dev/null 2>&1 &
TCP_PID=$!

# Give tcpdump a moment to bind.
sleep 0.5

echo "Fetching https://${HOST}/ ..."
curl --http3 -sS -o /dev/null --max-time "$DURATION" "https://${HOST}/" 2>/dev/null \
  || curl       -sS -o /dev/null --max-time "$DURATION" "https://${HOST}/" 2>/dev/null \
  || echo "(curl fetch failed; capture may be empty)"

# Let trailing packets arrive before stopping.
sleep 0.5
kill -INT "$TCP_PID" 2>/dev/null || true
wait "$TCP_PID" 2>/dev/null || true

echo "Wrote: ${OUT}"
