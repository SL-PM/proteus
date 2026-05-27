#!/usr/bin/env bash
# capture-proteus.sh — record PROTEUS traffic on loopback (M15).
#
# Usage:
#   sudo ./scripts/capture-proteus.sh [PORT] [SECONDS]
#
# Defaults: PORT=4433, SECONDS=10.
# Output:   captures/v0.3/proteus-port<PORT>-<UTC>.pcap

set -euo pipefail

PORT="${1:-4433}"
DURATION="${2:-10}"
OUT_DIR="captures/v0.3"
TS="$(date -u +%Y%m%d-%H%M%SZ)"
OUT="${OUT_DIR}/proteus-port${PORT}-${TS}.pcap"

if ! command -v tcpdump >/dev/null 2>&1; then
  echo "tcpdump not found" >&2
  exit 1
fi
if [ "$(id -u)" -ne 0 ]; then
  echo "this script needs root for tcpdump; rerun with sudo" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"

case "$(uname)" in
  Darwin) IFACE=lo0 ;;
  Linux)  IFACE=lo  ;;
  *)      IFACE=lo0 ;;
esac

echo "Capturing UDP/${PORT} on ${IFACE} for ${DURATION}s → ${OUT}"
tcpdump -i "$IFACE" -w "$OUT" "udp port ${PORT}" >/dev/null 2>&1 &
TCP_PID=$!
sleep "$DURATION"
kill -INT "$TCP_PID" 2>/dev/null || true
wait "$TCP_PID" 2>/dev/null || true

echo "Wrote: ${OUT}"
echo "Inspect: tshark -r ${OUT} -V"
