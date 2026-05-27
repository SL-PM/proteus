#!/usr/bin/env bash
# compare-captures.sh — quick side-by-side summary of two pcaps (M15).
#
# Usage:
#   ./scripts/compare-captures.sh A.pcap B.pcap [out.md]
#
# Writes a Markdown table comparing packet count, frame-size statistics,
# and duration. If [out.md] is omitted, prints to stdout.

set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "usage: $0 A.pcap B.pcap [out.md]" >&2
  exit 1
fi

A="$1"
B="$2"
OUT="${3:-/dev/stdout}"

if ! command -v tshark >/dev/null 2>&1; then
  echo "tshark not found (try: brew install wireshark or apt install tshark)" >&2
  exit 1
fi
[ -r "$A" ] || { echo "cannot read $A" >&2; exit 1; }
[ -r "$B" ] || { echo "cannot read $B" >&2; exit 1; }

count() {
  tshark -r "$1" 2>/dev/null | wc -l | tr -d ' '
}
size_stats() {
  # Echoes "min avg max" on one line. "n/a n/a n/a" if no packets.
  tshark -r "$1" -T fields -e frame.len 2>/dev/null | awk '
    NR == 1 { min = $1; max = $1 }
    { sum += $1; if ($1 < min) min = $1; if ($1 > max) max = $1; n++ }
    END {
      if (n) printf "%d %.0f %d", min, sum/n, max
      else   printf "n/a n/a n/a"
    }'
}
duration_s() {
  local f="$1"
  local first last
  first="$(tshark -r "$f" -T fields -e frame.time_epoch 2>/dev/null | head -1)"
  last="$(tshark -r "$f" -T fields -e frame.time_epoch 2>/dev/null | tail -1)"
  awk -v a="$first" -v b="$last" 'BEGIN {
    if (a && b) printf "%.3f", b - a
    else        printf "n/a"
  }'
}

read -r AMIN AAVG AMAX <<<"$(size_stats "$A")"
read -r BMIN BAVG BMAX <<<"$(size_stats "$B")"

cat <<EOF >"$OUT"
# Capture comparison — $(date -u +%Y-%m-%dT%H:%M:%SZ)

| Metric | A (\`$(basename "$A")\`) | B (\`$(basename "$B")\`) |
|---|---:|---:|
| Packets       | $(count "$A")         | $(count "$B")         |
| Min size (B)  | $AMIN                 | $BMIN                 |
| Avg size (B)  | $AAVG                 | $BAVG                 |
| Max size (B)  | $AMAX                 | $BMAX                 |
| Duration (s)  | $(duration_s "$A")    | $(duration_s "$B")    |

Per-packet detail:    \`tshark -r FILE -V\`
Size histogram:       \`tshark -r FILE -q -z io,stat,1,'frame.len'\`
TLS handshake fields: \`tshark -r FILE -Y 'tls.handshake' -V\`
QUIC frame counts:    \`tshark -r FILE -q -z quic,heur\`
EOF

[ "$OUT" != "/dev/stdout" ] && echo "Wrote: $OUT"
