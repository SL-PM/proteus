# Capture comparison — 2026-05-27T12:42:23Z

| Metric | A (`proteus-port4433-20260527-115730Z.pcap`) | B (`h3-www_cloudflare_com-20260527-124056Z.pcap`) |
|---|---:|---:|
| Packets       | 14         | 41         |
| Min size (B)  | 66                 | 84                 |
| Avg size (B)  | 641                 | 672                 |
| Max size (B)  | 1421                 | 1486                 |
| Duration (s)  | 0,003    | 7,996    |

Per-packet detail:    `tshark -r FILE -V`
Size histogram:       `tshark -r FILE -q -z io,stat,1,'frame.len'`
TLS handshake fields: `tshark -r FILE -Y 'tls.handshake' -V`
QUIC frame counts:    `tshark -r FILE -q -z quic,heur`
