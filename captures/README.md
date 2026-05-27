# captures/

Output directory for the M15 capture scripts under `../scripts/`. The
`.pcap` files themselves are gitignored (see `../.gitignore`) because
they may be large and host-specific.

## Layout

- `v0.3/` — captures for the M14 + M15 sign-off block. PROTEUS
  rejection events on loopback vs real HTTP/3 baselines from public
  cover hosts. See [`../docs/m14-invalid-client.md`](../docs/m14-invalid-client.md)
  for what the sign-off requires.

Future versions will add `v0.4/` (REALITY-style upstream masquerading
captures) and `v0.5/` (fingerprint padding / timing profile inputs).

## Producing captures

See [`../scripts/README.md`](../scripts/README.md) for the full
workflow. Quick reference:

```sh
# loopback PROTEUS capture (15s)
sudo ./scripts/capture-proteus.sh 4433 15

# real H3 baseline (5s)
sudo ./scripts/capture-h3.sh www.cloudflare.com 5

# side-by-side summary
./scripts/compare-captures.sh \
    captures/v0.3/proteus-port4433-*.pcap \
    captures/v0.3/h3-www_cloudflare_com-*.pcap \
    docs/m14-comparison-report.md
```
