# Open Items — manual actions for the operator

Everything v0.3 cannot finish automatically. Split into:
- **A.** v0.3 sign-off — close the loop on what's already built.
- **B.** Before any deployment — must do before v0.3 touches a real
  machine, even a lab one.
- **C.** Optional polish — session-end housekeeping.

---

## A. v0.3 sign-off

### A1. M14 capture + comparison report

The code-path side of M14 is done; only the pcap baselines + the
diff report are missing. Acceptance checklist lives in
[`m14-invalid-client.md`](m14-invalid-client.md).

Required: `sudo` + a curl build with HTTP/3 support.

Steps:

1. Install curl with HTTP/3 support.
   ```sh
   # macOS, community-built curl with HTTP/3:
   brew install curl-http3
   #   (or use the canonical brewed curl if its libcurl has http3 enabled)

   # Verify:
   curl --http3 -V 2>&1 | grep -q HTTP3 && echo OK
   ```
2. Terminal 1 — start the server with a permissive config (no
   `policy:` section).
3. Terminal 2:
   ```sh
   sudo ./scripts/capture-proteus.sh 4433 15
   ```
4. Terminal 3, within the 15-second window — trigger a rejection
   event. Easiest path: regenerate the client key after the server
   already loaded the public one, then run `proteus-tools udp-test`.
   The new private key won't match the server's stored pubkey, so
   auth fails with `H3_GENERAL_PROTOCOL_ERROR`.
5. Separate run for the real-H3 baseline:
   ```sh
   sudo ./scripts/capture-h3.sh www.cloudflare.com 5
   ```
6. Generate the report:
   ```sh
   ./scripts/compare-captures.sh \
       captures/v0.3/proteus-port4433-*.pcap \
       captures/v0.3/h3-www_cloudflare_com-*.pcap \
       docs/m14-comparison-report.md
   ```
7. Commit `docs/m14-comparison-report.md`. The pcaps themselves are
   gitignored by default; force-add them only if you want a checked-in
   reference baseline.

After step 7, DoD item 11 is met → v0.3 reaches **12/12 DoD**.

---

## B. Before any deployment

### B1. Decide on a code license

Neither `README.md` nor `Cargo.toml` declare a code license. Pick one
before:
- pushing to a public git remote
- shipping a binary to anyone else
- accepting outside contributions

Common picks:
- **Apache-2.0** — permissive, includes patent grant.
- **MIT** — simpler, no patent grant.
- **AGPL-3.0** — copyleft, requires sharing modifications even over
  the network (good fit for a circumvention tool that wants its
  derivatives to stay open).

Docs are already CC-BY-SA-4.0.

### B2. Replace the self-signed cert

`proteus_core::tls::server_config` generates a fresh self-signed cert
on every startup. The `tls.cert` / `tls.key` config fields exist but
the PEM-loading code path is still deferred (see the `M6` note in
that module). For any real deployment, wire that up to a Let's
Encrypt or otherwise CA-signed cert.

### B3. Set a production policy

`configs/server.example.yaml` shows the recommended starting point:

```yaml
policy:
  block_private_ranges: true
  allowed_ports: [80, 443, 8080]
  allow_udp: false
```

The integration tests deliberately run without a `policy:` section
because they target loopback (which is RFC1918 / blocked). Any real
server needs one.

### B4. Tune the rate limit

Hardcoded in `proteus-server::main`:

```rust
const RATE_LIMIT_MAX: usize = 30;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
```

For a multi-user server raise these. For a single-user private
deployment lower them. Promoting these to a config field is a
small follow-up (≤ 30 lines).

### B5. Decide what to do with the H3 decoy body

`DECOY_HTML` in `proteus-server::main` is a placeholder "It works."
page. A real deployment should swap in something less obvious — for
example, copy the index of the cover host you're impersonating.
v0.4 REALITY upstream forwarding makes this moot.

---

## C. Optional polish

### C1. Tag the release

```sh
git tag -a v0.3.0-rc.1 -m "v0.3 protocol-complete; M14 sign-off pending"
```

If there's a remote: `git push origin v0.3.0-rc.1`.

### C2. Generate a CHANGELOG

```sh
git log --reverse --format="* %h %s" $(git rev-list --max-parents=0 HEAD)..HEAD \
    > CHANGELOG.md
```

(That starts from the root commit. Adjust the range as needed if the
repo later gets a new initial commit.)

### C3. Set up a remote

The repo has no remote yet. After B1 (license):

```sh
git remote add origin git@github.com:<user>/proteus.git
git push -u origin main
git push origin --tags        # if you tagged in C1
```

---

## What does NOT need manual action

For completeness — these *should* work without any human in the loop:

- `cargo build --workspace`, `cargo test --workspace` (73 tests),
  `cargo fmt --check`, `cargo clippy --workspace --all-targets -- -D warnings`.
- Full local PROTEUS demo per the [README Quick start](../README.md#quick-start)
  — keygen, server, client, `curl --socks5`.
- `scripts/compare-captures.sh` produces a Markdown report shape
  automatically; only the input pcaps require a sudo capture step.
- Metrics snapshots (every 30s to stderr), replay-cache sweep
  (every 60s), rate-limit sweep (every 120s).
