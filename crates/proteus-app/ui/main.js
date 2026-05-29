// PROTEUS desktop UI — vanilla JS over `withGlobalTauri`.
//
// Talks to the three Rust commands (connect / disconnect / get_stats).
// Tauri maps JS camelCase args to Rust snake_case (subUrl → sub_url,
// socks5Port → socks5_port). Stats are polled once a second.

const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const subEl = el("sub");
const portEl = el("port");
const actionEl = el("action");
const dotEl = el("dot");
const statusEl = el("status");
const addrEl = el("addr");
const totalsEl = el("totals");
const downEl = el("down");
const upEl = el("up");
const pingEl = el("ping");
const errEl = el("err");

let connected = false;
let busy = false;
let pollTimer = null;

function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(Math.floor(Math.log(n) / Math.log(1024)), u.length - 1);
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}

function fmtRate(bps) {
  if (!bps || bps < 1) return "0 B/s";
  const u = ["B/s", "KB/s", "MB/s", "GB/s"];
  const i = Math.min(Math.floor(Math.log(bps) / Math.log(1024)), u.length - 1);
  return `${(bps / Math.pow(1024, i)).toFixed(1)} ${u[i]}`;
}

function setError(msg) {
  errEl.textContent = msg || "";
}

function renderIdle() {
  connected = false;
  dotEl.className = "dot off";
  dotEl.title = "disconnected";
  statusEl.textContent = "Idle";
  addrEl.textContent = "—";
  totalsEl.textContent = "↓ 0 B · ↑ 0 B";
  downEl.textContent = "—";
  upEl.textContent = "—";
  pingEl.textContent = "—";
  actionEl.textContent = "Connect";
  actionEl.classList.remove("danger");
  actionEl.classList.add("primary");
}

function renderStats(s) {
  if (!s) {
    renderIdle();
    return;
  }
  connected = true;
  const live = s.connected;
  dotEl.className = live ? "dot on" : "dot warn";
  dotEl.title = live ? "connected" : "link closed";
  statusEl.textContent = live ? "Connected" : "Link closed";
  addrEl.textContent = s.socks5_addr;
  downEl.textContent = fmtRate(s.down_bps);
  upEl.textContent = fmtRate(s.up_bps);
  pingEl.textContent = `${Math.round(s.ping_ms)} ms`;
  totalsEl.textContent = `↓ ${fmtBytes(s.down_bytes)} · ↑ ${fmtBytes(s.up_bytes)}`;
  actionEl.textContent = "Disconnect";
  actionEl.classList.remove("primary");
  actionEl.classList.add("danger");
}

async function poll() {
  try {
    const s = await invoke("get_stats");
    renderStats(s);
  } catch (e) {
    // Non-fatal: keep last frame, surface the message.
    setError(String(e));
  }
}

function startPolling() {
  if (pollTimer) return;
  poll();
  pollTimer = setInterval(poll, 1000);
}

function stopPolling() {
  if (pollTimer) {
    clearInterval(pollTimer);
    pollTimer = null;
  }
}

async function doConnect() {
  const subUrl = subEl.value.trim();
  if (!subUrl.startsWith("proteus://")) {
    setError("Paste a proteus:// subscription link first.");
    return;
  }
  const socks5Port = parseInt(portEl.value, 10) || 1080;
  busy = true;
  setError("");
  statusEl.textContent = "Connecting…";
  actionEl.disabled = true;
  try {
    const addr = await invoke("connect", { subUrl, socks5Port });
    addrEl.textContent = addr;
    startPolling();
  } catch (e) {
    setError(String(e));
    renderIdle();
  } finally {
    busy = false;
    actionEl.disabled = false;
  }
}

async function doDisconnect() {
  busy = true;
  actionEl.disabled = true;
  statusEl.textContent = "Disconnecting…";
  try {
    stopPolling();
    await invoke("disconnect");
  } catch (e) {
    setError(String(e));
  } finally {
    renderIdle();
    busy = false;
    actionEl.disabled = false;
  }
}

actionEl.addEventListener("click", () => {
  if (busy) return;
  if (connected) doDisconnect();
  else doConnect();
});

renderIdle();
