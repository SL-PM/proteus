// PROTEUS desktop UI — vanilla JS over `withGlobalTauri`.
//
// Talks to connect / disconnect / get_stats. Tauri maps JS camelCase args
// to Rust snake_case (subUrl→sub_url, socks5Port→socks5_port,
// systemProxy→system_proxy). Stats polled once a second.

const { invoke } = window.__TAURI__.core;

const el = (id) => document.getElementById(id);
const subEl = el("sub");
const portEl = el("port");
const sysproxyEl = el("sysproxy");
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
let sysActive = false;
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
  statusEl.textContent = live
    ? sysActive
      ? "Connected · systemweit"
      : "Connected"
    : "Link closed";
  addrEl.textContent = s.socks5_addr + (sysActive ? "  · systemweit" : "");
  downEl.textContent = fmtRate(s.down_bps);
  upEl.textContent = fmtRate(s.up_bps);
  pingEl.textContent = `${Math.round(s.ping_ms)} ms`;
  totalsEl.textContent = `↓ ${fmtBytes(s.down_bytes)} · ↑ ${fmtBytes(s.up_bytes)}`;
  actionEl.textContent = "Disconnect";
  actionEl.classList.remove("primary");
  actionEl.classList.add("danger");
}

// Link dropped under us: tear down + restore the system proxy so the
// browser never gets stranded pointing at a dead listener.
async function handleDrop() {
  stopPolling();
  try {
    await invoke("disconnect");
  } catch (e) {
    /* best effort */
  }
  const msg =
    "Verbindung verloren — getrennt" +
    (sysActive ? " (System-Proxy zurückgesetzt)" : "") +
    ".";
  sysActive = false;
  renderIdle();
  setError(msg);
}

async function poll() {
  try {
    const s = await invoke("get_stats");
    if (s && !s.connected) {
      await handleDrop();
      return;
    }
    renderStats(s);
  } catch (e) {
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
  const systemProxy = !!sysproxyEl.checked;
  busy = true;
  setError("");
  statusEl.textContent = "Connecting…";
  actionEl.disabled = true;
  try {
    const res = await invoke("connect", { subUrl, socks5Port, systemProxy });
    sysActive = !!res.system_proxy;
    addrEl.textContent = res.socks5_addr + (sysActive ? "  · systemweit" : "");
    if (res.note) setError(res.note);
    startPolling();
  } catch (e) {
    setError(String(e));
    sysActive = false;
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
    sysActive = false;
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
