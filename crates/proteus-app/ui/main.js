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
let reconnecting = false;
let pollTimer = null;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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

// Link dropped under us: try to re-dial transparently (keeping the system
// proxy in place — the listener rebinds the same port) with backoff. Only
// if every attempt fails do we tear down and restore the proxy, so the
// browser isn't stranded on a dead listener.
async function handleDrop() {
  if (reconnecting) return;
  reconnecting = true;
  stopPolling();
  dotEl.className = "dot warn";
  dotEl.title = "reconnecting";
  for (let attempt = 1; attempt <= 6; attempt++) {
    statusEl.textContent = `Reconnecting… (${attempt}/6)`;
    setError("Verbindung verloren — verbinde neu…");
    await sleep(attempt === 1 ? 600 : 3000);
    try {
      const ok = await invoke("reconnect");
      if (ok) {
        setError("");
        reconnecting = false;
        startPolling();
        return;
      }
    } catch (e) {
      /* keep retrying until the attempt budget is spent */
    }
  }
  // Gave up: restore the proxy + go idle so traffic isn't black-holed.
  reconnecting = false;
  try {
    await invoke("disconnect");
  } catch (e) {
    /* best effort */
  }
  sysActive = false;
  renderIdle();
  setError("Konnte nicht neu verbinden — getrennt.");
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
