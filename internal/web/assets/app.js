const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const state = {
  appState: null,
  status: null,
  history: [],
  connections: [],
  logs: [],
};

// --- Modern Web Platform Progressive Fallbacks ---

// 1. Invoker Commands fallback (HTMLButtonElement.prototype.commandForElement)
if (!('commandForElement' in HTMLButtonElement.prototype)) {
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[command][commandfor]');
    if (!btn) return;
    const target = document.getElementById(btn.getAttribute('commandfor'));
    if (!target) return;
    const cmd = btn.getAttribute('command');
    if (cmd === 'show-modal' && typeof target.showModal === 'function') {
      target.showModal();
    } else if (cmd === 'close' && typeof target.close === 'function') {
      target.close();
    }
  });
}

// 2. Dialog closedby="any" light-dismiss fallback
if (!('closedBy' in HTMLDialogElement.prototype)) {
  const outside = (e, dialog) => {
    const r = dialog.getBoundingClientRect();
    return e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom;
  };
  for (const dialog of $$('dialog[closedby="any"]')) {
    let pressedOutside = false;
    dialog.addEventListener('pointerdown', (e) => { pressedOutside = outside(e, dialog); });
    dialog.addEventListener('pointerup', (e) => {
      if (pressedOutside && outside(e, dialog)) dialog.close();
    });
  }
}

// Reset returnValue on close to avoid stale values across opens
for (const dialog of $$('dialog')) {
  dialog.addEventListener('close', () => { dialog.returnValue = ''; });
}

// 3. Native <input type="checkbox" switch> fallback for Chrome/Firefox/Edge
if (!('switch' in HTMLInputElement.prototype)) {
  for (const input of $$('input[type="checkbox"][switch]')) {
    input.setAttribute('role', 'switch');
    input.classList.add('switch-fallback');
  }
}

// 4. Focusgroup tablist fallback + tab selection management
const tabButtons = $$('.tablist [role="tab"]');
const tabPanels = $$('.tabpanels > [role="tabpanel"]');

function selectTab(tab) {
  for (const t of tabButtons) {
    const active = t === tab;
    t.setAttribute('aria-selected', String(active));
    t.toggleAttribute('focusgroupstart', active);
  }
  for (const p of tabPanels) {
    const match = p.getAttribute('aria-labelledby') === tab.id;
    if (match) {
      p.removeAttribute('hidden');
    } else {
      p.setAttribute('hidden', 'until-found');
    }
  }
  tab.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}

tabButtons.forEach((tab, idx) => {
  tab.addEventListener('click', () => selectTab(tab));
  if (!Object.hasOwn(HTMLElement.prototype, 'focusGroup')) {
    tab.addEventListener('keydown', (e) => {
      let nextIdx = idx;
      if (e.key === 'ArrowRight') nextIdx = (idx + 1) % tabButtons.length;
      else if (e.key === 'ArrowLeft') nextIdx = (idx - 1 + tabButtons.length) % tabButtons.length;
      else if (e.key === 'Home') nextIdx = 0;
      else if (e.key === 'End') nextIdx = tabButtons.length - 1;
      else return;
      e.preventDefault();
      tabButtons[nextIdx].focus();
      selectTab(tabButtons[nextIdx]);
    });
  }
});

// Sync hidden="until-found" tabs if browser find-in-page matches inside a hidden panel
for (const p of tabPanels) {
  p.addEventListener('beforematch', () => {
    const tab = document.getElementById(p.getAttribute('aria-labelledby'));
    if (tab) selectTab(tab);
  });
}

// --- Theme Selector ---
const themeSelect = $('#theme-select');
const savedTheme = localStorage.getItem('gridshield-theme') || 'system';
themeSelect.value = savedTheme;
applyTheme(savedTheme);

function applyTheme(mode) {
  if (mode === 'dark' || mode === 'light') {
    document.documentElement.dataset.theme = mode;
  } else {
    delete document.documentElement.dataset.theme;
  }
  localStorage.setItem('gridshield-theme', mode);
  drawChart();
}

themeSelect.addEventListener('change', () => applyTheme(themeSelect.value));
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => drawChart());

// --- Navigation ---
$$('.nav-item').forEach((btn) => {
  btn.addEventListener('click', () => {
    const view = btn.dataset.view;
    $$('.nav-item').forEach((b) => {
      if (b === btn) b.setAttribute('aria-current', 'page');
      else b.removeAttribute('aria-current');
    });
    $$('.view-section').forEach((sec) => {
      sec.hidden = sec.id !== `view-${view}`;
    });
    if (view === 'dashboard') drawChart();
  });
});

// --- Toast & API Helpers ---
let toastTimer = null;
function showToast(msg, isError = false) {
  const el = $('#toast-banner');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { el.hidden = true; }, 4200);
}

async function api(path, opts = {}) {
  const res = await fetch(path, {
    headers: { 'Content-Type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error || `HTTP ${res.status}`);
  }
  return data;
}

function formatBytes(n) {
  if (!n || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let idx = 0;
  let val = n;
  while (val >= 1024 && idx < units.length - 1) {
    val /= 1024;
    idx++;
  }
  return `${val < 10 && idx > 0 ? val.toFixed(2) : val.toFixed(1)} ${units[idx]}`;
}

function formatSpeed(bps) {
  return `${formatBytes(bps)}/s`;
}

function formatDuration(sinceUnix) {
  if (!sinceUnix) return '';
  const sec = Math.max(0, Math.floor(Date.now() / 1000) - sinceUnix);
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = sec % 60;
  const pad = (v) => String(v).padStart(2, '0');
  return `${pad(h)}:${pad(m)}:${pad(s)}`;
}

// --- Renderers ---
function renderStatus() {
  const st = state.status;
  if (!st) return;

  $('#env-badge').textContent = `${st.os}/${st.arch}${st.is_root ? ' · root' : ''}`;
  $('#ver-badge').textContent = `v${st.version}`;

  const orb = $('#btn-power');
  orb.setAttribute('aria-pressed', String(st.connected));
  $('#power-label').textContent = st.connected ? 'DISCONNECT' : 'CONNECT';
  $('#status-dot').classList.toggle('online', st.connected);
  $('#status-text').textContent = st.connected ? 'Protected · Sudoku Tunnel Active' : 'Disconnected';
  $('#uptime-text').textContent = st.connected ? formatDuration(st.connected_since) : '';

  const nodeEl = $('#active-node-summary');
  const chipsEl = $('#proto-chips');
  chipsEl.replaceChildren();

  const activeProf = st.active_profile || findActiveProfile();
  if (activeProf) {
    nodeEl.textContent = `${activeProf.name} — ${activeProf.server_address}`;
    const chips = [
      activeProf.ascii,
      activeProf.aead,
      activeProf.httpmask?.disable ? 'raw-tcp' : `httpmask:${activeProf.httpmask?.mode || 'auto'}`,
      activeProf.enable_pure_downlink ? 'pure-downlink' : 'packed-downlink',
    ];
    if (activeProf.last_latency_ms) chips.push(`${activeProf.last_latency_ms} ms`);
    for (const c of chips) {
      const span = document.createElement('span');
      span.className = 'badge accent';
      span.textContent = c;
      chipsEl.appendChild(span);
    }
  } else {
    nodeEl.textContent = 'No node selected — click Quick Local Demo or add a Sudoku server.';
  }

  // Routing segmented buttons
  $$('.seg-btn').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.route === st.routing_mode);
  });

  // Switches
  $('#toggle-sysproxy').checked = Boolean(st.system_proxy?.enabled);
  $('#sysproxy-sub').textContent = st.system_proxy?.enabled
    ? `Active on ${(st.system_proxy.services || []).join(', ') || 'OS'} -> ${st.system_proxy.host}:${st.system_proxy.port}`
    : 'One-click SOCKS5 + HTTP (no root required)';

  $('#toggle-tun').checked = Boolean(st.tun?.enabled);
  $('#tun-sub').textContent = st.tun?.enabled
    ? `Active on ${st.tun.interface} (${st.tun.local_ip}, MTU ${st.tun.mtu})`
    : (st.is_root ? 'Ready (running with root privileges)' : 'gVisor utun NIC (start daemon with sudo for TUN)');

  // Metrics
  const tr = st.traffic || {};
  $('#stat-down-speed').textContent = formatSpeed(tr.down_bps || 0);
  $('#stat-up-speed').textContent = formatSpeed(tr.up_bps || 0);
  $('#stat-down-total').textContent = `Total: ${formatBytes(tr.down_total || 0)}`;
  $('#stat-up-total').textContent = `Total: ${formatBytes(tr.up_total || 0)}`;
  $('#stat-conns').textContent = String(st.active_conns || 0);
  $('#stat-proxy-addr').textContent = st.mixed_proxy_addr ? `Mixed: ${st.mixed_proxy_addr}` : 'Local port idle';

  // Server status
  $('#srv-status-title').textContent = st.server_running
    ? `Server Running on ${st.server_addr}`
    : 'Server Stopped';
  $('#srv-status-sub').textContent = st.server_running
    ? `Active tunnels: ${st.server_clients} · Total handled: ${st.server_handled}`
    : 'Configure and start a wire-compatible Sudoku server right from this machine.';
  $('#btn-srv-start').disabled = st.server_running;
  $('#btn-srv-stop').disabled = !st.server_running;
}

function findActiveProfile() {
  if (!state.appState) return null;
  return (state.appState.profiles || []).find((p) => p.id === state.appState.active_profile_id)
    || (state.appState.profiles || [])[0]
    || null;
}

function renderProfiles() {
  const grid = $('#profiles-grid');
  grid.replaceChildren();
  const profiles = state.appState?.profiles || [];
  const activeId = state.status?.active_profile?.id || state.appState?.active_profile_id;

  if (profiles.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'card span-2';
    empty.innerHTML = `<p class="muted" style="margin:0;">No Sudoku nodes saved yet. Click <strong>+ Add Node</strong>, <strong>Import Link</strong>, or run <strong>Quick Local Demo</strong> from Dashboard.</p>`;
    grid.appendChild(empty);
    return;
  }

  for (const p of profiles) {
    const card = document.createElement('article');
    card.className = `profile-card${p.id === activeId ? ' active' : ''}`;

    const top = document.createElement('div');
    top.className = 'profile-top';
    const titleBox = document.createElement('div');
    const h3 = document.createElement('h3');
    h3.className = 'profile-name';
    h3.textContent = p.name;
    const addr = document.createElement('div');
    addr.className = 'profile-addr';
    addr.textContent = p.server_address;
    titleBox.append(h3, addr);

    const latBadge = document.createElement('span');
    latBadge.className = `badge${p.last_latency_ms ? ' ok' : ''}`;
    latBadge.textContent = p.last_latency_ms ? `${p.last_latency_ms} ms` : 'Untested';
    top.append(titleBox, latBadge);

    const chips = document.createElement('div');
    chips.className = 'pill-row';
    for (const txt of [p.ascii, p.aead, p.httpmask?.disable ? 'raw-tcp' : `http:${p.httpmask?.mode || 'auto'}`]) {
      const sp = document.createElement('span');
      sp.className = 'badge';
      sp.textContent = txt;
      chips.appendChild(sp);
    }

    const actions = document.createElement('div');
    actions.className = 'profile-actions';

    const btnConn = makeBtn(p.id === activeId && state.status?.connected ? 'Reconnect' : 'Connect', 'primary small', async () => {
      try {
        state.status = await api('/api/connect', { method: 'POST', body: JSON.stringify({ profile_id: p.id }) });
        await refreshState();
        showToast(`Connected to ${p.name}`);
      } catch (err) { showToast(err.message, true); }
    });

    const btnPing = makeBtn('Ping', 'secondary small', async () => {
      btnPing.disabled = true;
      btnPing.textContent = '...';
      try {
        const res = await api(`/api/profiles/${encodeURIComponent(p.id)}/ping`, { method: 'POST' });
        showToast(`${p.name}: ${res.latency_ms} ms`);
        await refreshState();
      } catch (err) {
        showToast(`Ping failed: ${err.message}`, true);
      } finally {
        btnPing.disabled = false;
        btnPing.textContent = 'Ping';
      }
    });

    const btnShare = makeBtn('Link', 'secondary small', async () => {
      try {
        const res = await api(`/api/profiles/${encodeURIComponent(p.id)}/link`);
        $('#output-export-link').value = res.link;
        $('#modal-export').showModal();
      } catch (err) { showToast(err.message, true); }
    });

    const btnEdit = makeBtn('Edit', 'secondary small', () => openProfileEditor(p));
    const btnDel = makeBtn('Delete', 'danger small', async () => {
      try {
        await api(`/api/profiles/${encodeURIComponent(p.id)}`, { method: 'DELETE' });
        await refreshState();
        showToast(`Deleted ${p.name}`);
      } catch (err) { showToast(err.message, true); }
    });

    actions.append(btnConn, btnPing, btnShare, btnEdit, btnDel);
    card.append(top, chips, actions);
    grid.appendChild(card);
  }
}

function makeBtn(label, cls, onClick) {
  const b = document.createElement('button');
  b.type = 'button';
  b.className = `btn ${cls}`;
  b.textContent = label;
  b.addEventListener('click', onClick);
  return b;
}

function renderConnections() {
  const tbody = $('#conns-tbody');
  tbody.replaceChildren();
  const list = state.connections || [];
  if (list.length === 0) {
    const tr = document.createElement('tr');
    const td = document.createElement('td');
    td.colSpan = 6;
    td.className = 'muted';
    td.textContent = 'No active connections right now.';
    tr.appendChild(td);
    tbody.appendChild(tr);
    return;
  }

  for (const c of list) {
    const tr = document.createElement('tr');
    const th = document.createElement('th');
    th.textContent = c.target;
    const tdProto = document.createElement('td');
    tdProto.textContent = (c.network || 'tcp').toUpperCase();
    const tdRoute = document.createElement('td');
    tdRoute.textContent = c.route;
    const tdUp = document.createElement('td');
    tdUp.textContent = formatBytes(c.upload);
    const tdDown = document.createElement('td');
    tdDown.textContent = formatBytes(c.download);
    const tdAct = document.createElement('td');
    tdAct.appendChild(makeBtn('Close', 'danger small', async () => {
      try {
        await api(`/api/connections/${c.id}`, { method: 'DELETE' });
      } catch (err) { showToast(err.message, true); }
    }));
    tr.append(th, tdProto, tdRoute, tdUp, tdDown, tdAct);
    tbody.appendChild(tr);
  }
}

function appendLog(entry) {
  const box = $('#logs-box');
  const row = document.createElement('div');
  row.className = 'log-line';
  const dt = new Date((entry.ts || 0) * 1000).toTimeString().slice(0, 8);
  row.innerHTML = `<span class="log-ts">${dt}</span><span class="log-lvl-${entry.level}">${entry.level}</span><span class="log-tag">[${entry.tag}]</span><span></span>`;
  row.lastElementChild.textContent = entry.message;
  box.appendChild(row);
  while (box.childElementCount > 250) box.firstElementChild.remove();
  box.scrollTop = box.scrollHeight;
}

function populateServerForm(srv) {
  if (!srv) return;
  const f = $('#form-server');
  f.elements.listen_port.value = srv.listen_port || 8443;
  f.elements.aead.value = srv.aead || 'chacha20-poly1305';
  f.elements.ascii.value = srv.ascii || 'prefer_entropy';
  f.elements.httpmask_mode.value = srv.httpmask?.mode || 'auto';
  f.elements.key.value = srv.key || '';
  f.elements.suspicious_action.value = srv.suspicious_action || 'silent';
  f.elements.fallback_address.value = srv.fallback_address || '';
  f.elements.enable_pure_downlink.checked = srv.enable_pure_downlink !== false;
  if (srv.client_key) {
    $('#srv-client-key-val').textContent = srv.client_key;
    $('#srv-client-key-box').hidden = false;
  }
}

// --- Canvas 60fps Bandwidth Chart ---
function drawChart() {
  const canvas = $('#speed-chart');
  if (!canvas) return;
  const ctx = canvas.getContext('2d');
  const rect = canvas.getBoundingClientRect();
  const dpr = window.devicePixelRatio || 1;
  const w = Math.max(300, Math.floor(rect.width || 560));
  const h = 170;
  if (canvas.width !== w * dpr || canvas.height !== h * dpr) {
    canvas.width = w * dpr;
    canvas.height = h * dpr;
  }
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, w, h);

  const cs = getComputedStyle(document.documentElement);
  const border = cs.getPropertyValue('--border').trim() || '#334155';
  const downColor = cs.getPropertyValue('--success').trim() || '#34d399';
  const upColor = cs.getPropertyValue('--accent').trim() || '#38bdf8';
  const muted = cs.getPropertyValue('--muted').trim() || '#94a3b8';

  const pts = state.history.slice(-60);
  let maxVal = 64 * 1024;
  for (const p of pts) {
    if (p.down_bps > maxVal) maxVal = p.down_bps;
    if (p.up_bps > maxVal) maxVal = p.up_bps;
  }

  // Grid lines
  ctx.strokeStyle = border;
  ctx.lineWidth = 1;
  ctx.font = '11px ui-monospace, monospace';
  ctx.fillStyle = muted;
  for (let i = 1; i <= 3; i++) {
    const y = Math.round((h / 4) * i) + 0.5;
    ctx.beginPath();
    ctx.moveTo(0, y);
    ctx.lineTo(w, y);
    ctx.stroke();
  }
  ctx.fillText(`Peak: ${formatSpeed(maxVal)}`, 8, 15);

  const plotSeries = (key, color, fillAlpha) => {
    if (pts.length < 2) return;
    ctx.beginPath();
    const step = w / 59;
    const offset = (60 - pts.length) * step;
    pts.forEach((p, idx) => {
      const x = offset + idx * step;
      const y = h - 8 - ((p[key] || 0) / maxVal) * (h - 28);
      if (idx === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    });
    ctx.strokeStyle = color;
    ctx.lineWidth = 2;
    ctx.stroke();

    ctx.lineTo(offset + (pts.length - 1) * step, h);
    ctx.lineTo(offset, h);
    ctx.closePath();
    ctx.globalAlpha = fillAlpha;
    ctx.fillStyle = color;
    ctx.fill();
    ctx.globalAlpha = 1;
  };

  plotSeries('down_bps', downColor, 0.14);
  plotSeries('up_bps', upColor, 0.12);
}

// --- Modal Profile Editor ---
function openProfileEditor(p) {
  const f = $('#form-profile');
  $('#modal-profile-title').textContent = p ? 'Edit Sudoku Node' : 'Add Sudoku Node';
  f.elements.id.value = p?.id || '';
  f.elements.name.value = p?.name || '';
  f.elements.server_address.value = p?.server_address || '';
  f.elements.key.value = p?.key || '';
  f.elements.ascii.value = p?.ascii || 'prefer_entropy';
  f.elements.aead.value = p?.aead || 'chacha20-poly1305';
  f.elements.httpmask_mode.value = p?.httpmask?.mode || 'auto';
  f.elements.multiplex.value = p?.multiplex || 'auto';
  f.elements.padding_min.value = p?.padding_min ?? 5;
  f.elements.padding_max.value = p?.padding_max ?? 15;
  f.elements.httpmask_host.value = p?.httpmask?.host || '';
  f.elements.httpmask_path.value = p?.httpmask?.path_root || '';
  f.elements.custom_table.value = p?.custom_table || '';
  f.elements.enable_pure_downlink.checked = p ? Boolean(p.enable_pure_downlink) : true;
  f.elements.httpmask_tls.checked = Boolean(p?.httpmask?.tls);
  f.elements.httpmask_disable.checked = Boolean(p?.httpmask?.disable);
  $('#modal-profile').showModal();
}

$('#btn-new-profile').addEventListener('click', () => {
  const f = $('#form-profile');
  f.reset();
  f.elements.id.value = '';
  $('#modal-profile-title').textContent = 'Add Sudoku Node';
});

$('#form-profile').addEventListener('submit', async (e) => {
  e.preventDefault();
  const f = e.target;
  const payload = {
    id: f.elements.id.value.trim(),
    name: f.elements.name.value.trim(),
    server_address: f.elements.server_address.value.trim(),
    key: f.elements.key.value.trim(),
    ascii: f.elements.ascii.value,
    aead: f.elements.aead.value,
    multiplex: f.elements.multiplex.value,
    padding_min: Number(f.elements.padding_min.value) || 5,
    padding_max: Number(f.elements.padding_max.value) || 15,
    custom_table: f.elements.custom_table.value.trim(),
    enable_pure_downlink: f.elements.enable_pure_downlink.checked,
    httpmask: {
      disable: f.elements.httpmask_disable.checked,
      mode: f.elements.httpmask_mode.value,
      tls: f.elements.httpmask_tls.checked,
      host: f.elements.httpmask_host.value.trim(),
      path_root: f.elements.httpmask_path.value.trim(),
    },
  };
  try {
    await api('/api/profiles', { method: 'POST', body: JSON.stringify(payload) });
    $('#modal-profile').close();
    await refreshState();
    showToast(`Saved node "${payload.name}"`);
  } catch (err) {
    showToast(err.message, true);
  }
});

$('#form-import').addEventListener('submit', async (e) => {
  e.preventDefault();
  const link = $('#input-import-link').value.trim();
  try {
    const prof = await api('/api/profiles/import', { method: 'POST', body: JSON.stringify({ link }) });
    $('#input-import-link').value = '';
    $('#modal-import').close();
    await refreshState();
    showToast(`Imported "${prof.name}" (${prof.server_address})`);
  } catch (err) {
    showToast(err.message, true);
  }
});

$('#btn-copy-link').addEventListener('click', async () => {
  const txt = $('#output-export-link').value;
  try {
    await navigator.clipboard.writeText(txt);
    showToast('Copied sudoku:// link to clipboard');
  } catch {
    $('#output-export-link').select();
    showToast('Select and copy the link manually');
  }
});

// --- Dashboard Controls ---
$('#btn-power').addEventListener('click', async () => {
  try {
    if (state.status?.connected) {
      state.status = await api('/api/disconnect', { method: 'POST' });
      showToast('Disconnected');
    } else {
      state.status = await api('/api/connect', { method: 'POST', body: JSON.stringify({}) });
      showToast('Connected to Sudoku VPN');
    }
    renderStatus();
    renderProfiles();
  } catch (err) {
    showToast(err.message, true);
  }
});

$('#btn-local-demo').addEventListener('click', async () => {
  const btn = $('#btn-local-demo');
  btn.disabled = true;
  try {
    const res = await api('/api/demo', { method: 'POST' });
    state.status = res.status;
    await refreshState();
    showToast(`Local Sudoku Server + Client connected (${res.profile.last_latency_ms || 1} ms)!`);
  } catch (err) {
    showToast(err.message, true);
  } finally {
    btn.disabled = false;
  }
});

$$('.seg-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    try {
      state.status = await api('/api/routing', { method: 'POST', body: JSON.stringify({ mode: btn.dataset.route }) });
      renderStatus();
      showToast(`Routing mode: ${btn.dataset.route.toUpperCase()}`);
    } catch (err) { showToast(err.message, true); }
  });
});

$('#toggle-sysproxy').addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  try {
    state.status = await api('/api/sysproxy', { method: 'POST', body: JSON.stringify({ enabled }) });
    renderStatus();
    showToast(enabled ? 'OS System Proxy enabled' : 'OS System Proxy disabled');
  } catch (err) {
    e.target.checked = !enabled;
    showToast(err.message, true);
  }
});

$('#toggle-tun').addEventListener('change', async (e) => {
  const enabled = e.target.checked;
  try {
    state.status = await api('/api/tun', { method: 'POST', body: JSON.stringify({ enabled }) });
    renderStatus();
    showToast(enabled ? 'Full-Device TUN VPN active!' : 'TUN mode disabled');
  } catch (err) {
    e.target.checked = !enabled;
    showToast(err.message, true);
  }
});

// --- Server & Crypto Tools ---
$('#btn-srv-start').addEventListener('click', async () => {
  const f = $('#form-server');
  const cfg = {
    listen_port: Number(f.elements.listen_port.value) || 8443,
    aead: f.elements.aead.value,
    ascii: f.elements.ascii.value,
    key: f.elements.key.value.trim(),
    suspicious_action: f.elements.suspicious_action.value,
    fallback_address: f.elements.fallback_address.value.trim(),
    enable_pure_downlink: f.elements.enable_pure_downlink.checked,
    padding_min: 5,
    padding_max: 15,
    httpmask: { disable: false, mode: f.elements.httpmask_mode.value },
  };
  try {
    const res = await api('/api/server/start', { method: 'POST', body: JSON.stringify(cfg) });
    state.status = res.status;
    populateServerForm(res.server);
    renderStatus();
    showToast(`Sudoku Server listening on :${res.server.listen_port}`);
  } catch (err) { showToast(err.message, true); }
});

$('#btn-srv-stop').addEventListener('click', async () => {
  try {
    state.status = await api('/api/server/stop', { method: 'POST' });
    renderStatus();
    showToast('Sudoku Server stopped');
  } catch (err) { showToast(err.message, true); }
});

$('#btn-keygen').addEventListener('click', async () => {
  try {
    const keys = await api('/api/keygen', { method: 'POST', body: JSON.stringify({}) });
    $('#out-pub-key').value = keys.master_public_key;
    $('#out-avail-key').value = keys.available_private_key;
    $('#out-master-key').value = keys.master_private_key;
    showToast('Generated new Ed25519 Master + Split keys');
  } catch (err) { showToast(err.message, true); }
});

$('#btn-split-key').addEventListener('click', async () => {
  const master = $('#out-master-key').value.trim() || $('#out-avail-key').value.trim();
  if (!master) {
    showToast('Generate a Master Key first', true);
    return;
  }
  try {
    const res = await api('/api/keygen', { method: 'POST', body: JSON.stringify({ more: master }) });
    $('#out-avail-key').value = res.split_private_key;
    showToast('Derived new split client private key');
  } catch (err) { showToast(err.message, true); }
});

$('#btn-run-bench').addEventListener('click', async () => {
  const btn = $('#btn-run-bench');
  const out = $('#bench-result');
  btn.disabled = true;
  out.textContent = 'Running end-to-end 4x4 Sudoku tunnel self-test (512 KB payload)...';
  try {
    const res = await api('/api/selftest', {
      method: 'POST',
      body: JSON.stringify({
        ascii: $('#bench-ascii').value,
        aead: $('#bench-aead').value,
        httpmask_mode: $('#bench-http').value,
      }),
    });
    out.textContent = [
      `STATUS:       PASS`,
      `Handshake:    ${res.handshake_ms} ms (Ed25519 split-key + X25519 PFS)`,
      `Transferred:  ${formatBytes(res.bytes_echoed)} verified bit-for-bit`,
      `Throughput:   ${res.throughput_mbps.toFixed(1)} Mbps`,
      `Cipher:       ${res.aead} | Sudoku: ${res.ascii} | HTTPMask: ${res.httpmask_mode}`,
      `Wire Sample:  ${res.wire_sample}`,
    ].join('\n');
  } catch (err) {
    out.textContent = `FAIL: ${err.message}`;
  } finally {
    btn.disabled = false;
  }
});

$('#btn-clear-logs').addEventListener('click', () => {
  $('#logs-box').replaceChildren();
});

// --- Bootstrap & Live SSE Telemetry ---
async function refreshState() {
  state.appState = await api('/api/state');
  renderProfiles();
  populateServerForm(state.appState.server);
  renderStatus();
}

async function init() {
  try {
    const [st, appSt, hist, logs] = await Promise.all([
      api('/api/status'),
      api('/api/state'),
      api('/api/traffic/history'),
      api('/api/logs'),
    ]);
    state.status = st;
    state.appState = appSt;
    state.history = hist || [];
    for (const l of (logs || [])) appendLog(l);
    renderProfiles();
    populateServerForm(appSt.server);
    renderStatus();
    drawChart();
  } catch (err) {
    showToast(`Failed to connect to core API: ${err.message}`, true);
  }

  const es = new EventSource('/api/events');
  es.addEventListener('status', (e) => {
    state.status = JSON.parse(e.data);
    if (state.status.traffic) {
      state.history.push(state.status.traffic);
      if (state.history.length > 60) state.history.shift();
    }
    renderStatus();
    drawChart();
  });
  es.addEventListener('connections', (e) => {
    state.connections = JSON.parse(e.data) || [];
    renderConnections();
  });
  es.addEventListener('log', (e) => {
    appendLog(JSON.parse(e.data));
  });
}

init();
