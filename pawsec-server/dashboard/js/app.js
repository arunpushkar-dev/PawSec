/**
 * PawSec Dashboard — entry point.
 * Wires together WSClient, StatsManager, SessionsManager, SessionDetailManager.
 */

import { WSClient }           from './websocket_client.js';
import { StatsManager }       from './stats.js';
import { SessionsManager }    from './sessions.js';
import { SessionDetailManager } from './session_detail.js';

// ─── Config from URL or localStorage ────────────────────
const params   = new URLSearchParams(window.location.search);
const API_BASE = params.get('server') || localStorage.getItem('pawsec_server') || '';
const API_KEY  = params.get('key')    || localStorage.getItem('pawsec_api_key') || '';

// If the key arrived via URL param, persist it so page refreshes stay on the same user
if (params.get('key')) {
  localStorage.setItem('pawsec_api_key', params.get('key'));
}
const WS_URL   = (API_BASE
  ? API_BASE.replace(/^http/, 'ws')
  : `ws://${location.host}`) + '/ws/dashboard' + (API_KEY ? `?token=${API_KEY}` : '');

// ─── Managers ────────────────────────────────────────────
const stats  = new StatsManager(API_BASE);
const detail = new SessionDetailManager(API_BASE, API_KEY);
const sessions = new SessionsManager(API_BASE, API_KEY, (sessionId) => {
  detail.loadSession(sessionId);
  document.getElementById('empty-state').style.display = 'none';
  document.getElementById('session-detail').style.display = 'block';
});

// ─── WebSocket ───────────────────────────────────────────
const ws = new WSClient(WS_URL);

// Auto-refresh: always-on every 30s regardless of WS state.
// WS still handles instant updates; polling fills gaps and catches admin-side changes.
const POLL_INTERVAL_MS = 30_000;
let   wsLive           = false;

async function pollRefresh() {
  await sessions.load();
  if (localStorage.getItem('pawsec_local_cleared_at')) {
    stats.computeFromSessions(sessions.getSessions());
  } else {
    await stats.load(API_KEY);
  }
}

// Start always-on polling — runs unconditionally
setInterval(pollRefresh, POLL_INTERVAL_MS);

ws.addEventListener('status', (ev) => {
  const dot   = document.getElementById('ws-dot');
  const label = document.getElementById('ws-label');
  const s = ev.detail;
  dot.className = `ws-dot ${s}`;
  const msgs = {
    connected: 'Live', connecting: 'Connecting…',
    reconnecting: 'Reconnecting…', error: 'Error', disconnected: 'Offline'
  };
  label.textContent = msgs[s] ?? s;

  if (s === 'connected') {
    const wasOffline = !wsLive;
    wsLive = true;
    // Reload data to fill any gap that occurred while WS was down
    if (wasOffline) pollRefresh();
  } else {
    wsLive = false;
  }
});

ws.addEventListener('message', (ev) => {
  const msg = ev.detail;
  if (msg.event === 'new_prompt') {
    sessions.prependSession(msg);
    detail.handleNewPrompt(msg);
    // Recompute stats from sessions when Clear View is active so counts stay in sync
    if (localStorage.getItem('pawsec_local_cleared_at')) {
      stats.computeFromSessions(sessions.getSessions());
    } else {
      stats.handleNewPrompt(msg);
    }
  }
  // ping — no action needed
});

// ─── User info ───────────────────────────────────────────
async function loadUserInfo() {
  if (!API_KEY) return;
  try {
    const res = await fetch(`${API_BASE}/api/v1/me`, {
      headers: { 'X-API-Key': API_KEY },
    });
    if (!res.ok) return;
    const user = await res.json();
    // Cache so the settings modal can show identity without an extra fetch
    localStorage.setItem('pawsec_user_name',  user.name       || '');
    localStorage.setItem('pawsec_company_id', user.company_id || '');
    localStorage.setItem('pawsec_user_email', user.email      || '');

    const headerRight = document.querySelector('.header-right');
    if (headerRight) {
      const userEl = document.createElement('span');
      userEl.style.cssText = 'font-size:12px;color:var(--text-secondary);margin-left:4px;';
      const company = user.company_id ? ` · ${user.company_id}` : '';
      userEl.textContent = `${user.name}${company} (${user.email})`;
      headerRight.insertBefore(userEl, headerRight.firstChild);
      if (user.is_admin) {
        const adminLink = document.createElement('a');
        adminLink.href = '/dashboard/admin';
        adminLink.style.cssText = 'font-size:12px;color:var(--teal);margin-left:8px;text-decoration:none;';
        adminLink.textContent = 'Admin';
        headerRight.insertBefore(adminLink, headerRight.firstChild);
      }
    }
  } catch (_) {}
}

// ─── Boot ────────────────────────────────────────────────
async function init() {
  await Promise.all([
    stats.load(API_KEY),
    sessions.load(),
    loadUserInfo(),
  ]);
  // If Clear View is active, override stats with counts from the displayed sessions
  if (localStorage.getItem('pawsec_local_cleared_at')) {
    stats.computeFromSessions(sessions.getSessions());
  }
  ws.connect();
}

init();

// Expose hooks for the inline clear-view script
window.__pawsec = {
  reloadSessions: async () => {
    await sessions.load();
    // After sessions load, recompute stats from them so counts stay consistent
    if (localStorage.getItem('pawsec_local_cleared_at')) {
      stats.computeFromSessions(sessions.getSessions());
    } else {
      await stats.load(API_KEY);
    }
  },
  resetStats:  () => stats.resetView(),
  reloadStats: async () => {
    localStorage.removeItem('pawsec_local_cleared_at');
    await Promise.all([stats.load(API_KEY), sessions.load()]);
  },
};
// Clean up legacy key from old ID-snapshot approach
localStorage.removeItem('pawsec_hidden_sessions');
