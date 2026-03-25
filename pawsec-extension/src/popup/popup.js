/**
 * PawSec popup — stats, server status dot, toggle, "Open Dashboard".
 */

const toggle      = document.getElementById('enabled-toggle');
const statusDot   = document.getElementById('status-dot');
const statusText  = document.getElementById('status-text');
const serverDot   = document.getElementById('server-dot');
const serverLabel = document.getElementById('server-label');
const dashBtn     = document.getElementById('dashboard-btn');
const settingsBtn = document.getElementById('settings-btn');

// ─── Load state ──────────────────────────────────────────
chrome.storage.sync.get(
  { pawsec_enabled: true, server_url: '', server_api_key: '' },
  (cfg) => {
    toggle.checked = cfg.pawsec_enabled;
    updateStatus(cfg.pawsec_enabled);
    if (cfg.server_url) checkServer(cfg.server_url, cfg.server_api_key);
  }
);

// Show cached user identity immediately (populated by settings.js on save)
chrome.storage.local.get(
  { pawsec_user_name: '', pawsec_company_id: '' },
  ({ pawsec_user_name, pawsec_company_id }) => {
    if (pawsec_user_name) showUserIdentity(pawsec_user_name, pawsec_company_id);
  }
);

function renderStats(s) {
  document.getElementById('stat-total').textContent   = s.total   ?? 0;
  document.getElementById('stat-blocked').textContent = s.blocked ?? 0;
  document.getElementById('stat-warned').textContent  = s.warned  ?? 0;
}

// Initial load
chrome.storage.local.get(
  { pawsec_stats: { total: 0, blocked: 0, warned: 0 } },
  ({ pawsec_stats: s }) => renderStats(s)
);

// Live updates while popup is open
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === 'local' && changes.pawsec_stats) {
    renderStats(changes.pawsec_stats.newValue ?? { total: 0, blocked: 0, warned: 0 });
  }
});

// ─── Toggle ───────────────────────────────────────────────
toggle.addEventListener('change', () => {
  const enabled = toggle.checked;
  chrome.storage.sync.set({ pawsec_enabled: enabled });
  chrome.runtime.sendMessage({ type: 'PAWSEC_TOGGLE', enabled });
  updateStatus(enabled);
});

function updateStatus(enabled) {
  if (enabled) {
    statusDot.classList.remove('off');
    statusText.textContent = 'Protected';
    statusText.style.color = '';
  } else {
    statusDot.classList.add('off');
    statusText.textContent = 'Protection disabled';
    statusText.style.color = '#8b949e';
  }
}

// ─── User identity display ────────────────────────────────
function showUserIdentity(name, companyId) {
  const row = document.getElementById('user-identity-row');
  if (!row) return;
  document.getElementById('popup-user-name').textContent    = name || '—';
  document.getElementById('popup-user-company').textContent = companyId || '';
  row.style.display = 'block';
}

// ─── Server ping ──────────────────────────────────────────
async function checkServer(url, apiKey) {
  serverLabel.textContent = 'Checking server…';
  try {
    const res = await fetch(`${url}/health`, {
      headers: apiKey ? { 'X-API-Key': apiKey } : {},
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      serverDot.className = 'server-dot online';
      serverLabel.textContent = 'Server connected';
      dashBtn.disabled = false;
      dashBtn.addEventListener('click', () => {
        chrome.tabs.create({ url: `${url}/dashboard` });
      });
      // Fetch user identity and server stats
      if (apiKey) {
        fetchAndShowIdentity(url, apiKey);
        fetchServerStats(url, apiKey);
      }
      return;
    }
  } catch { /* offline */ }
  serverDot.className = 'server-dot offline';
  serverLabel.textContent = 'Server unreachable';
}

// ─── Server stats fetch ───────────────────────────────────
async function fetchServerStats(url, apiKey) {
  try {
    const res = await fetch(`${url}/api/v1/stats`, {
      headers: { 'X-API-Key': apiKey },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return;
    const data = await res.json();
    // Map server fields → local storage shape and persist so popup shows them
    const stats = {
      total:   data.total_prompts ?? 0,
      blocked: data.blocked       ?? 0,
      warned:  data.warned        ?? 0,
    };
    chrome.storage.local.set({ pawsec_stats: stats });
    // renderStats is called automatically via onChanged listener
  } catch { /* server unreachable — keep local counts */ }
}

async function fetchAndShowIdentity(url, apiKey) {
  try {
    const res = await fetch(`${url}/api/v1/me`, {
      headers: { 'X-API-Key': apiKey },
      signal: AbortSignal.timeout(4000),
    });
    if (!res.ok) return;
    const user = await res.json();
    showUserIdentity(user.name, user.company_id);
    // Cache for next popup open
    chrome.storage.local.set({
      pawsec_user_name:  user.name       || '',
      pawsec_company_id: user.company_id || '',
    });
  } catch { /* ignore */ }
}

// ─── Clear stats ──────────────────────────────────────────
document.getElementById('clear-stats-btn').addEventListener('click', async () => {
  // 1. Reset storage immediately — source of truth for popup on next open
  await chrome.storage.local.set({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } });
  // 2. Reset DOM
  document.getElementById('stat-total').textContent   = '0';
  document.getElementById('stat-blocked').textContent = '0';
  document.getElementById('stat-warned').textContent  = '0';
  // 3. Tell service worker to reset in-memory blockedCount + badge
  //    .catch() suppresses "message channel closed" when SW is dormant
  chrome.runtime.sendMessage({ type: 'PAWSEC_CLEAR_STATS' }).catch(() => {});
});

// ─── Settings ─────────────────────────────────────────────
settingsBtn.addEventListener('click', () => {
  chrome.runtime.openOptionsPage();
});
