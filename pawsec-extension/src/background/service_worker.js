/**
 * PawSec service worker (MV3).
 * Responsibilities:
 * - Session lifecycle management
 * - Optional server API delegation (POST /api/v1/analyze)
 * - Offline queue (max 50 items) with retry on reconnect
 * - Badge color + count (blocked prompts in current session)
 * - Extension toggle broadcast
 */

const DEFAULTS = {
  pawsec_enabled:    true,
  server_url:        '',
  server_api_key:    '',
  warn_threshold:    30,
  block_threshold:   70,
  min_score_to_send: 30,  // only send to server if score >= this
};

// ─── Session ─────────────────────────────────────────────
let currentSession = null;
let blockedCount   = 0;

const SESSION_STORE_KEY   = 'pawsec_current_session';
const SESSION_TIMEOUT_MS  = 30 * 60 * 1000; // 30 minutes idle → new session

async function ensureSession(platform = 'unknown') {
  const now   = Date.now();
  const today = new Date().toISOString().slice(0, 10); // 'YYYY-MM-DD'

  // 1. In-memory cache — still valid only if within the idle timeout
  if (currentSession) {
    try {
      const stored = await chrome.storage.local.get(SESSION_STORE_KEY);
      const entry  = stored[SESSION_STORE_KEY];
      if (entry?.id === currentSession && (now - (entry.last_active ?? 0)) < SESSION_TIMEOUT_MS) {
        // Touch last_active
        await chrome.storage.local.set({ [SESSION_STORE_KEY]: { ...entry, last_active: now } });
        return currentSession;
      }
    } catch { /* ignore */ }
    // Idle timeout exceeded — fall through to create a new session
    currentSession = null;
  }

  // 2. Restore from storage if within timeout window and same day
  try {
    const stored = await chrome.storage.local.get(SESSION_STORE_KEY);
    const entry  = stored[SESSION_STORE_KEY];
    if (
      entry?.date === today &&
      entry?.id &&
      (now - (entry.last_active ?? 0)) < SESSION_TIMEOUT_MS
    ) {
      currentSession = entry.id;
      await chrome.storage.local.set({ [SESSION_STORE_KEY]: { ...entry, last_active: now } });
      return currentSession;
    }
  } catch { /* storage unavailable */ }

  // 3. No valid session — create one on the server
  const { server_url, server_api_key } = await chrome.storage.sync.get(['server_url', 'server_api_key']);
  if (!server_url) return null;

  try {
    const res = await fetch(`${server_url}/api/v1/sessions`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': server_api_key || '' },
      body:    JSON.stringify({
        user_agent:        navigator?.userAgent ?? '',
        extension_version: chrome.runtime.getManifest().version,
        platform_hint:     platform,
      }),
    });
    if (res.ok) {
      const data = await res.json();
      currentSession = data.session_id;
      try {
        await chrome.storage.local.set({
          [SESSION_STORE_KEY]: { id: currentSession, date: today, last_active: now }
        });
      } catch { /* ignore */ }
      return currentSession;
    }
  } catch { /* offline */ }
  return null;
}

// ─── Offline Queue ───────────────────────────────────────
const QUEUE_KEY  = 'pawsec_offline_queue';
const MAX_QUEUE  = 50;

async function enqueue(item) {
  const { pawsec_offline_queue: q = [] } = await chrome.storage.local.get(QUEUE_KEY);
  q.push(item);
  if (q.length > MAX_QUEUE) q.shift(); // drop oldest
  await chrome.storage.local.set({ [QUEUE_KEY]: q });
}

async function flushQueue() {
  const { [QUEUE_KEY]: q = [] } = await chrome.storage.local.get(QUEUE_KEY);
  if (!q.length) return;
  const { server_url, server_api_key } = await chrome.storage.sync.get(['server_url', 'server_api_key']);
  if (!server_url) return;

  const remaining = [];
  for (const item of q) {
    try {
      const res = await fetch(`${server_url}/api/v1/analyze`, {
        method:  'POST',
        headers: { 'Content-Type': 'application/json', 'X-API-Key': server_api_key || '' },
        body:    JSON.stringify(item),
      });
      if (!res.ok) remaining.push(item);
    } catch {
      remaining.push(item);
      break; // still offline
    }
  }
  await chrome.storage.local.set({ [QUEUE_KEY]: remaining });
}

// ─── Server Submission ───────────────────────────────────
async function submitToServer({ text, platform, result }) {
  const settings = await chrome.storage.sync.get(Object.keys(DEFAULTS));
  const cfg = { ...DEFAULTS, ...settings };

  if (!cfg.server_url) return;

  const score   = result.risk?.effective_score ?? 0;
  const isRisky = score >= cfg.min_score_to_send;

  const sessionId = await ensureSession(platform) ?? `sess_local_${Date.now()}`;

  // Risky prompts  → send full text + all analyzers (deep server analysis)
  // Safe prompts   → send [REDACTED] + no analyzers (session counter only, text stays private)
  const body = {
    prompt_text:      isRisky ? text.slice(0, 4000) : '[REDACTED]',
    session_id:       sessionId,
    platform:         platform,
    extension_version: chrome.runtime.getManifest().version,
    in_browser_result: {
      pii_detected:            result.pii?.detected              ?? false,
      api_secrets_detected:    result.api_secrets?.threat_detected ?? false,
      credentials_detected:    result.credentials?.detected       ?? false,
      code_injection_detected: result.code_injection?.threat_detected ?? false,
      private_url_detected:    result.private_url?.detected       ?? false,
      risk_level: result.risk?.risk_level ?? 'SAFE',
      risk_score: score,
    },
    analyzers_requested: isRisky
      ? ['pii', 'phi', 'code_injection', 'api_secrets', 'credentials',
         'private_url', 'business_data', 'financial_data', 'llm', 'risk']
      : [],
  };

  try {
    const res = await fetch(`${cfg.server_url}/api/v1/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': cfg.server_api_key || '' },
      body:    JSON.stringify(body),
    });
    if (!res.ok) await enqueue(body);
  } catch {
    await enqueue(body);
  }
}

// ─── LLM Pre-Check ───────────────────────────────────────
// Fast path: sends only ['llm','risk'] to server so Ollama can classify
// semantic intent (harmful, jailbreak) for prompts that scored 0 in-browser.
// Aborts after 8 s — fails open (ALLOW) so user experience is never blocked
// by a slow/offline server.
async function runLLMCheck(text, platform) {
  const settings = await chrome.storage.sync.get(Object.keys(DEFAULTS));
  const cfg = { ...DEFAULTS, ...settings };
  if (!cfg.server_url) return { action: 'ALLOW' };

  const controller = new AbortController();
  // Ollama's server-side timeout is 10 s — give it 8 s before we fail open.
  const timeoutId  = setTimeout(() => controller.abort(), 8000);
  try {
    const sessionId = await ensureSession(platform) ?? `sess_local_${Date.now()}`;
    const res = await fetch(`${cfg.server_url}/api/v1/analyze`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json', 'X-API-Key': cfg.server_api_key || '' },
      body: JSON.stringify({
        prompt_text:         text.slice(0, 2000),
        session_id:          sessionId,
        platform:            platform,
        extension_version:   chrome.runtime.getManifest().version,
        analyzers_requested: ['llm', 'risk'],
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (res.ok) {
      const data = await res.json();
      return { action: data.action_taken, risk_score: data.risk_score, risk_level: data.risk_level };
    }
  } catch { clearTimeout(timeoutId); }
  return { action: 'ALLOW' };  // timeout or network error → fail open
}

// ─── Badge ───────────────────────────────────────────────
function updateBadge() {
  chrome.action.setBadgeText({ text: blockedCount > 0 ? String(blockedCount) : '' });
  chrome.action.setBadgeBackgroundColor({ color: '#b91c1c' });
}

// ─── Message Handlers ────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  // LLM pre-check: called by content script for score=0 prompts before submit.
  // Must return `true` to keep the message channel open for the async response.
  if (msg.type === 'LLM_PRE_CHECK') {
    runLLMCheck(msg.text, msg.platform).then(sendResponse);
    return true;
  }

  if (msg.type === 'PAWSEC_ANALYSIS') {
    submitToServer({
      text:     msg.text || '',
      platform: msg.platform,
      result:   msg.result,
    });
  }

  if (msg.type === 'PAWSEC_BLOCKED') {
    blockedCount++;
    updateBadge();
    // Store in session stats
    chrome.storage.local.get({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } }, (data) => {
      data.pawsec_stats.total++;
      data.pawsec_stats.blocked++;
      chrome.storage.local.set({ pawsec_stats: data.pawsec_stats });
    });
  }

  if (msg.type === 'PAWSEC_WARNED') {
    chrome.storage.local.get({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } }, (data) => {
      data.pawsec_stats.total++;
      data.pawsec_stats.warned++;
      chrome.storage.local.set({ pawsec_stats: data.pawsec_stats });
    });
  }

  if (msg.type === 'PAWSEC_ALLOWED') {
    chrome.storage.local.get({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } }, (data) => {
      data.pawsec_stats.total++;
      chrome.storage.local.set({ pawsec_stats: data.pawsec_stats });
    });
  }

  if (msg.type === 'GET_STATS') {
    chrome.storage.local.get({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } }, (data) => {
      chrome.runtime.sendMessage({ type: 'STATS_RESPONSE', stats: data.pawsec_stats });
    });
  }

  if (msg.type === 'PAWSEC_CLEAR_STATS') {
    blockedCount = 0;
    updateBadge();
    chrome.storage.local.set({ pawsec_stats: { total: 0, blocked: 0, warned: 0 } });
  }
});

// ─── Lifecycle ───────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.sync.get(Object.keys(DEFAULTS), (stored) => {
    const toSet = {};
    for (const [k, v] of Object.entries(DEFAULTS)) {
      if (!(k in stored)) toSet[k] = v;
    }
    if (Object.keys(toSet).length) chrome.storage.sync.set(toSet);
  });
  chrome.action.setBadgeText({ text: '' });
});

// On browser startup: clear the in-memory session cache and flush any offline
// queue. The date-keyed local storage entry is self-expiring — no need to
// remove it; a new day will naturally produce a new session.
chrome.runtime.onStartup.addListener(() => {
  currentSession = null;
  flushQueue();
});
self.addEventListener('fetch', () => {}); // keep SW active hint
