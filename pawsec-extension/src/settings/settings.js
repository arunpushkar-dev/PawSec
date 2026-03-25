/**
 * PawSec settings page.
 */

const DEFAULTS = {
  server_url:        '',
  server_api_key:    '',
  warn_threshold:    30,
  block_threshold:   70,
  pawsec_enabled:    true,
  az_pii:            true,
  az_code_injection: true,
  az_api_secrets:    true,
  az_credentials:    true,
  az_private_url:    true,
  az_phi:            true,
  az_business_data:  true,
  az_financial_data:    true,
  az_unknown_malicious: true,
  az_llm:               true,
};

// ─── Elements ─────────────────────────────────────────────
const $id   = (id) => document.getElementById(id);
const warn  = $id('warn-threshold');
const block = $id('block-threshold');

// ─── Fetch user identity from /api/v1/me ──────────────────
async function fetchUserIdentity(serverUrl, apiKey) {
  const identityEl = $id('user-identity');
  const errEl      = $id('user-identity-err');
  identityEl.style.display = 'none';
  errEl.style.display      = 'none';
  if (!serverUrl || !apiKey) return;
  try {
    const res = await fetch(`${serverUrl.replace(/\/$/, '')}/api/v1/me`, {
      headers: { 'X-API-Key': apiKey },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) {
      errEl.textContent = `API key not recognised (HTTP ${res.status}) — check key and server URL.`;
      errEl.style.display = 'block';
      return;
    }
    const user = await res.json();
    $id('uid-name').textContent    = user.name || '';
    $id('uid-company').textContent = user.company_id ? `(${user.company_id})` : '';
    $id('uid-email').textContent   = user.email || '';
    identityEl.style.display = 'block';
    // Cache in chrome.storage.local so popup can show identity without re-fetching
    chrome.storage.local.set({
      pawsec_user_name:  user.name       || '',
      pawsec_company_id: user.company_id || '',
    });
    // Push new key + identity into any open dashboard tab's localStorage, then reload it
    const cleanUrl = serverUrl.replace(/\/$/, '');
    const userName  = user.name       || '';
    const companyId = user.company_id || '';
    try {
      chrome.tabs.query({}, (tabs) => {
        tabs.forEach((tab) => {
          if (!tab.url) return;
          // Match user dashboard only — skip /dashboard/admin
          if (!/\/dashboard(\?|$)/.test(tab.url)) return;
          chrome.scripting.executeScript({
            target: { tabId: tab.id },
            func: (srv, key, name, co) => {
              localStorage.setItem('pawsec_server',     srv);
              localStorage.setItem('pawsec_api_key',    key);
              localStorage.setItem('pawsec_user_name',  name);
              localStorage.setItem('pawsec_company_id', co);
              location.reload();
            },
            args: [cleanUrl, apiKey, userName, companyId],
          });
        });
      });
    } catch (_) {}
  } catch (e) {
    errEl.textContent = 'Could not verify key: ' + e.message.slice(0, 80);
    errEl.style.display = 'block';
  }
}

// ─── Fetch + cache server stats into local storage ────────
async function fetchAndCacheStats(serverUrl, apiKey) {
  try {
    const res = await fetch(`${serverUrl.replace(/\/$/, '')}/api/v1/stats`, {
      headers: { 'X-API-Key': apiKey },
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) return;
    const data = await res.json();
    chrome.storage.local.set({
      pawsec_stats: {
        total:   data.total_prompts ?? 0,
        blocked: data.blocked       ?? 0,
        warned:  data.warned        ?? 0,
      },
    });
  } catch { /* server unreachable */ }
}

// ─── Load ─────────────────────────────────────────────────
chrome.storage.sync.get(DEFAULTS, (cfg) => {
  $id('server-url').value      = cfg.server_url;
  $id('api-key').value         = cfg.server_api_key;
  warn.value                   = cfg.warn_threshold;
  block.value                  = cfg.block_threshold;
  $id('warn-val').textContent  = cfg.warn_threshold;
  $id('block-val').textContent = cfg.block_threshold;

  $id('az-pii').checked            = cfg.az_pii;
  $id('az-code-injection').checked = cfg.az_code_injection;
  $id('az-api-secrets').checked    = cfg.az_api_secrets;
  $id('az-credentials').checked    = cfg.az_credentials;
  $id('az-private-url').checked    = cfg.az_private_url;
  $id('az-phi').checked            = cfg.az_phi;
  $id('az-business-data').checked  = cfg.az_business_data;
  $id('az-financial-data').checked    = cfg.az_financial_data;
  $id('az-unknown-malicious').checked = cfg.az_unknown_malicious;
  $id('az-llm').checked               = cfg.az_llm;

  // Auto-show identity if key already saved
  if (cfg.server_url && cfg.server_api_key) {
    fetchUserIdentity(cfg.server_url, cfg.server_api_key);
  }
});

// ─── Live range display ───────────────────────────────────
warn.addEventListener('input', () => { $id('warn-val').textContent = warn.value; });
block.addEventListener('input', () => { $id('block-val').textContent = block.value; });

// ─── Test connection ──────────────────────────────────────
$id('test-btn').addEventListener('click', async () => {
  const url    = $id('server-url').value.trim();
  const apiKey = $id('api-key').value.trim();
  const result = $id('test-result');
  if (!url) { result.textContent = 'Enter server URL first'; result.className = 'test-result err'; return; }
  result.textContent = 'Testing…';
  result.className   = 'test-result';
  try {
    const res = await fetch(`${url}/health`, {
      headers: apiKey ? { 'X-API-Key': apiKey } : {},
      signal: AbortSignal.timeout(4000),
    });
    const data = res.ok ? await res.json() : null;
    if (res.ok) {
      const llmStatus = data?.ollama_available
        ? 'LLM (Ollama) online'
        : 'LLM (Ollama) offline — deep analysis will skip LLM skill';
      result.innerHTML  = `PawSec Server v${data?.version ?? '?'} reachable &nbsp;|&nbsp; ${llmStatus}`;
      result.className  = data?.ollama_available ? 'test-result ok' : 'test-result warn';
      // Auto-verify the API key identity after a successful connection test
      if (apiKey) fetchUserIdentity(url, apiKey);
    } else {
      result.textContent = `PawSec Server returned HTTP ${res.status} — check server logs`;
      result.className   = 'test-result err';
    }
  } catch (e) {
    result.textContent = 'Unreachable: ' + e.message.slice(0, 60);
    result.className   = 'test-result err';
  }
});

// ─── Toast ────────────────────────────────────────────────
let _toastTimer = null;
function showToast(msg, type = 'success', durationMs = 3000) {
  const toast = $id('toast');
  const bar   = toast.querySelector('.toast-bar');

  // Reset any running animation
  bar.style.animation = 'none';
  void bar.offsetWidth; // reflow

  toast.className = `toast toast-${type}`;
  toast.querySelector('.toast-icon').textContent = type === 'success' ? '✅' : '❌';
  toast.querySelector('.toast-msg').textContent  = msg;

  // Drain bar animation
  bar.style.animation = `toast-drain ${durationMs}ms linear forwards`;

  toast.classList.add('show');
  clearTimeout(_toastTimer);
  _toastTimer = setTimeout(() => toast.classList.remove('show'), durationMs);
}

// ─── Button state helper ──────────────────────────────────
function setBtnState(btn, state, label) {
  btn.classList.remove('state-saving', 'state-success', 'state-error');
  if (state) btn.classList.add(`state-${state}`);
  btn.querySelector('.btn-label').textContent = label;
  btn.disabled = state === 'saving';
}

// ─── Save ─────────────────────────────────────────────────
$id('save-btn').addEventListener('click', () => {
  const saveBtn = $id('save-btn');
  const errEl   = $id('threshold-error');
  const warnVal  = Number(warn.value);
  const blockVal = Number(block.value);

  // Validate thresholds
  if (warnVal >= blockVal) {
    errEl.textContent = `Warn threshold (${warnVal}) must be lower than Block threshold (${blockVal}).`;
    showToast('Invalid thresholds — warn must be below block.', 'error');
    return;
  }
  errEl.textContent = '';

  const cfg = {
    server_url:        $id('server-url').value.trim(),
    server_api_key:    $id('api-key').value.trim(),
    warn_threshold:    warnVal,
    block_threshold:   blockVal,
    az_pii:            $id('az-pii').checked,
    az_code_injection: $id('az-code-injection').checked,
    az_api_secrets:    $id('az-api-secrets').checked,
    az_credentials:    $id('az-credentials').checked,
    az_private_url:    $id('az-private-url').checked,
    az_phi:            $id('az-phi').checked,
    az_business_data:  $id('az-business-data').checked,
    az_financial_data:    $id('az-financial-data').checked,
    az_unknown_malicious: $id('az-unknown-malicious').checked,
    az_llm:               $id('az-llm').checked,
  };

  setBtnState(saveBtn, 'saving', 'Saving…');

  chrome.storage.sync.set(cfg, () => {
    if (chrome.runtime.lastError) {
      setBtnState(saveBtn, 'error', '✗ Failed');
      showToast('Save failed: ' + chrome.runtime.lastError.message, 'error', 4000);
      setTimeout(() => setBtnState(saveBtn, null, 'Save Settings'), 2500);
      return;
    }
    setBtnState(saveBtn, 'success', '✓ Saved');
    showToast('Settings saved successfully.', 'success');
    setTimeout(() => setBtnState(saveBtn, null, 'Save Settings'), 2500);
    // Re-verify identity and pull server stats with the newly saved key
    if (cfg.server_url && cfg.server_api_key) {
      fetchUserIdentity(cfg.server_url, cfg.server_api_key);
      fetchAndCacheStats(cfg.server_url, cfg.server_api_key);
    }
  });
});

// ─── Reset ────────────────────────────────────────────────
$id('reset-btn').addEventListener('click', () => {
  chrome.storage.sync.set(DEFAULTS, () => {
    showToast('Settings reset to defaults.', 'success', 1500);
    setTimeout(() => location.reload(), 400);
  });
});
