/**
 * PawSec inline warning banner (Shadow DOM).
 * Shown for MEDIUM risk (WARN action) — user can Proceed or Cancel.
 */

export function showWarningBanner(result, onProceed, onCancel) {
  // Remove any existing banner
  removeBanner();

  const host = document.createElement('div');
  host.id = 'pawsec-banner-host';
  host.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;';
  document.body.appendChild(host);

  const shadow = host.attachShadow({ mode: 'closed' });

  shadow.innerHTML = `
    <style>
      :host { all: initial; }
      .banner {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
        font-size: 14px;
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 10px 16px;
        background: #fff8fb;
        border-bottom: 2px solid #c87fa4;
        color: #2d1f2a;
        box-shadow: 0 4px 16px rgba(200,127,164,0.18);
        animation: slideIn 0.2s ease;
      }
      @keyframes slideIn {
        from { transform: translateY(-100%); opacity: 0; }
        to   { transform: translateY(0);    opacity: 1; }
      }
      .icon { font-size: 20px; flex-shrink: 0; }
      .content { flex: 1; }
      .title  { font-weight: 700; color: #a85f84; margin-bottom: 2px; }
      .detail { font-size: 12px; color: #a07890; }
      .actions { display: flex; gap: 8px; flex-shrink: 0; }
      button {
        padding: 6px 14px;
        border-radius: 6px;
        border: none;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: opacity 0.15s;
      }
      button:hover { opacity: 0.85; }
      .btn-cancel  { background: #c87fa4; color: #fff; }
      .btn-proceed { background: #fdf6f9; color: #a07890; border: 1px solid #f0d6e4; }
      .findings { display: flex; gap: 6px; flex-wrap: wrap; margin-top: 4px; }
      .tag {
        font-size: 11px;
        padding: 2px 7px;
        border-radius: 10px;
        background: rgba(200,127,164,0.12);
        color: #c87fa4;
        border: 1px solid rgba(200,127,164,0.35);
      }
    </style>
    <div class="banner" role="alert" aria-live="assertive">
      <span class="icon">${(result.effective_score ?? 0) < 30 ? '🔍' : '⚠️'}</span>
      <div class="content">
        <div class="title">${(result.effective_score ?? 0) < 30
          ? `PawSec: Prompt scanned — no threats found (Score: ${result.effective_score ?? 0})`
          : `PawSec: Sensitive content detected (Score: ${result.effective_score})`
        }</div>
        <div class="findings">${buildFindingTags(result)}</div>
        <div class="detail">${(result.effective_score ?? 0) < 30
          ? 'Review before sending — you can proceed or cancel.'
          : 'Review your prompt before sending.'
        }</div>
      </div>
      <div class="actions">
        <button class="btn-cancel"  id="cancel-btn">Cancel</button>
        <button class="btn-proceed" id="proceed-btn">Send Anyway</button>
      </div>
    </div>`;

  shadow.getElementById('cancel-btn').addEventListener('click', () => {
    removeBanner();
    onCancel?.();
  });
  shadow.getElementById('proceed-btn').addEventListener('click', () => {
    removeBanner();
    onProceed?.();
  });

  // Auto-dismiss after 15s if user does nothing
  host._timer = setTimeout(() => {
    removeBanner();
    onCancel?.();
  }, 15000);
}

export function showBlockOverlay(result, onDismiss) {
  removeBanner();

  const host = document.createElement('div');
  host.id = 'pawsec-banner-host';
  host.style.cssText = 'all:initial;position:fixed;inset:0;z-index:2147483647;';
  document.body.appendChild(host);

  const shadow = host.attachShadow({ mode: 'closed' });

  shadow.innerHTML = `
    <style>
      :host { all: initial; }
      .overlay {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
        position: fixed;
        inset: 0;
        background: rgba(200,127,164,0.25);
        backdrop-filter: blur(4px);
        display: flex;
        align-items: center;
        justify-content: center;
        animation: fadeIn 0.2s ease;
      }
      @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
      .card {
        background: #fff8fb;
        border: 2px solid #d95f5f;
        border-radius: 12px;
        padding: 28px 32px;
        max-width: 440px;
        width: 90vw;
        text-align: center;
        color: #2d1f2a;
        box-shadow: 0 8px 32px rgba(200,127,164,0.25);
      }
      .shield { width: 56px; height: 56px; margin: 0 auto 12px; display: block; }
      h2 { color: #d95f5f; font-size: 18px; font-weight: 700; margin: 0 0 8px; }
      .score { font-size: 28px; font-weight: 800; color: #d95f5f; margin: 8px 0; }
      .findings { display: flex; gap: 6px; flex-wrap: wrap; justify-content: center; margin: 10px 0; }
      .tag {
        font-size: 11px;
        padding: 2px 8px;
        border-radius: 10px;
        background: rgba(217,95,95,0.10);
        color: #d95f5f;
        border: 1px solid rgba(217,95,95,0.35);
      }
      p { font-size: 13px; color: #a07890; margin: 8px 0 20px; }
      button {
        padding: 10px 28px;
        border-radius: 8px;
        border: none;
        font-size: 14px;
        font-weight: 700;
        cursor: pointer;
        background: #d95f5f;
        color: white;
        transition: opacity 0.15s;
      }
      button:hover { opacity: 0.85; }
    </style>
    <div class="overlay" role="alertdialog" aria-modal="true" aria-label="PawSec security block">
      <div class="card">
        <svg class="shield" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
          <defs>
            <filter id="ps-fluffy" x="-30%" y="-30%" width="160%" height="160%">
              <feMorphology operator="dilate" in="SourceAlpha" radius="2.5" result="expanded"/>
              <feGaussianBlur in="expanded" stdDeviation="2.2" result="blurred"/>
              <feFlood flood-color="#ffffff" flood-opacity="0.9" result="white"/>
              <feComposite in="white" in2="blurred" operator="in" result="halo"/>
              <feMerge><feMergeNode in="halo"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
            <filter id="ps-shadow" x="-25%" y="-20%" width="150%" height="150%">
              <feDropShadow dx="0" dy="2" stdDeviation="3.5" flood-color="#0f172a" flood-opacity="0.18"/>
            </filter>
          </defs>
          <g filter="url(#ps-shadow)">
            <g filter="url(#ps-fluffy)">
              <ellipse cx="50" cy="68" rx="34" ry="28" fill="#ffffff"/>
              <circle cx="19" cy="47" r="10.5" fill="#ffffff"/>
              <circle cx="36" cy="31" r="12.5" fill="#ffffff"/>
              <circle cx="64" cy="31" r="12.5" fill="#ffffff"/>
              <circle cx="81" cy="47" r="10.5" fill="#ffffff"/>
            </g>
          </g>
          <circle cx="43" cy="72" r="10" fill="#F2AABD"/>
          <circle cx="57" cy="72" r="10" fill="#F2AABD"/>
          <circle cx="50" cy="64" r="10" fill="#F2AABD"/>
          <circle cx="19" cy="47" r="7"   fill="#F2AABD"/>
          <circle cx="36" cy="31" r="8.5" fill="#F2AABD"/>
          <circle cx="64" cy="31" r="8.5" fill="#F2AABD"/>
          <circle cx="81" cy="47" r="7"   fill="#F2AABD"/>
        </svg>
        <h2>Prompt Blocked by PawSec</h2>
        <div class="score">${result.effective_score} / 100</div>
        <div class="findings">${buildFindingTags(result)}</div>
        <p>This prompt contains critical security risks and has been blocked from submission. Please remove sensitive information before sending.</p>
        <button id="dismiss-btn">Dismiss</button>
      </div>
    </div>`;

  shadow.getElementById('dismiss-btn').addEventListener('click', () => {
    removeBanner();
    onDismiss?.();
  });

  // Allow Escape key
  const escHandler = (e) => {
    if (e.key === 'Escape') { removeBanner(); onDismiss?.(); document.removeEventListener('keydown', escHandler); }
  };
  document.addEventListener('keydown', escHandler);
}

function removeBanner() {
  const host = document.getElementById('pawsec-banner-host');
  if (host) {
    clearTimeout(host._timer);
    host.remove();
  }
}

// ─── Analyzing indicator ──────────────────────────────────────────────────────
// Shown while the LLM pre-check is in flight so the user knows the submit
// is being held intentionally (not frozen).

export function showAnalyzingIndicator() {
  removeBanner(); // remove any stale UI
  const host = document.createElement('div');
  host.id = 'pawsec-banner-host';
  host.style.cssText = 'all:initial;position:fixed;top:0;left:0;right:0;z-index:2147483647;';
  document.body.appendChild(host);

  const shadow = host.attachShadow({ mode: 'closed' });
  shadow.innerHTML = `
    <style>
      :host { all: initial; }
      .bar {
        font-family: 'Inter', 'Segoe UI', system-ui, sans-serif;
        font-size: 13px;
        display: flex;
        align-items: center;
        gap: 10px;
        padding: 8px 16px;
        background: #fff8fb;
        border-bottom: 2px solid #f0d6e4;
        color: #a07890;
      }
      .spinner {
        width: 14px; height: 14px;
        border: 2px solid #f0d6e4;
        border-top-color: #c87fa4;
        border-radius: 50%;
        animation: spin 0.7s linear infinite;
        flex-shrink: 0;
      }
      @keyframes spin { to { transform: rotate(360deg); } }
    </style>
    <div class="bar">
      <div class="spinner"></div>
      PawSec: Checking prompt security…
    </div>`;
}

export function removeAnalyzingIndicator() {
  removeBanner();
}

function buildFindingTags(result) {
  const tags = [];
  if (result.pii?.detected)            tags.push('PII');
  if (result.phi?.detected)            tags.push('PHI');
  if (result.api_secrets?.threat_detected) tags.push('API Secrets');
  if (result.credentials?.detected)   tags.push('Credentials');
  if (result.code_injection?.threat_detected) tags.push('Code Injection');
  else if (result.code_injection?.code_detected) tags.push('Code Detected');
  if (result.private_url?.detected)   tags.push('Private URLs');
  if (result.business_data?.detected) tags.push('Business Data');
  if (result.financial_data?.detected) tags.push('Financial Data');
  if (result.unknown_malicious_intent?.detected) tags.push('Malicious Intent');
  return tags.map(t => `<span class="tag">${t}</span>`).join('') || '<span class="tag">Low Risk</span>';
}
