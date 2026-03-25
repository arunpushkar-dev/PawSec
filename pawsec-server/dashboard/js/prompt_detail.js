/**
 * Renders the expandable per-prompt analysis card.
 */

const SEVERITY_CLASS = {
  Critical: 'critical', HIGH: 'critical', High: 'high',
  MEDIUM: 'medium', Medium: 'medium', LOW: '', Low: ''
};

function riskClass(level) {
  const map = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: '', SAFE: '' };
  return map[level] ?? '';
}

function chipRow(label, count, icon = '') {
  const hasFinding = count > 0;
  return `<div class="finding-chip ${hasFinding ? 'has-findings' : ''}">
    <span>${icon} ${label}</span>
    <span class="chip-count">${count}</span>
  </div>`;
}

function llmTags(llm) {
  if (!llm?.available) return '';
  const tags = [
    { label: llm.Intent_Category,           sev: llm.Intent_Risk_Severity },
    { label: llm.Generic_Persona_Category,   sev: llm.Persona_Risk_Severity },
    { label: llm.Pattern,                    sev: llm.Pattern_Risk_Severity },
  ].filter(t => t.label && t.label !== 'Benign' && t.label !== 'Neutral/Default State' && t.label !== 'Normal');

  if (!tags.length) return '';
  return `<div class="llm-row">
    ${tags.map(t => `<span class="llm-tag ${SEVERITY_CLASS[t.sev] ?? ''}">${t.label}</span>`).join('')}
  </div>`;
}

export function buildPromptCard(prompt) {
  const a = prompt.analysis ?? {};
  const risk = a.risk ?? {};
  const recs = risk.recommendations ?? [];
  const score = prompt.risk_score ?? risk.effective_score ?? 0;
  const level = prompt.risk_level ?? risk.risk_level ?? 'SAFE';
  const time = new Date(prompt.timestamp).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  const previewText = (prompt.masked_text ?? '').slice(0, 120);

  const card = document.createElement('div');
  card.className = `prompt-card risk-${level}`;
  card.innerHTML = `
    <div class="prompt-card-header">
      <span class="prompt-time">${time}</span>
      <span class="prompt-preview">${escapeHtml(previewText)}</span>
      <span class="risk-badge ${prompt.action_taken}">${prompt.action_taken ?? 'ALLOWED'}</span>
      <span class="prompt-score">${score}</span>
      <svg class="expand-icon" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><polyline points="9 18 15 12 9 6"/></svg>
    </div>
    <div class="prompt-detail">
      <div class="masked-text-block">${escapeHtml(prompt.masked_text ?? '')}</div>
      <div class="findings-grid">
        ${chipRow('PII',            a.pii?.count ?? 0,                       '🪪')}
        ${chipRow('PHI',            a.phi?.count ?? 0,                       '🏥')}
        ${chipRow('Code Injection', a.code_injection?.count ?? 0,            '💉')}
        ${chipRow('API Secrets',    a.api_secrets?.count ?? 0,               '🔑')}
        ${chipRow('Credentials',    a.credentials?.count ?? 0,               '🔐')}
        ${chipRow('Private URLs',   a.private_url?.count ?? 0,               '🔒')}
        ${chipRow('Business Data',  a.business_data?.count ?? 0,             '🏢')}
        ${chipRow('Financial',      a.financial_data?.count ?? 0,            '💰')}
        ${chipRow('Unknown Malicious Intent', a.unknown_malicious_intent?.count ?? 0,  '🎭')}
      </div>
      ${llmTags(a.llm_classification)}
      ${recs.length ? `<div class="recommendations">
        <h4>Recommendations</h4>
        ${recs.map(r => `<div class="rec-item">${escapeHtml(r)}</div>`).join('')}
      </div>` : ''}
    </div>`;

  card.querySelector('.prompt-card-header').addEventListener('click', () => {
    card.classList.toggle('expanded');
  });

  return card;
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}
