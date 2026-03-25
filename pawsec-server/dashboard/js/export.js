/**
 * Client-side CSV export for a session's prompts.
 */

function csvEscape(val) {
  const s = String(val ?? '').replace(/"/g, '""');
  return `"${s}"`;
}

export function exportSessionCSV(sessionId, prompts) {
  const headers = [
    'session_id', 'prompt_id', 'timestamp', 'platform',
    'risk_score', 'risk_level', 'action_taken',
    'pii_count', 'phi_count', 'code_injection_count',
    'api_secrets_count', 'credentials_count', 'private_url_count',
    'business_data_count', 'financial_data_count',
    'llm_intent', 'masked_text'
  ];

  const rows = [headers.join(',')];

  for (const p of prompts) {
    const a = p.analysis ?? {};
    rows.push([
      csvEscape(sessionId),
      csvEscape(p.prompt_id),
      csvEscape(p.timestamp),
      csvEscape(p.platform),
      csvEscape(p.risk_score ?? a.risk?.effective_score ?? 0),
      csvEscape(p.risk_level ?? a.risk?.risk_level ?? 'SAFE'),
      csvEscape(p.action_taken),
      csvEscape(a.pii?.count ?? 0),
      csvEscape(a.phi?.count ?? 0),
      csvEscape(a.code_injection?.count ?? 0),
      csvEscape(a.api_secrets?.count ?? 0),
      csvEscape(a.credentials?.count ?? 0),
      csvEscape(a.private_url?.count ?? 0),
      csvEscape(a.business_data?.count ?? 0),
      csvEscape(a.financial_data?.count ?? 0),
      csvEscape(a.llm?.Intent_Category ?? ''),
      csvEscape(p.masked_text ?? ''),
    ].join(','));
  }

  const blob = new Blob([rows.join('\n')], { type: 'text/csv;charset=utf-8;' });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement('a');
  a.href     = url;
  a.download = `pawsec-${sessionId}-${new Date().toISOString().slice(0,10)}.csv`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}
