/**
 * PawSec in-browser API secrets detector.
 * Ports the Python api-secrets-detector skill for offline use.
 * Covers 40+ services matching api_secrets_detector.py.
 */

import { maskValue } from './pii_detector.js';

const PATTERNS = [
  // ── AWS ──────────────────────────────────────────────────────────────────
  { service: 'AWS',          type: 'access_key_id',     severity: 'CRITICAL', re: /\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b/g },
  { service: 'AWS',          type: 'secret_access_key', severity: 'CRITICAL', re: /(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[=:]\s*["']?([A-Za-z0-9/+]{40})["']?/gi },
  { service: 'AWS',          type: 'session_token',     severity: 'CRITICAL', re: /(?:aws[_\-]?session[_\-]?token)\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi },
  // ── OpenAI ───────────────────────────────────────────────────────────────
  { service: 'OpenAI',       type: 'api_key',           severity: 'CRITICAL', re: /\bsk-[A-Za-z0-9]{48}\b/g },
  { service: 'OpenAI',       type: 'project_key',       severity: 'CRITICAL', re: /\bsk-proj-[A-Za-z0-9_\-]{48,}\b/g },
  // ── Anthropic ────────────────────────────────────────────────────────────
  { service: 'Anthropic',    type: 'api_key',           severity: 'CRITICAL', re: /\bsk-ant-api\d{2}-[A-Za-z0-9_\-]{93}\b/g },
  // ── GitHub ───────────────────────────────────────────────────────────────
  { service: 'GitHub',       type: 'pat_classic',       severity: 'CRITICAL', re: /\bghp_[A-Za-z0-9]{36}\b/g },
  { service: 'GitHub',       type: 'pat_fine_grained',  severity: 'CRITICAL', re: /\bgithub_pat_[A-Za-z0-9_]{82}\b/g },
  { service: 'GitHub',       type: 'oauth_token',       severity: 'HIGH',     re: /\bgho_[A-Za-z0-9]{36}\b/g },
  { service: 'GitHub',       type: 'app_token',         severity: 'HIGH',     re: /\bghu_[A-Za-z0-9]{36}\b/g },
  { service: 'GitHub',       type: 'refresh_token',     severity: 'HIGH',     re: /\bghr_[A-Za-z0-9]{36}\b/g },
  // ── Stripe ───────────────────────────────────────────────────────────────
  { service: 'Stripe',       type: 'secret_key_live',   severity: 'CRITICAL', re: /\bsk_live_[A-Za-z0-9]{24,}\b/g },
  { service: 'Stripe',       type: 'secret_key_test',   severity: 'HIGH',     re: /\bsk_test_[A-Za-z0-9]{24,}\b/g },
  { service: 'Stripe',       type: 'restricted_key',    severity: 'CRITICAL', re: /\brk_live_[A-Za-z0-9]{24,}\b/g },
  { service: 'Stripe',       type: 'webhook_secret',    severity: 'HIGH',     re: /\bwhsec_[A-Za-z0-9]{32,}\b/g },
  // ── Google Cloud ─────────────────────────────────────────────────────────
  { service: 'GCP',          type: 'api_key',           severity: 'CRITICAL', re: /\bAIza[0-9A-Za-z\-_]{35}\b/g },
  { service: 'GCP',          type: 'oauth_client_secret',severity: 'CRITICAL',re: /(?:client[_\-]?secret)["']?\s*:\s*["']?(GOCSPX-[A-Za-z0-9\-_]{28,})["']?/gi },
  // ── HuggingFace ──────────────────────────────────────────────────────────
  { service: 'HuggingFace',  type: 'api_token',         severity: 'HIGH',     re: /\bhf_[A-Za-z0-9]{37,}\b/g },
  // ── Twilio ───────────────────────────────────────────────────────────────
  { service: 'Twilio',       type: 'account_sid',       severity: 'HIGH',     re: /\bAC[a-f0-9]{32}\b/g },
  { service: 'Twilio',       type: 'auth_token',        severity: 'CRITICAL', re: /\bSK[a-f0-9]{32}\b/g },
  // ── Slack ────────────────────────────────────────────────────────────────
  { service: 'Slack',        type: 'bot_token',         severity: 'HIGH',     re: /\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b/g },
  { service: 'Slack',        type: 'user_token',        severity: 'HIGH',     re: /\bxoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+\b/g },
  { service: 'Slack',        type: 'app_token',         severity: 'HIGH',     re: /\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+\b/g },
  { service: 'Slack',        type: 'legacy_token',      severity: 'HIGH',     re: /\bxoxa-[0-9]+-[A-Za-z0-9]+\b/g },
  // ── SendGrid ─────────────────────────────────────────────────────────────
  { service: 'SendGrid',     type: 'api_key',           severity: 'HIGH',     re: /\bSG\.[A-Za-z0-9._\-]{64,}\b/g },
  // ── Azure ────────────────────────────────────────────────────────────────
  { service: 'Azure',        type: 'connection_string',  severity: 'CRITICAL', re: /DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}/gi },
  { service: 'Azure',        type: 'client_secret',      severity: 'CRITICAL', re: /(?:clientSecret|client_secret)\s*[=:]\s*["']([A-Za-z0-9~.\-_]{30,})["']/gi },
  // ── Heroku ───────────────────────────────────────────────────────────────
  { service: 'Heroku',       type: 'api_key',           severity: 'HIGH',     re: /\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b/g },
  // ── DigitalOcean ─────────────────────────────────────────────────────────
  { service: 'DigitalOcean', type: 'pat',               severity: 'HIGH',     re: /\bdop_v1_[a-f0-9]{64}\b/g },
  // ── Mailgun ──────────────────────────────────────────────────────────────
  { service: 'Mailgun',      type: 'api_key',           severity: 'HIGH',     re: /\bkey-[a-z0-9]{32}\b/g },
  // ── Mailchimp ────────────────────────────────────────────────────────────
  { service: 'Mailchimp',    type: 'api_key',           severity: 'HIGH',     re: /\b[a-f0-9]{32}-us[0-9]{1,2}\b/g },
  // ── Shopify ──────────────────────────────────────────────────────────────
  { service: 'Shopify',      type: 'admin_api_token',   severity: 'CRITICAL', re: /\bshpat_[A-Za-z0-9]{32}\b/g },
  { service: 'Shopify',      type: 'custom_app_token',  severity: 'HIGH',     re: /\bshpca_[A-Za-z0-9]{32}\b/g },
  // ── npm ──────────────────────────────────────────────────────────────────
  { service: 'npm',          type: 'access_token',      severity: 'HIGH',     re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  // ── PyPI ─────────────────────────────────────────────────────────────────
  { service: 'PyPI',         type: 'api_token',         severity: 'HIGH',     re: /\bpypi-[A-Za-z0-9_\-]{64,}\b/g },
  // ── Datadog ──────────────────────────────────────────────────────────────
  { service: 'Datadog',      type: 'api_key',           severity: 'HIGH',     re: /(?:dd[_\-]?api[_\-]?key)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi },
  // ── PagerDuty ────────────────────────────────────────────────────────────
  { service: 'PagerDuty',    type: 'api_key',           severity: 'HIGH',     re: /\bu\+[A-Za-z0-9_\-]{18}\b/g },
  // ── HashiCorp Vault ───────────────────────────────────────────────────────
  { service: 'HashiCorp Vault', type: 'token',          severity: 'CRITICAL', re: /\b(?:hvs|s)\.[A-Za-z0-9]{24,}\b/g },
  // ── JWT ──────────────────────────────────────────────────────────────────
  { service: 'JWT',          type: 'token',             severity: 'HIGH',     re: /\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b/g },
  // ── PEM Private Keys ─────────────────────────────────────────────────────
  { service: 'Cryptographic Key', type: 'rsa_private_key',    severity: 'CRITICAL', re: /-----BEGIN RSA PRIVATE KEY-----/gi },
  { service: 'Cryptographic Key', type: 'ec_private_key',     severity: 'CRITICAL', re: /-----BEGIN EC PRIVATE KEY-----/gi },
  { service: 'Cryptographic Key', type: 'openssh_private_key',severity: 'CRITICAL', re: /-----BEGIN OPENSSH PRIVATE KEY-----/gi },
  { service: 'Cryptographic Key', type: 'generic_private_key',severity: 'CRITICAL', re: /-----BEGIN PRIVATE KEY-----/gi },
  { service: 'Cryptographic Key', type: 'pgp_private_key',    severity: 'CRITICAL', re: /-----BEGIN PGP PRIVATE KEY BLOCK-----/gi },
  // ── Database Connection Strings ───────────────────────────────────────────
  { service: 'PostgreSQL',   type: 'connection_string', severity: 'CRITICAL', re: /postgresql(?::\/\/|\+psycopg2:\/\/)[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+/gi },
  { service: 'MySQL',        type: 'connection_string', severity: 'CRITICAL', re: /mysql(?::\/\/|\+mysqlconnector:\/\/)[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+/gi },
  { service: 'MongoDB',      type: 'connection_string', severity: 'CRITICAL', re: /mongodb(?:\+srv)?:\/\/[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+/gi },
  { service: 'Redis',        type: 'connection_string', severity: 'HIGH',     re: /redis:\/\/:[^@\s]{3,}@[A-Za-z0-9.\-]+/gi },
  { service: 'Generic DB',   type: 'jdbc_string',       severity: 'HIGH',     re: /jdbc:[a-z]+:\/\/[^;\s]+;password=[^;\s]+/gi },
];

// ── High-entropy context detector ─────────────────────────────────────────
const HIGH_ENTROPY_CTX_RE = /(?:secret|api[_\-]?key|token|credential|auth|private[_\-]?key|access[_\-]?key|client[_\-]?secret|app[_\-]?secret|bearer|passwd|password)\s*[=:]\s*["']?([A-Za-z0-9+/=_\-\.]{20,})["']?/gi;

function _shannonEntropy(s) {
  const freq = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  const len = s.length;
  return -Object.values(freq).reduce((acc, n) => {
    const p = n / len;
    return acc + p * Math.log2(p);
  }, 0);
}

function _checkHighEntropy(text) {
  const findings = [];
  HIGH_ENTROPY_CTX_RE.lastIndex = 0;
  for (const m of text.matchAll(HIGH_ENTROPY_CTX_RE)) {
    const candidate = m[1];
    if (!candidate || candidate.length < 20) continue;
    const entropy = _shannonEntropy(candidate);
    if (entropy >= 4.5) {
      findings.push({
        service:              'Generic',
        type:                 'high_entropy_secret',
        severity:             'HIGH',
        matched_value_masked: maskValue(candidate),
        entropy:              Math.round(entropy * 100) / 100,
      });
    }
  }
  return findings;
}

/**
 * @param {string} text
 * @returns {{ threat_detected: boolean, secrets_found: Array, count: number, risk_level: string }}
 */
export function analyzeAPISecrets(text) {
  const found = [];
  const seenPositions = [];

  for (const { service, type, severity, re } of PATTERNS) {
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      if (seenPositions.some(p => Math.abs(m.index - p) < 5)) continue;
      seenPositions.push(m.index);
      found.push({ service, type, severity, matched_value_masked: maskValue(m[0]), position: m.index });
    }
    re.lastIndex = 0;
  }

  // Add high-entropy generic secrets
  found.push(..._checkHighEntropy(text));

  const riskOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const maxRisk = found.reduce((acc, f) => {
    return (riskOrder[f.severity] ?? 0) > (riskOrder[acc] ?? 0) ? f.severity : acc;
  }, 'SAFE');

  return {
    threat_detected: found.length > 0,
    secrets_found:   found,
    count:           found.length,
    risk_level:      found.length ? maxRisk : 'SAFE',
  };
}
