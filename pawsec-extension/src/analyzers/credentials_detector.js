/**
 * PawSec in-browser credentials detector.
 * Ports the Python credentials-detector skill for offline use.
 */

import { maskValue } from './pii_detector.js';

const PLACEHOLDER_RE = /\b(?:example|sample|test|demo|placeholder|changeme|your[_\-]?password|enter[_\-]?password|my[_\-]?password|password123|admin123|secret123|xxxxxxxx|<password>|\[password\]|\{password\})\b/i;

const PATTERNS = [
  // ── Env / config file password variables ─────────────────────────────────
  {
    name: 'env_password',
    severity: 'CRITICAL',
    re: /(?:^|[\s\n])(?:PASSWORD|PASSWD|PWD|DB_PASS|DB_PASSWORD|SECRET|SECRET_KEY|APP_SECRET|MASTER_KEY|PRIVATE_KEY|API_SECRET|CLIENT_SECRET|AUTH_SECRET|SESSION_SECRET|ENCRYPTION_KEY|SIGNING_KEY)\s*=\s*(?!["'<{[$ ])["']?([^\s"';\n#]{4,})["']?/gim,
  },
  // ── Generic key=value password ────────────────────────────────────────────
  {
    name: 'generic_kv_password',
    severity: 'HIGH',
    re: /\b(?:password|passwd|pwd|pass)\s*[=:]\s*["']?(?!["'<{])([^\s"';\n,}{]{4,})["']?/gi,
  },
  // ── Generic key=value secret/token ───────────────────────────────────────
  {
    name: 'generic_kv_secret',
    severity: 'HIGH',
    re: /\b(?:secret|token|api_key|apikey|auth_token|access_token|client_secret|app_secret)\s*[=:]\s*["']?(?!["'<{])([^\s"';\n,}{]{8,})["']?/gi,
  },
  // ── JSON password / secret fields ────────────────────────────────────────
  {
    name: 'json_password',
    severity: 'CRITICAL',
    re: /"(?:password|passwd|pwd|pass)"\s*:\s*"(?!"|<|\$|\{)([^"]{4,})"/gi,
  },
  {
    name: 'json_secret',
    severity: 'HIGH',
    re: /"(?:secret|token|api_key|apikey|auth_token|access_token|client_secret|app_secret|private_key|signing_key)"\s*:\s*"(?!"|<)([^"]{8,})"/gi,
  },
  {
    name: 'json_credentials_object',
    severity: 'HIGH',
    re: /"credentials"\s*:\s*\{[^}]{10,}\}/gi,
  },
  // ── HTTP Authorization headers ────────────────────────────────────────────
  {
    name: 'basic_auth',
    severity: 'CRITICAL',
    re: /Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})/gi,
  },
  {
    name: 'bearer_token',
    severity: 'HIGH',
    re: /Authorization\s*:\s*Bearer\s+([A-Za-z0-9._\-]{20,})/gi,
  },
  // ── DSN / connection string password ─────────────────────────────────────
  {
    name: 'dsn_password',
    severity: 'CRITICAL',
    re: /(?:password|passwd|pwd)\s*=\s*([^;\s"']{4,})\s*(?:;|$)/gi,
  },
  // ── Hardcoded credentials in code ────────────────────────────────────────
  {
    name: 'hardcoded_password',
    severity: 'CRITICAL',
    re: /(?:String|string|str|var|let|const|val)\s+\w*[Pp]assword\w*\s*=\s*["'](?!"|<|\$)([^"']{4,})["']/g,
  },
  {
    name: 'hardcoded_secret',
    severity: 'HIGH',
    re: /(?:String|string|str|var|let|const|val)\s+\w*[Ss]ecret\w*\s*=\s*["'](?!"|<)([^"']{8,})["']/g,
  },
  // ── SMTP credentials ─────────────────────────────────────────────────────
  {
    name: 'smtp_credentials',
    severity: 'HIGH',
    re: /(?:smtp[_\-]?(?:user|pass|password|auth)|mail[_\-]?password)\s*[=:]\s*["']?([^\s"';\n]{4,})["']?/gi,
  },
  // ── XML/YAML password attribute ───────────────────────────────────────────
  {
    name: 'xml_yaml_password',
    severity: 'HIGH',
    re: /(?:password|passwd)\s*=\s*["'](?!"|<)([^"']{4,})["']/gi,
  },
  // ── cURL -u user:pass ─────────────────────────────────────────────────────
  {
    name: 'curl_credentials',
    severity: 'HIGH',
    re: /curl\s+.*?-u\s+[^\s]+:[^\s]+/gi,
  },
];

/**
 * @param {string} text
 * @returns {{ detected: boolean, findings: Array, count: number, risk_level: string }}
 */
export function analyzeCredentials(text) {
  const findings = [];

  for (const { name, severity, re } of PATTERNS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(text)) !== null) {
      const value = m[1] ?? '';
      if (PLACEHOLDER_RE.test(value.trim())) continue;
      findings.push({
        type: name,
        severity,
        value_masked: maskValue(value),
        context_snippet: text.slice(Math.max(0, m.index - 20), m.index + 60).replace(/\n/g, ' '),
      });
    }
    re.lastIndex = 0;
  }

  const riskOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const maxRisk = findings.reduce((acc, f) => {
    return (riskOrder[f.severity] ?? 0) > (riskOrder[acc] ?? 0) ? f.severity : acc;
  }, 'SAFE');

  return {
    detected:   findings.length > 0,
    findings,
    count:      findings.length,
    risk_level: findings.length ? maxRisk : 'SAFE',
  };
}
