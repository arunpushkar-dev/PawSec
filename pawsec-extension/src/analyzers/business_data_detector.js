/**
 * PawSec Business Data Detector (browser port of business_data_detector.py)
 *
 * Detects business entity identifiers: EIN (US), DUNS, EU VAT (27 countries),
 * UK Company Number, ABN/ACN (Australia), Canada BN.
 *
 * Scope: Organisation/entity-level identifiers only.
 * Individual identity documents (driver's licences, passports, etc.) are handled
 * by pii_detector.js.
 *
 * Returns:
 *   detected    — true if any identifiers found
 *   findings    — array of { type, name, jurisdiction, severity, value_masked, position }
 *   count       — total findings
 *   risk_level  — SAFE / MEDIUM / HIGH / CRITICAL
 */

// ── Helper: mask sensitive values ─────────────────────────────────────────
function _maskValue(value) {
  if (value.length <= 4) return '*'.repeat(value.length);
  return value.slice(0, 2) + '*'.repeat(value.length - 4) + value.slice(-2);
}

// ── Business identifier patterns ──────────────────────────────────────────
const PATTERNS = [
  // US EIN (labeled)
  {
    type: 'ein',
    name: 'US Employer Identification Number (EIN)',
    jurisdiction: 'United States',
    severity: 'HIGH',
    re: /(?:EIN|Employer\s+Identification\s+(?:Number|No\.?)|Federal\s+Tax\s+ID|FEIN)\s*[:\-#]?\s*(\b\d{2}-\d{7}\b)/gi,
  },
  // DUNS Number
  {
    type: 'duns',
    name: 'DUNS Number (Dun & Bradstreet)',
    jurisdiction: 'International',
    severity: 'MEDIUM',
    re: /(?:DUNS|D[-&]U[-&]N[-&]S|Dun\s+&\s+Bradstreet)\s*(?:Number|No\.?|#)?\s*[:\-]?\s*(\b\d{2}-\d{3}-\d{4}\b|\b\d{9}\b)/gi,
  },
  // EU VAT (27 member states)
  {
    type: 'vat_eu',
    name: 'EU VAT Number',
    jurisdiction: 'European Union',
    severity: 'MEDIUM',
    re: /(?:VAT|Value\s+Added\s+Tax)\s*(?:Number|No\.?|#|ID|Registration)?\s*[:\-]?\s*(AT\s*U\d{8}|BE\s*0\d{9}|BG\s*\d{9,10}|CY\s*\d{8}[A-Z]|CZ\s*\d{8,10}|DE\s*\d{9}|DK\s*\d{8}|EE\s*\d{9}|EL\s*\d{9}|ES\s*[A-Z0-9]\d{7}[A-Z0-9]|FI\s*\d{8}|FR\s*[A-HJ-NP-Z0-9]{2}\d{9}|HR\s*\d{11}|HU\s*\d{8}|IE\s*\d{7}[A-Z]{1,2}|IT\s*\d{11}|LT\s*(?:\d{9}|\d{12})|LU\s*\d{8}|LV\s*\d{11}|MT\s*\d{8}|NL\s*\d{9}B\d{2}|PL\s*\d{10}|PT\s*\d{9}|RO\s*\d{2,10}|SE\s*\d{12}|SI\s*\d{8}|SK\s*\d{10})/gi,
  },
  // UK Company Number
  {
    type: 'uk_company',
    name: 'UK Company Registration Number',
    jurisdiction: 'United Kingdom',
    severity: 'MEDIUM',
    re: /(?:Company\s+(?:Number|No\.?|Registration)|Companies\s+House|CRN)\s*[:\-]?\s*(\b(?:[A-Z]{2}|[A-Z])?\d{6,8}\b)/gi,
  },
  // Australian Business Number
  {
    type: 'abn',
    name: 'Australian Business Number (ABN)',
    jurisdiction: 'Australia',
    severity: 'MEDIUM',
    re: /(?:ABN|Australian\s+Business\s+Number)\s*[:\-]?\s*(\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b)/gi,
  },
  // Australian Company Number
  {
    type: 'acn',
    name: 'Australian Company Number (ACN)',
    jurisdiction: 'Australia',
    severity: 'MEDIUM',
    re: /(?:ACN|Australian\s+Company\s+Number)\s*[:\-]?\s*(\b\d{3}\s?\d{3}\s?\d{3}\b)/gi,
  },
  // Canada Business Number
  {
    type: 'canada_bn',
    name: 'Canada Business Number (BN)',
    jurisdiction: 'Canada',
    severity: 'MEDIUM',
    re: /(?:BN|Business\s+Number|CRA\s+Number)\s*[:\-]?\s*(\b\d{9}\s?(?:RT|RP|RC|RZ)\s?\d{4}\b)/gi,
  },
];

// EIN standalone context (labeled separately in Python)
const EIN_CONTEXT_RE  = /(?:EIN|FEIN|Tax\s+ID|Employer\s+ID)/gi;
const EIN_STANDALONE  = /\b(\d{2}-\d{7})\b/g;

/**
 * @param {string} text
 * @returns {{
 *   detected: boolean,
 *   findings: Array,
 *   count: number,
 *   risk_level: string
 * }}
 */
export function analyzeBusinessData(text) {
  const findings = [];
  const seenPositions = [];

  for (const spec of PATTERNS) {
    spec.re.lastIndex = 0;
    for (const m of text.matchAll(spec.re)) {
      const pos = m.index;
      if (seenPositions.some(p => Math.abs(pos - p) < 10)) continue;
      seenPositions.push(pos);

      const value = m[1] ?? m[0];
      findings.push({
        type:         spec.type,
        name:         spec.name,
        jurisdiction: spec.jurisdiction,
        severity:     spec.severity,
        value_masked: _maskValue(value),
        position:     pos,
      });
    }

    // EIN standalone context check (mirrors Python standalone logic)
    if (spec.type === 'ein') {
      EIN_CONTEXT_RE.lastIndex = 0;
      for (const ctxM of text.matchAll(EIN_CONTEXT_RE)) {
        const windowStart = Math.max(0, ctxM.index - 5);
        const windowEnd   = Math.min(text.length, ctxM.index + ctxM[0].length + 30);
        const window      = text.slice(windowStart, windowEnd);
        EIN_STANDALONE.lastIndex = 0;
        for (const einM of window.matchAll(EIN_STANDALONE)) {
          const absPos = windowStart + einM.index;
          if (seenPositions.some(p => Math.abs(absPos - p) < 10)) continue;
          seenPositions.push(absPos);
          findings.push({
            type:         'ein',
            name:         'US Employer Identification Number (EIN)',
            jurisdiction: 'United States',
            severity:     'HIGH',
            value_masked: _maskValue(einM[1]),
            position:     absPos,
          });
        }
      }
    }
  }

  const risk_level = findings.length
    ? (findings.some(f => f.severity === 'CRITICAL') ? 'CRITICAL'
       : findings.some(f => f.severity === 'HIGH')   ? 'HIGH'
       : 'MEDIUM')
    : 'SAFE';

  return {
    detected:   findings.length > 0,
    findings,
    count:      findings.length,
    risk_level,
  };
}
