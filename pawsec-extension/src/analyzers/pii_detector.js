/**
 * PawSec in-browser PII detector — Layer 1 (fast regex) + Layer 3 (DL context).
 * Mirrors the Python pii-detector skill for offline use.
 *
 * Layer 1: Strong-pattern regex for common PII (email, phone, SSN, etc.)
 * Layer 3: Driver's licence detection — all 50 US states, context-gated
 */

const PII_PATTERNS = [
  // Email
  { name: 'email',       risk: 'MEDIUM', re: /\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b/g },
  // India mobile (must run before phone_us to avoid +91 numbers being consumed as US phones)
  { name: 'phone_india', risk: 'MEDIUM', re: /\b(?:\+91[\s\-]?)?[6-9]\d{9}\b/g },
  // US Phone
  { name: 'phone_us',    risk: 'MEDIUM', re: /\b(\+1[-.\s]?)?(\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4})\b/g },
  // International phone (leading +country code)
  { name: 'phone_intl',  risk: 'MEDIUM', re: /\+(?!1\b)[1-9]\d{6,14}\b/g },
  // US SSN
  { name: 'ssn',         risk: 'HIGH',   re: /\b(?!000|666|9\d{2})\d{3}[-\s](?!00)\d{2}[-\s](?!0000)\d{4}\b/g },
  // Credit card (Luhn-like 4×4 groups or 16-digit)
  { name: 'credit_card', risk: 'HIGH',   re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5]\d{14}|3[47]\d{13}|6(?:011|5\d{2})\d{12}|(?:\d{4}[-\s]){3}\d{4})\b/g },
  // IBAN
  { name: 'iban',        risk: 'HIGH',   re: /\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b/g },
  // IPv4 (skip RFC-1918 — handled by private_url_detector)
  { name: 'ipv4',        risk: 'LOW',    re: /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g },
  // MAC address
  { name: 'mac',         risk: 'LOW',    re: /\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b/g },
  // Passport (US-style + generic)
  { name: 'passport',    risk: 'HIGH',   re: /\b[A-Z]{1,2}\d{6,9}\b/g },
  // Aadhaar (India)
  { name: 'aadhaar',     risk: 'HIGH',   re: /\b[2-9]\d{3}[\s-]?\d{4}[\s-]?\d{4}\b/g },
  // India PAN
  { name: 'pan_india',   risk: 'HIGH',   re: /\b[A-Z]{5}\d{4}[A-Z]\b/g },
  // GPS coordinates
  { name: 'gps',         risk: 'MEDIUM', re: /[-+]?(?:[1-8]?\d(?:\.\d+)?|90(?:\.0+)?),\s*[-+]?(?:180(?:\.0+)?|(?:1[0-7]\d|\d{1,2})(?:\.\d+)?)/g },
  // US bank routing number
  { name: 'bank_routing',risk: 'HIGH',   re: /\b0[0-9]{2}[0-9]{6}[0-9]\b/g },
  // IPv6 address
  { name: 'ipv6',        risk: 'LOW',    re: /\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,7}:\b|\b::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}\b/g },
  // IMEI / 15-digit device serial (context-gated via surrounding text is handled in layer2, but standalone 15-digit is detected here)
  { name: 'imei',        risk: 'MEDIUM', re: /\b\d{15}\b/g },
  // Medical Record Number (labeled)
  { name: 'mrn',         risk: 'HIGH',   re: /\b(?:MRN|Medical\s+Record)\s*[:#]?\s*[A-Z]?\d{5,10}\b/gi },
  // Date of birth (labeled keyword + date)
  { name: 'dob',         risk: 'MEDIUM', re: /\b(?:dob|date\s+of\s+birth|birth\s+date|birthdate|d\.o\.b\.?)\s*[:\-]?\s*(\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}\s+(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*\s+\d{2,4})/gi },
  // Street address (number + street suffix)
  { name: 'street_address', risk: 'MEDIUM', re: /\b\d{1,5}\s+[\w\s]{1,30}\s+(?:street|st|avenue|ave|road|rd|boulevard|blvd|lane|ln|drive|dr|court|ct|sector|block|nagar|marg|vihar)\b/gi },
];

const MASK_CHAR = '█';

// ── Layer 3: Driver's licence (all 50 US states, context-gated) ───────────
const DL_CONTEXT_RE = /(?:driver'?s?\s+licen[sc]e|driving\s+licen[sc]e|DLN?|licen[sc]e\s+(?:number|no\.?|#|id)|state\s+id|photo\s+id|government\s+id)/gi;
const DL_WINDOW = 150;

const DL_PATTERNS = [
  { states: ['Alabama'],        re: /\b(\d{7,8})\b/g },
  { states: ['Alaska'],         re: /\b(\d{7})\b/g },
  { states: ['Arizona'],        re: /\b([A-Z]\d{8,9}|\d{9})\b/g },
  { states: ['Arkansas'],       re: /\b(\d{4,9})\b/g },
  { states: ['California'],     re: /\b([A-Z]\d{7})\b/g },
  { states: ['Colorado'],       re: /\b(\d{9}|[A-Z]\d{3}[A-Z]\d{3}|[A-Z]\d{8})\b/g },
  { states: ['Connecticut'],    re: /\b(\d{9})\b/g },
  { states: ['Delaware'],       re: /\b(\d{1,7})\b/g },
  { states: ['Florida'],        re: /\b([A-Z]\d{12})\b/g },
  { states: ['Georgia'],        re: /\b(\d{7,9})\b/g },
  { states: ['Hawaii'],         re: /\b(H\d{8}|\d{9})\b/g },
  { states: ['Idaho'],          re: /\b([A-Z]{2}\d{6}[A-Z]|\d{9})\b/g },
  { states: ['Illinois'],       re: /\b([A-Z]\d{11,12})\b/g },
  { states: ['Indiana'],        re: /\b(\d{10}|[A-Z]\d{9})\b/g },
  { states: ['Iowa'],           re: /\b(\d{9}|\d{3}[A-Z]{2}\d{4})\b/g },
  { states: ['Kansas'],         re: /\b([A-Z]\d{8,9}|\d{9})\b/g },
  { states: ['Kentucky'],       re: /\b([A-Z]\d{8,9}|\d{9})\b/g },
  { states: ['Louisiana'],      re: /\b(\d{9})\b/g },
  { states: ['Maine'],          re: /\b(\d{7,8}|[A-Z]\d{8})\b/g },
  { states: ['Maryland'],       re: /\b([A-Z]\d{12})\b/g },
  { states: ['Massachusetts'],  re: /\b(S\d{8}|\d{9})\b/g },
  { states: ['Michigan'],       re: /\b([A-Z]\d{10})\b/g },
  { states: ['Minnesota'],      re: /\b([A-Z]\d{12})\b/g },
  { states: ['Mississippi'],    re: /\b(\d{9})\b/g },
  { states: ['Missouri'],       re: /\b([A-Z]\d{5,9}|\d{9}|[A-Z]\d{6}R)\b/g },
  { states: ['Montana'],        re: /\b(\d{13}|[A-Z]{3}\d{10}|[A-Z0-9]{9})\b/g },
  { states: ['Nebraska'],       re: /\b([A-Z]\d{6,8})\b/g },
  { states: ['Nevada'],         re: /\b(\d{9,10}|X\d{8})\b/g },
  { states: ['New Hampshire'],  re: /\b(\d{2}[A-Z]{3}\d{5})\b/g },
  { states: ['New Jersey'],     re: /\b([A-Z]\d{14})\b/g },
  { states: ['New Mexico'],     re: /\b(\d{8,9})\b/g },
  { states: ['New York'],       re: /\b(\d{9}|[A-Z]\d{18}|[A-Z]{8}\d)\b/g },
  { states: ['North Carolina'], re: /\b(\d{1,12})\b/g },
  { states: ['North Dakota'],   re: /\b([A-Z]{3}\d{6}|\d{9})\b/g },
  { states: ['Ohio'],           re: /\b([A-Z]{2}\d{6}|\d{8})\b/g },
  { states: ['Oklahoma'],       re: /\b([A-Z]\d{9}|\d{9})\b/g },
  { states: ['Oregon'],         re: /\b(\d{1,9}|[A-Z]\d{6})\b/g },
  { states: ['Pennsylvania'],   re: /\b(\d{8})\b/g },
  { states: ['Rhode Island'],   re: /\b(\d{7}|V\d{6})\b/g },
  { states: ['South Carolina'], re: /\b(\d{5,11})\b/g },
  { states: ['South Dakota'],   re: /\b(\d{6,10}|[A-Z]{2}\d{6,8})\b/g },
  { states: ['Tennessee'],      re: /\b(\d{7,9})\b/g },
  { states: ['Texas'],          re: /\b(\d{8})\b/g },
  { states: ['Utah'],           re: /\b(\d{4,10})\b/g },
  { states: ['Vermont'],        re: /\b(\d{8}[A-Z])\b/g },
  { states: ['Virginia'],       re: /\b([A-Z]\d{8,11}|\d{9})\b/g },
  { states: ['Washington'],     re: /\b([A-Z]{3}[A-Z*]{2}\d{3}[A-Z0-9]{2})\b/g },
  { states: ['West Virginia'],  re: /\b([A-Z0-9]\d{6})\b/g },
  { states: ['Wisconsin'],      re: /\b([A-Z]\d{13})\b/g },
  { states: ['Wyoming'],        re: /\b(\d{9,10})\b/g },
];

function _detectDriverLicenses(text) {
  const findings = [];
  const seenPositions = [];

  DL_CONTEXT_RE.lastIndex = 0;
  const contextMatches = [...text.matchAll(DL_CONTEXT_RE)];
  if (!contextMatches.length) return findings;

  for (const ctxMatch of contextMatches) {
    const windowStart = Math.max(0, ctxMatch.index - DL_WINDOW);
    const windowEnd   = Math.min(text.length, ctxMatch.index + DL_WINDOW);
    const window      = text.slice(windowStart, windowEnd);

    for (const spec of DL_PATTERNS) {
      spec.re.lastIndex = 0;
      for (const m of window.matchAll(spec.re)) {
        const absPos = windowStart + m.index;
        if (seenPositions.some(p => Math.abs(absPos - p) < 8)) continue;
        seenPositions.push(absPos);
        const value = m[1] ?? m[0];
        findings.push({
          type:  'driver_license',
          risk:  'HIGH',
          value_masked: maskValue(value),
          name:  `Driver's Licence — ${spec.states.join(', ')} format`,
        });
      }
    }
  }
  return findings;
}

/**
 * Mask matched value leaving first 2 and last 2 chars visible (min 4 chars).
 * @param {string} val
 * @returns {string}
 */
export function maskValue(val) {
  if (val.length <= 4) return MASK_CHAR.repeat(val.length);
  return val.slice(0, 2) + MASK_CHAR.repeat(val.length - 4) + val.slice(-2);
}

/**
 * Mask all PII in text and return masked text + findings.
 * @param {string} text
 * @returns {{ masked: string, findings: Array, count: number, detected: boolean, risk_level: string }}
 */
export function analyzePII(text) {
  const findings = [];
  let masked = text;

  for (const { name, risk, re } of PII_PATTERNS) {
    re.lastIndex = 0;
    const matches = [...masked.matchAll(re)];
    for (const m of matches) {
      findings.push({ type: name, risk, value_masked: maskValue(m[0]) });
    }
    if (matches.length) {
      masked = masked.replace(re, (m) => `[${name.toUpperCase()}:${maskValue(m)}]`);
    }
    re.lastIndex = 0;
  }

  // Layer 3: driver's licence (context-gated, all 50 US states)
  findings.push(..._detectDriverLicenses(text));

  const riskOrder = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
  const maxRisk = findings.reduce((acc, f) => {
    return (riskOrder[f.risk] ?? 0) > (riskOrder[acc] ?? 0) ? f.risk : acc;
  }, 'SAFE');

  // Count-based escalation: 2+ PII findings elevate risk to at least HIGH
  let risk_level = maxRisk;
  if (findings.length >= 2 && riskOrder[risk_level] < riskOrder['HIGH']) {
    risk_level = 'HIGH';
  }

  return {
    detected:   findings.length > 0,
    count:      findings.length,
    findings,
    masked_text: masked,
    risk_level,
  };
}
