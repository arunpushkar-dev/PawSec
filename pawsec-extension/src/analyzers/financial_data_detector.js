/**
 * PawSec Financial Data Detector (browser port of financial_data_detector.py)
 *
 * Detects sensitive financial information: salary/compensation, P&L data,
 * revenue/EBITDA, payroll records, budget projections, and equity/option details.
 *
 * Uses a proximity-window approach: financial figures are only flagged when
 * found within 200 chars of financial context keywords.
 *
 * Returns:
 *   detected                  — true if any financial figures found in context
 *   findings                  — array of { type, name, severity, amount_hint, snippet, position }
 *   count                     — total findings
 *   distinct_financial_figures — total distinct amounts across all types
 *   risk_level                — SAFE / MEDIUM / HIGH / CRITICAL
 */

// ── Context window size (chars around each keyword match) ──────────────────
const WINDOW = 200;

// ── Currency / amount pattern ──────────────────────────────────────────────
const AMOUNT_RE = new RegExp(
  '(?:' +
  // Dollar/Pound/Euro symbol + number
  '[\\$£€¥]\\s*\\d{1,3}(?:[,.\\s]\\d{3})*(?:\\.\\d{1,2})?[KkMmBbTt]?' +
  '|' +
  // Number + currency code
  '\\d{1,3}(?:[,\\s]\\d{3})*(?:\\.\\d{1,2})?\\s*(?:USD|GBP|EUR|INR|AUD|CAD)' +
  '|' +
  // Spelled-out with K/M/B/T
  '\\d+(?:\\.\\d+)?\\s*[KkMmBbTt](?:\\s+(?:dollars?|pounds?|euros?|rupees?))?' +
  '|' +
  // Plain large number with commas (> 3 digits, context-required)
  '\\d{1,3}(?:,\\d{3}){1,4}(?:\\.\\d{1,2})?' +
  ')',
  'gi'
);

// ── Context groups (mirrors Python _load_context_groups) ──────────────────
const CONTEXT_GROUPS = [
  {
    type: 'salary_compensation',
    name: 'Salary / Compensation Figure',
    severity: 'HIGH',
    contextRe: /\b(?:salary|salaries|compensation|remuneration|total\s+comp|base\s+(?:salary|pay|compensation)|annual\s+(?:salary|pay|comp)|monthly\s+(?:salary|pay)|wage|wages|pay\s+(?:rate|grade|band)|ctc|cost\s+to\s+company|take[- ]?home|net\s+pay|gross\s+pay|earning(?:s)?|income|stipend)\b/gi,
  },
  {
    type: 'bonus_incentive',
    name: 'Bonus / Incentive Figure',
    severity: 'HIGH',
    contextRe: /\b(?:bonus|bonuses|incentive|commission|performance\s+pay|variable\s+pay|quarterly\s+bonus|annual\s+bonus|signing\s+bonus|retention\s+bonus|sti|lti)\b/gi,
  },
  {
    type: 'revenue_pl',
    name: 'Revenue / P&L Figure',
    severity: 'CRITICAL',
    contextRe: /\b(?:revenue|revenues|net\s+revenue|gross\s+revenue|total\s+revenue|annual\s+revenue|quarterly\s+revenue|profit|loss|net\s+(?:profit|loss|income)|gross\s+(?:profit|margin)|operating\s+(?:profit|loss|income)|ebitda|ebit|p[&/]l|profit\s+and\s+loss|income\s+statement|bottom\s+line|top\s+line|run\s+rate|arr|mrr|annual\s+recurring\s+revenue|monthly\s+recurring)\b/gi,
  },
  {
    type: 'payroll',
    name: 'Payroll Figure',
    severity: 'HIGH',
    contextRe: /\b(?:payroll|paycheque|paycheck|pay\s+stub|pay\s+slip|direct\s+deposit|payroll\s+(?:run|cycle|period|processing)|total\s+payroll|payroll\s+cost|employees\s+(?:paid|salary))\b/gi,
  },
  {
    type: 'budget_projection',
    name: 'Budget / Financial Projection',
    severity: 'HIGH',
    contextRe: /\b(?:budget|forecast|projection|financial\s+plan|capex|opex|operating\s+(?:budget|expense)|capital\s+(?:budget|expenditure)|q[1-4]\s+(?:target|forecast)|fy\s*\d{2,4}\s*(?:budget|forecast|target|plan)|five[- ]year\s+plan|three[- ]year\s+plan|financial\s+(?:target|goal|projection))\b/gi,
  },
  {
    type: 'equity_options',
    name: 'Equity / Stock Options Figure',
    severity: 'HIGH',
    contextRe: /\b(?:equity|options?|stock\s+options?|rsus?|restricted\s+stock\s+units?|vesting|cliff|grant|shares?\s+(?:outstanding|granted|vested|unvested)|option\s+(?:pool|strike\s+price|exercise\s+price)|cap\s+table|capitalization|valuation|series\s+[a-z]\s+(?:round|funding)|pre[- ]money|post[- ]money)\b/gi,
  },
  {
    type: 'funding_investment',
    name: 'Funding / Investment Figure',
    severity: 'HIGH',
    contextRe: /\b(?:funding|fundrais(?:e|ing)|investment|investor|venture\s+capital|private\s+equity|seed\s+(?:round|funding)|series\s+[a-z]\s+round|ipo|acquisition|merger|deal\s+value|enterprise\s+value|transaction\s+value|purchase\s+price)\b/gi,
  },
  {
    type: 'internal_finance_code',
    name: 'Internal Financial Code',
    severity: 'MEDIUM',
    contextRe: /\b(?:cost\s+cent(?:er|re)|gl\s+(?:code|account)|general\s+ledger|account\s+code|budget\s+code|wbs\s+(?:code|element)|profit\s+cent(?:er|re)|fund\s+code)\b/gi,
  },
];

// ── Amount hint (magnitude without exact value) ───────────────────────────
function _hintAmount(value) {
  const clean = value.replace(/[,\s]/g, '');
  const digits = clean.replace(/[^0-9.]/g, '');
  try {
    let num = parseFloat(digits);
    if (isNaN(num)) return 'amount';
    const suffixMatch = clean.match(/[KkMmBbTt]$/);
    if (suffixMatch) {
      const mult = { k: 1e3, m: 1e6, b: 1e9, t: 1e12 }[suffixMatch[0].toLowerCase()] || 1;
      num *= mult;
    }
    if (num >= 1e12) return `~${(num / 1e12).toFixed(1)}T`;
    if (num >= 1e9)  return `~${(num / 1e9).toFixed(1)}B`;
    if (num >= 1e6)  return `~${(num / 1e6).toFixed(1)}M`;
    if (num >= 1e3)  return `~${(num / 1e3).toFixed(1)}K`;
    return `~${num.toFixed(0)}`;
  } catch {
    return 'amount';
  }
}

/**
 * @param {string} text
 * @returns {{
 *   detected: boolean,
 *   findings: Array,
 *   count: number,
 *   distinct_financial_figures: number,
 *   risk_level: string
 * }}
 */
export function analyzeFinancialData(text) {
  const findings = [];
  const seenPositions = [];
  const distinctAmountsPerType = {};

  for (const group of CONTEXT_GROUPS) {
    group.contextRe.lastIndex = 0;
    const contextMatches = [...text.matchAll(group.contextRe)];
    if (!contextMatches.length) continue;

    for (const ctxMatch of contextMatches) {
      const ctxCenter   = ctxMatch.index;
      const windowStart = Math.max(0, ctxCenter - WINDOW);
      const windowEnd   = Math.min(text.length, ctxCenter + WINDOW);
      const windowText  = text.slice(windowStart, windowEnd);

      AMOUNT_RE.lastIndex = 0;
      const amounts = [...windowText.matchAll(AMOUNT_RE)];

      for (const amountMatch of amounts) {
        const absPos = windowStart + amountMatch.index;

        // Deduplication: skip if within 5 chars of an already-found position
        if (seenPositions.some(p => Math.abs(absPos - p) < 5)) continue;
        seenPositions.push(absPos);

        // Track distinct amounts per type for risk escalation
        distinctAmountsPerType[group.type] = (distinctAmountsPerType[group.type] || 0) + 1;

        const snipStart = Math.max(0, absPos - 30);
        const snipEnd   = Math.min(text.length, absPos + 60);
        const snippet   = text.slice(snipStart, snipEnd).replace(/\n/g, ' ');

        findings.push({
          type:         group.type,
          name:         group.name,
          severity:     group.severity,
          amount_hint:  _hintAmount(amountMatch[0]),
          snippet,
          position:     absPos,
        });
      }
    }
    group.contextRe.lastIndex = 0;
  }

  const totalDistinct = Object.values(distinctAmountsPerType).reduce((a, b) => a + b, 0);

  let risk_level = 'SAFE';
  if (findings.length) {
    const severities = findings.map(f => f.severity);
    if (severities.includes('CRITICAL') || totalDistinct >= 3) {
      risk_level = severities.includes('CRITICAL') ? 'CRITICAL' : 'HIGH';
    } else if (severities.includes('HIGH')) {
      risk_level = 'HIGH';
    } else {
      risk_level = 'MEDIUM';
    }
  }

  return {
    detected:                   findings.length > 0,
    findings,
    count:                      findings.length,
    distinct_financial_figures: totalDistinct,
    risk_level,
  };
}
