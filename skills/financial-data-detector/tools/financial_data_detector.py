"""
Financial Data Detector
Detects sensitive financial information: salary/compensation figures, P&L data,
revenue/EBITDA, payroll records, budget projections, and equity/option details.
Uses proximity-window approach: financial figures are only flagged when within
range of financial context keywords.
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Tuple


class FinancialDataDetector:
    """Detects sensitive financial data in text using context-aware detection."""

    # Window size (chars on each side of a context keyword)
    _WINDOW = 200

    def __init__(self):
        self._context_groups = self._load_context_groups()
        self._amount_pattern = self._build_amount_pattern()

    def _build_amount_pattern(self) -> re.Pattern:
        """Match currency amounts in various formats."""
        return re.compile(
            r'(?:'
            # Dollar/Pound/Euro symbol + number
            r'[\$£€¥]\s*\d{1,3}(?:[,.\s]\d{3})*(?:\.\d{1,2})?[KkMmBbTt]?'
            r'|'
            # Number + currency code
            r'\d{1,3}(?:[,\s]\d{3})*(?:\.\d{1,2})?\s*(?:USD|GBP|EUR|INR|AUD|CAD)'
            r'|'
            # Spelled-out with K/M/B/T
            r'\d+(?:\.\d+)?\s*[KkMmBbTt](?:\s+(?:dollars?|pounds?|euros?|rupees?))?'
            r'|'
            # Plain large number with commas (> 3 digits, context-required)
            r'\d{1,3}(?:,\d{3}){1,4}(?:\.\d{1,2})?'
            r')',
            re.IGNORECASE
        )

    def _load_context_groups(self) -> List[Dict]:
        return [
            # ── Salary / Compensation ─────────────────────────────────────────────
            {
                "type": "salary_compensation",
                "name": "Salary / Compensation Figure",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:salary|salaries|compensation|remuneration|total\s+comp|'
                    r'base\s+(?:salary|pay|compensation)|annual\s+(?:salary|pay|comp)|'
                    r'monthly\s+(?:salary|pay)|wage|wages|pay\s+(?:rate|grade|band)|'
                    r'ctc|cost\s+to\s+company|take[- ]?home|net\s+pay|gross\s+pay|'
                    r'earning(?:s)?|income|stipend)\b',
                    re.IGNORECASE
                )
            },
            # ── Bonus / Incentives ────────────────────────────────────────────────
            {
                "type": "bonus_incentive",
                "name": "Bonus / Incentive Figure",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:bonus|bonuses|incentive|commission|performance\s+pay|'
                    r'variable\s+pay|quarterly\s+bonus|annual\s+bonus|'
                    r'signing\s+bonus|retention\s+bonus|sti|lti)\b',
                    re.IGNORECASE
                )
            },
            # ── Revenue / P&L ────────────────────────────────────────────────────
            {
                "type": "revenue_pl",
                "name": "Revenue / P&L Figure",
                "severity": "CRITICAL",
                "context_pattern": re.compile(
                    r'\b(?:revenue|revenues|net\s+revenue|gross\s+revenue|'
                    r'total\s+revenue|annual\s+revenue|quarterly\s+revenue|'
                    r'profit|loss|net\s+(?:profit|loss|income)|gross\s+(?:profit|margin)|'
                    r'operating\s+(?:profit|loss|income)|ebitda|ebit|'
                    r'p[&/]l|profit\s+and\s+loss|income\s+statement|'
                    r'bottom\s+line|top\s+line|run\s+rate|arr|mrr|'
                    r'annual\s+recurring\s+revenue|monthly\s+recurring)\b',
                    re.IGNORECASE
                )
            },
            # ── Payroll ──────────────────────────────────────────────────────────
            {
                "type": "payroll",
                "name": "Payroll Figure",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:payroll|paycheque|paycheck|pay\s+stub|pay\s+slip|'
                    r'direct\s+deposit|payroll\s+(?:run|cycle|period|processing)|'
                    r'total\s+payroll|payroll\s+cost|employees\s+(?:paid|salary))\b',
                    re.IGNORECASE
                )
            },
            # ── Budget / Financial Projections ────────────────────────────────────
            {
                "type": "budget_projection",
                "name": "Budget / Financial Projection",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:budget|forecast|projection|financial\s+plan|'
                    r'capex|opex|operating\s+(?:budget|expense)|'
                    r'capital\s+(?:budget|expenditure)|q[1-4]\s+(?:target|forecast)|'
                    r'fy\s*\d{2,4}\s*(?:budget|forecast|target|plan)|'
                    r'five[- ]year\s+plan|three[- ]year\s+plan|'
                    r'financial\s+(?:target|goal|projection))\b',
                    re.IGNORECASE
                )
            },
            # ── Equity / Options ─────────────────────────────────────────────────
            {
                "type": "equity_options",
                "name": "Equity / Stock Options Figure",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:equity|options?|stock\s+options?|rsus?|'
                    r'restricted\s+stock\s+units?|vesting|cliff|grant|'
                    r'shares?\s+(?:outstanding|granted|vested|unvested)|'
                    r'option\s+(?:pool|strike\s+price|exercise\s+price)|'
                    r'cap\s+table|capitalization|valuation|'
                    r'series\s+[a-z]\s+(?:round|funding)|pre[- ]money|post[- ]money)\b',
                    re.IGNORECASE
                )
            },
            # ── Funding / Investment ──────────────────────────────────────────────
            {
                "type": "funding_investment",
                "name": "Funding / Investment Figure",
                "severity": "HIGH",
                "context_pattern": re.compile(
                    r'\b(?:funding|fundrais(?:e|ing)|investment|investor|'
                    r'venture\s+capital|private\s+equity|seed\s+(?:round|funding)|'
                    r'series\s+[a-z]\s+round|ipo|acquisition|merger|deal\s+value|'
                    r'enterprise\s+value|transaction\s+value|purchase\s+price)\b',
                    re.IGNORECASE
                )
            },
            # ── Internal Financial Codes ──────────────────────────────────────────
            {
                "type": "internal_finance_code",
                "name": "Internal Financial Code",
                "severity": "MEDIUM",
                "context_pattern": re.compile(
                    r'\b(?:cost\s+center|cost\s+centre|gl\s+(?:code|account)|'
                    r'general\s+ledger|account\s+code|budget\s+code|'
                    r'wbs\s+(?:code|element)|profit\s+center|fund\s+code)\b',
                    re.IGNORECASE
                )
            },
        ]

    @staticmethod
    def _hint_amount(value: str) -> str:
        """Create a hint showing magnitude without the exact value."""
        clean = re.sub(r'[,\s]', '', value)
        digits = re.sub(r'[^0-9.]', '', clean)
        try:
            num = float(digits)
            suffix = re.search(r'[KkMmBbTt]$', clean)
            if suffix:
                mult = {'k': 1e3, 'm': 1e6, 'b': 1e9, 't': 1e12}.get(
                    suffix.group(0).lower(), 1
                )
                num *= mult
            if num >= 1e12:
                return f"~{num/1e12:.1f}T"
            elif num >= 1e9:
                return f"~{num/1e9:.1f}B"
            elif num >= 1e6:
                return f"~{num/1e6:.1f}M"
            elif num >= 1e3:
                return f"~{num/1e3:.1f}K"
            else:
                return f"~{num:.0f}"
        except (ValueError, TypeError):
            return "amount"

    def analyze(self, text: str) -> Dict:
        """Analyze text for sensitive financial figures."""
        findings = []
        seen_positions = []
        distinct_amounts_per_type = {}

        for group in self._context_groups:
            context_matches = list(group["context_pattern"].finditer(text))
            if not context_matches:
                continue

            for ctx_match in context_matches:
                ctx_center = ctx_match.start()
                window_start = max(0, ctx_center - self._WINDOW)
                window_end = min(len(text), ctx_center + self._WINDOW)
                window_text = text[window_start:window_end]

                amounts = list(self._amount_pattern.finditer(window_text))
                for amount_match in amounts:
                    abs_pos = window_start + amount_match.start()

                    if any(abs(abs_pos - p) < 5 for p in seen_positions):
                        continue
                    seen_positions.append(abs_pos)

                    # Track distinct amounts per type for risk escalation
                    t = group["type"]
                    if t not in distinct_amounts_per_type:
                        distinct_amounts_per_type[t] = 0
                    distinct_amounts_per_type[t] += 1

                    ctx_start_snip = max(0, abs_pos - 30)
                    ctx_end_snip = min(len(text), abs_pos + 60)
                    snippet = text[ctx_start_snip:ctx_end_snip].replace('\n', ' ')

                    findings.append({
                        "type": group["type"],
                        "name": group["name"],
                        "severity": group["severity"],
                        "amount_hint": self._hint_amount(amount_match.group(0)),
                        "snippet": snippet,
                        "position": abs_pos
                    })

        # Risk escalation: 3+ distinct financial figures = HIGH minimum
        total_distinct = sum(distinct_amounts_per_type.values())

        if findings:
            severities = [f["severity"] for f in findings]
            if "CRITICAL" in severities or total_distinct >= 3:
                risk_level = "CRITICAL" if "CRITICAL" in severities else "HIGH"
            elif "HIGH" in severities:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
        else:
            risk_level = "SAFE"

        return {
            "detected": len(findings) > 0,
            "findings": findings,
            "count": len(findings),
            "distinct_financial_figures": total_distinct,
            "risk_level": risk_level,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        return [self.analyze(t) for t in texts]


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    detector = FinancialDataDetector()

    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        print("Enter text to analyze (Ctrl+D/Ctrl+Z to end):")
        try:
            text = sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(0)

    result = detector.analyze(text)
    print(json.dumps(result, indent=2))
