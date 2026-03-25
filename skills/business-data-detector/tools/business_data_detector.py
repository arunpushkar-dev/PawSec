"""
Business Data Detector
Detects business entity identifiers: EIN (US), DUNS numbers, VAT numbers (EU),
ABN/ACN (Australia), UK company numbers, and Canada Business Numbers.

Scope: Organisation/entity-level identifiers only.
Individual identity documents (driver's licences, passports, etc.) are handled
by the pii-detector skill.
"""

import re
import json
from datetime import datetime
from typing import Dict, List


class BusinessDataDetector:
    """Detects business entity identifiers (EIN, DUNS, VAT, company numbers)."""

    def __init__(self):
        self._patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        return [
            # ── US Employer Identification Number (EIN) ───────────────────────────
            {
                "type": "ein",
                "name": "US Employer Identification Number (EIN)",
                "jurisdiction": "United States",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'(?:EIN|Employer\s+Identification\s+(?:Number|No\.?)|'
                    r'Federal\s+Tax\s+ID|FEIN)\s*[:\-#]?\s*'
                    r'(\b\d{2}-\d{7}\b)',
                    re.IGNORECASE
                ),
                "standalone": re.compile(r'\b(\d{2}-\d{7})\b')
            },
            # ── DUNS Number ──────────────────────────────────────────────────────
            {
                "type": "duns",
                "name": "DUNS Number (Dun & Bradstreet)",
                "jurisdiction": "International",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:DUNS|D[-&]U[-&]N[-&]S|Dun\s+&\s+Bradstreet)\s*(?:Number|No\.?|#)?\s*[:\-]?\s*'
                    r'(\b\d{2}-\d{3}-\d{4}\b|\b\d{9}\b)',
                    re.IGNORECASE
                )
            },
            # ── VAT Numbers (EU) ─────────────────────────────────────────────────
            {
                "type": "vat_eu",
                "name": "EU VAT Number",
                "jurisdiction": "European Union",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:VAT|Value\s+Added\s+Tax)\s*(?:Number|No\.?|#|ID|Registration)?\s*[:\-]?\s*'
                    r'('
                    r'AT\s*U\d{8}|'            # Austria
                    r'BE\s*0\d{9}|'            # Belgium
                    r'BG\s*\d{9,10}|'          # Bulgaria
                    r'CY\s*\d{8}[A-Z]|'        # Cyprus
                    r'CZ\s*\d{8,10}|'          # Czech Republic
                    r'DE\s*\d{9}|'             # Germany
                    r'DK\s*\d{8}|'             # Denmark
                    r'EE\s*\d{9}|'             # Estonia
                    r'EL\s*\d{9}|'             # Greece
                    r'ES\s*[A-Z0-9]\d{7}[A-Z0-9]|'  # Spain
                    r'FI\s*\d{8}|'             # Finland
                    r'FR\s*[A-HJ-NP-Z0-9]{2}\d{9}|'  # France
                    r'HR\s*\d{11}|'            # Croatia
                    r'HU\s*\d{8}|'             # Hungary
                    r'IE\s*\d{7}[A-Z]{1,2}|'  # Ireland
                    r'IT\s*\d{11}|'            # Italy
                    r'LT\s*(?:\d{9}|\d{12})|' # Lithuania
                    r'LU\s*\d{8}|'             # Luxembourg
                    r'LV\s*\d{11}|'            # Latvia
                    r'MT\s*\d{8}|'             # Malta
                    r'NL\s*\d{9}B\d{2}|'       # Netherlands
                    r'PL\s*\d{10}|'            # Poland
                    r'PT\s*\d{9}|'             # Portugal
                    r'RO\s*\d{2,10}|'          # Romania
                    r'SE\s*\d{12}|'            # Sweden
                    r'SI\s*\d{8}|'             # Slovenia
                    r'SK\s*\d{10}'             # Slovakia
                    r')',
                    re.IGNORECASE
                )
            },
            # ── UK Company Number ─────────────────────────────────────────────────
            {
                "type": "uk_company",
                "name": "UK Company Registration Number",
                "jurisdiction": "United Kingdom",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:Company\s+(?:Number|No\.?|Registration)|Companies\s+House|CRN)\s*[:\-]?\s*'
                    r'(\b(?:[A-Z]{2}|[A-Z])?\d{6,8}\b)',
                    re.IGNORECASE
                )
            },
            # ── Australian Business Number (ABN) ──────────────────────────────────
            {
                "type": "abn",
                "name": "Australian Business Number (ABN)",
                "jurisdiction": "Australia",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:ABN|Australian\s+Business\s+Number)\s*[:\-]?\s*'
                    r'(\b\d{2}\s?\d{3}\s?\d{3}\s?\d{3}\b)',
                    re.IGNORECASE
                )
            },
            # ── Australian Company Number (ACN) ───────────────────────────────────
            {
                "type": "acn",
                "name": "Australian Company Number (ACN)",
                "jurisdiction": "Australia",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:ACN|Australian\s+Company\s+Number)\s*[:\-]?\s*'
                    r'(\b\d{3}\s?\d{3}\s?\d{3}\b)',
                    re.IGNORECASE
                )
            },
            # ── Canadian Business Number ──────────────────────────────────────────
            {
                "type": "canada_bn",
                "name": "Canada Business Number (BN)",
                "jurisdiction": "Canada",
                "severity": "MEDIUM",
                "pattern": re.compile(
                    r'(?:BN|Business\s+Number|CRA\s+Number)\s*[:\-]?\s*'
                    r'(\b\d{9}\s?(?:RT|RP|RC|RZ)\s?\d{4}\b)',
                    re.IGNORECASE
                )
            },
        ]

    @staticmethod
    def _mask_value(value: str) -> str:
        if len(value) <= 4:
            return '*' * len(value)
        return value[:2] + '*' * (len(value) - 4) + value[-2:]

    def analyze(self, text: str) -> Dict:
        """Analyze text for business entity identifiers."""
        findings = []
        seen_positions = []

        for spec in self._patterns:
            for match in spec["pattern"].finditer(text):
                pos = match.start()
                if any(abs(pos - p) < 10 for p in seen_positions):
                    continue
                seen_positions.append(pos)

                value = match.group(1) if match.lastindex else match.group(0)
                findings.append({
                    "type": spec["type"],
                    "name": spec["name"],
                    "jurisdiction": spec["jurisdiction"],
                    "severity": spec["severity"],
                    "value_masked": self._mask_value(value),
                    "position": pos
                })

            # Also check standalone EIN pattern with context
            if spec["type"] == "ein" and "standalone" in spec:
                ein_context = re.compile(
                    r'(?:EIN|FEIN|Tax\s+ID|Employer\s+ID)',
                    re.IGNORECASE
                )
                for ctx_m in ein_context.finditer(text):
                    window_start = max(0, ctx_m.start() - 5)
                    window_end = min(len(text), ctx_m.end() + 30)
                    window = text[window_start:window_end]
                    for ein_m in spec["standalone"].finditer(window):
                        abs_pos = window_start + ein_m.start()
                        if any(abs(abs_pos - p) < 10 for p in seen_positions):
                            continue
                        seen_positions.append(abs_pos)
                        findings.append({
                            "type": "ein",
                            "name": "US Employer Identification Number (EIN)",
                            "jurisdiction": "United States",
                            "severity": "HIGH",
                            "value_masked": self._mask_value(ein_m.group(1)),
                            "position": abs_pos
                        })

        # Risk level
        if findings:
            severities = [f["severity"] for f in findings]
            if "CRITICAL" in severities:
                risk_level = "CRITICAL"
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
            "risk_level": risk_level,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        return [self.analyze(t) for t in texts]


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    detector = BusinessDataDetector()

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
