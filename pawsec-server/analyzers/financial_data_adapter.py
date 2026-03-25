"""Adapter for skills/financial-data-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'financial-data-detector', 'tools'))

from financial_data_detector import FinancialDataDetector  # noqa: E402

_detector = FinancialDataDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        findings_summary = [
            {"type": f.get("type", ""), "name": f.get("name", ""), "amount_hint": f.get("amount_hint", "")}
            for f in raw.get("findings", [])
        ]
        return {
            "detected": raw.get("detected", False),
            "count": raw.get("count", 0),
            "risk_level": raw.get("risk_level", "SAFE"),
            "distinct_financial_figures": raw.get("distinct_financial_figures", 0),
            "findings_summary": findings_summary,
            "_raw": raw,
        }
    except Exception as e:
        return {"detected": False, "count": 0, "risk_level": "SAFE",
                "distinct_financial_figures": 0, "findings_summary": [], "_error": str(e)}
