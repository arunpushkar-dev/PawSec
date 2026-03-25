"""Adapter for skills/business-data-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'business-data-detector', 'tools'))

from business_data_detector import BusinessDataDetector  # noqa: E402

_detector = BusinessDataDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        findings_summary = [
            {"type": f.get("type", ""), "name": f.get("name", ""), "jurisdiction": f.get("jurisdiction", "")}
            for f in raw.get("findings", [])
        ]
        return {
            "detected": raw.get("detected", False),
            "count": raw.get("count", 0),
            "risk_level": raw.get("risk_level", "SAFE"),
            "findings_summary": findings_summary,
            "_raw": raw,
        }
    except Exception as e:
        return {"detected": False, "count": 0, "risk_level": "SAFE",
                "findings_summary": [], "_error": str(e)}
