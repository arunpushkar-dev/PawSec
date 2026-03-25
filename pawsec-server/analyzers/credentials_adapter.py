"""Adapter for skills/credentials-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'credentials-detector', 'tools'))

from credentials_detector import CredentialsDetector  # noqa: E402

_detector = CredentialsDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        findings_summary = [
            {"type": f.get("type", ""), "name": f.get("name", ""), "severity": f.get("severity", "")}
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
