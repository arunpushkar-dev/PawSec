"""Adapter for skills/api-secrets-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'api-secrets-detector', 'tools'))

from api_secrets_detector import APISecretsDetector  # noqa: E402

_detector = APISecretsDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        secrets_summary = [
            {"service": s.get("service", ""), "type": s.get("type", ""), "severity": s.get("severity", "")}
            for s in raw.get("secrets_found", [])
        ]
        return {
            "threat_detected": raw.get("threat_detected", False),
            "count": raw.get("count", 0),
            "risk_level": raw.get("risk_level", "SAFE"),
            "secrets_summary": secrets_summary,
            "_raw": raw,
        }
    except Exception as e:
        return {"threat_detected": False, "count": 0, "risk_level": "SAFE",
                "secrets_summary": [], "_error": str(e)}
