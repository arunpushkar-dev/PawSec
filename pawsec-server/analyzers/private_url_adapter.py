"""Adapter for skills/private-url-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'private-url-detector', 'tools'))

from private_url_detector import PrivateURLDetector  # noqa: E402

_detector = PrivateURLDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        urls_summary = [
            {"type": u.get("type", ""), "name": u.get("name", ""), "risk": u.get("risk", "")}
            for u in raw.get("urls_found", [])
        ]
        return {
            "detected": raw.get("detected", False),
            "count": raw.get("count", 0),
            "risk_level": raw.get("risk_level", "SAFE"),
            "urls_summary": urls_summary,
            "_raw": raw,
        }
    except Exception as e:
        return {"detected": False, "count": 0, "risk_level": "SAFE",
                "urls_summary": [], "_error": str(e)}
