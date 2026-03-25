"""Adapter for skills/unknown-malicious-intent-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills',
                                'unknown-malicious-intent-detector', 'tools'))

from unknown_malicious_intent_detector import UnknownMaliciousIntentDetector  # noqa: E402

_detector = UnknownMaliciousIntentDetector()


def run(text: str) -> dict:
    """Run unknown malicious intent detection."""
    try:
        raw = _detector.analyze(text)
        return {
            "detected":   raw.get('detected', False),
            "count":      raw.get('count', 0),
            "risk_level": raw.get('risk_level', 'SAFE'),
            "findings":   raw.get('findings', []),
            "_raw":       raw,
        }
    except Exception as e:
        return {
            "detected": False, "count": 0, "risk_level": "SAFE",
            "findings": [], "_error": str(e),
        }
