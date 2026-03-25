"""Adapter for skills/phi-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'phi-detector', 'tools'))

from phi_detector import PHIDetector  # noqa: E402

_detector = PHIDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.detect(text)
        categories = raw.get('categories_detected', [])
        return {
            "detected": raw.get('count', 0) > 0,
            "count": raw.get('count', 0),
            "has_critical": raw.get('has_critical', False),
            "has_high": raw.get('has_high', False),
            "categories_detected": categories,
            "summary": raw.get('summary', ''),
            "_raw": raw,
        }
    except Exception as e:
        return {"detected": False, "count": 0, "has_critical": False,
                "has_high": False, "categories_detected": [], "_error": str(e)}
