"""Adapter for skills/code-injection-detector."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'code-injection-detector', 'tools'))

from code_injection_detector import CodeInjectionDetector  # noqa: E402

_detector = CodeInjectionDetector()


def run(text: str) -> dict:
    try:
        raw = _detector.analyze(text)
        return {
            "threat_detected": raw.get('threat_detected', False),
            "code_types": raw.get('code_types', []),
            "threat_count": raw.get('threat_count', 0),
            "_raw": raw,
        }
    except Exception as e:
        return {"threat_detected": False, "code_types": [], "threat_count": 0, "_error": str(e)}
