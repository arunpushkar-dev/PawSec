"""Adapter for skills/pii-detector."""

import sys
import os

# Add skills path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'pii-detector', 'tools'))

from pii_detector import PIIDetector  # noqa: E402

_detector = PIIDetector()


def run(text: str) -> dict:
    """Run PII detection and return normalized result."""
    try:
        raw = _detector.detect_pii(text, mask=True, masking_strategy='smart')
        findings_summary = list({
            f.get('name', f.get('category', '')) for f in (raw.get('findings') or [])
            if f.get('category') != 'linked_identifier_set'
        })[:10]
        return {
            "detected": raw.get('has_pii', False),
            "count": raw.get('count', 0),
            "risk_level": raw.get('risk_level', 'SAFE'),
            "findings_summary": findings_summary,
            "masked_text": raw.get('masked_text', text),
            # Full findings kept for risk calculator
            "_raw": raw,
        }
    except Exception as e:
        return {"detected": False, "count": 0, "risk_level": "SAFE",
                "findings_summary": [], "masked_text": text, "_error": str(e)}
