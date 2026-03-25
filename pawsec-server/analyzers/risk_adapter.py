"""Adapter for skills/risk-score-calculator (11-input v2 mode)."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'skills', 'risk-score-calculator', 'tools'))

from risk_calculator import RiskCalculator  # noqa: E402

_calculator = RiskCalculator()


def run(
    pii: dict = None,
    phi: dict = None,
    code_injection: dict = None,
    api_secrets: dict = None,
    credentials: dict = None,
    private_url: dict = None,
    business_data: dict = None,
    financial_data: dict = None,
    unknown_malicious_intent: dict = None,
    llm_classification: dict = None,
) -> dict:
    """Run risk calculation with all available skill outputs."""
    try:
        # Pass raw detector outputs for accurate PII scoring
        pii_for_risk = (pii or {}).get("_raw") or pii or {}
        phi_for_risk = (phi or {}).get("_raw") or phi or {}
        code_for_risk = (code_injection or {}).get("_raw") or code_injection or {}

        result = _calculator.calculate_risk(
            pii=pii_for_risk,
            phi=phi_for_risk,
            code_injection=code_for_risk,
            api_secrets=api_secrets,
            credentials=credentials,
            private_url=private_url,
            business_data=business_data,
            financial_data=financial_data,
            unknown_malicious_intent=unknown_malicious_intent,
            llm_classification=llm_classification,
        )
        return result
    except Exception as e:
        return {
            "total_score": 0, "effective_score": 0,
            "risk_level": "SAFE", "breakdown": {}, "recommendations": [],
            "_error": str(e)
        }
