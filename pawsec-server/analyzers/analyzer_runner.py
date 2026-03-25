"""
Orchestrates all skill adapters.
- 9 sync detectors run in parallel via asyncio.gather + run_in_executor
- LLM adapter runs concurrently (already has internal 10s timeout)
- Risk adapter runs last (needs all other results)
- Respects analyzers_requested list to skip disabled analyzers
"""

import asyncio
from concurrent.futures import ThreadPoolExecutor

from analyzers import (
    pii_adapter,
    phi_adapter,
    code_injection_adapter,
    api_secrets_adapter,
    credentials_adapter,
    private_url_adapter,
    business_data_adapter,
    financial_data_adapter,
    unknown_malicious_intent_adapter,
    llm_adapter,
    risk_adapter,
)

# Shared thread pool for sync skill adapters
_executor = ThreadPoolExecutor(max_workers=9, thread_name_prefix="pawsec-skill")

_SAFE_DEFAULTS: dict[str, dict] = {
    "pii":                      {"detected": False, "count": 0, "risk_level": "SAFE", "pii_found": []},
    "phi":                      {"detected": False, "count": 0, "risk_level": "SAFE", "phi_found": []},
    "code_injection":           {"threat_detected": False, "count": 0, "risk_level": "SAFE", "threats": []},
    "api_secrets":              {"threat_detected": False, "count": 0, "risk_level": "SAFE", "secrets_summary": []},
    "credentials":              {"detected": False, "count": 0, "risk_level": "SAFE", "findings_summary": []},
    "private_url":              {"detected": False, "count": 0, "risk_level": "SAFE", "urls_summary": []},
    "business_data":            {"detected": False, "count": 0, "risk_level": "SAFE", "findings": []},
    "financial_data":           {"detected": False, "count": 0, "risk_level": "SAFE", "findings": []},
    "unknown_malicious_intent": {"detected": False, "count": 0, "risk_level": "SAFE", "findings": []},
    "llm":                      {"available": False, "Intent_Category": None, "Generic_Persona_Category": None,
                                 "Pattern": None, "Intent_Risk_Severity": None, "Persona_Risk_Severity": None,
                                 "Pattern_Risk_Severity": None},
}


async def _run_sync(func, text: str):
    """Run a synchronous adapter function in the thread pool."""
    loop = asyncio.get_running_loop()
    return await loop.run_in_executor(_executor, func, text)


async def run_analysis(
    text: str,
    analyzers_requested: list[str] | None = None,
) -> dict:
    """
    Run all requested analyzers and return assembled results dict.

    Args:
        text: The (pre-masked) prompt text to analyze.
        analyzers_requested: List of analyzer names to run. None = run all.

    Returns:
        dict with keys: pii, phi, code_injection, api_secrets, credentials,
        private_url, business_data, financial_data, unknown_malicious_intent, llm, risk
    """
    requested = set(analyzers_requested) if analyzers_requested else {
        "pii", "phi", "code_injection", "api_secrets", "credentials",
        "private_url", "business_data", "financial_data",
        "unknown_malicious_intent", "llm", "risk"
    }

    # --- Phase 1: Run 9 sync detectors + LLM in parallel ---
    async def maybe_run(name: str, func):
        if name not in requested:
            return _SAFE_DEFAULTS[name].copy()
        try:
            return await _run_sync(func, text)
        except Exception as e:
            result = _SAFE_DEFAULTS[name].copy()
            result["_error"] = str(e)
            return result

    async def maybe_run_llm():
        if "llm" not in requested and "llm_classification" not in requested:
            return _SAFE_DEFAULTS["llm"].copy()
        try:
            return await _run_sync(llm_adapter.run, text)
        except Exception as e:
            result = _SAFE_DEFAULTS["llm"].copy()
            result["_error"] = str(e)
            return result

    (
        pii_result,
        phi_result,
        code_result,
        api_result,
        creds_result,
        url_result,
        biz_result,
        fin_result,
        umi_result,
        llm_result,
    ) = await asyncio.gather(
        maybe_run("pii",                      pii_adapter.run),
        maybe_run("phi",                      phi_adapter.run),
        maybe_run("code_injection",           code_injection_adapter.run),
        maybe_run("api_secrets",              api_secrets_adapter.run),
        maybe_run("credentials",              credentials_adapter.run),
        maybe_run("private_url",              private_url_adapter.run),
        maybe_run("business_data",            business_data_adapter.run),
        maybe_run("financial_data",           financial_data_adapter.run),
        maybe_run("unknown_malicious_intent", unknown_malicious_intent_adapter.run),
        maybe_run_llm(),
    )

    # --- Phase 2: Risk scoring (sequential, needs all other results) ---
    risk_result = {
        "total_score": 0, "effective_score": 0,
        "risk_level": "SAFE", "breakdown": {}, "recommendations": []
    }
    if "risk" in requested:
        try:
            risk_result = risk_adapter.run(
                pii=pii_result,
                phi=phi_result,
                code_injection=code_result,
                api_secrets=api_result,
                credentials=creds_result,
                private_url=url_result,
                business_data=biz_result,
                financial_data=fin_result,
                unknown_malicious_intent=umi_result,
                llm_classification=llm_result,
            )
        except Exception as e:
            risk_result = {
                "total_score": 0, "effective_score": 0,
                "risk_level": "SAFE", "breakdown": {}, "recommendations": [],
                "_error": str(e)
            }

    return {
        "pii":                      pii_result,
        "phi":                      phi_result,
        "code_injection":           code_result,
        "api_secrets":              api_result,
        "credentials":              creds_result,
        "private_url":              url_result,
        "business_data":            biz_result,
        "financial_data":           fin_result,
        "unknown_malicious_intent": umi_result,
        "llm_classification":       llm_result,
        "risk":                     risk_result,
    }
