#!/usr/bin/env python3
"""
Risk Score Calculator - Weighted Multi-Factor Risk Assessment

Calculates risk scores using weighted contributions from multiple security analyzers.

Default weights (v2 — 10-input full pipeline):
  Code Injection (15%), PII (12%), PHI (12%), API Secrets (15%),
  Credentials (15%), Private URL (8%), Business Data (8%),
  Financial Data (8%), LLM Classification (7%)  = 100%

Legacy v1 weights (5-input):
  Injection (20%), Code Injection (20%), Llama Guard (25%),
  Context (20%), PII (15%) = 100%
"""

from typing import Dict, List, Any, Optional

# 40-category persona taxonomy — maps lowercase category name → risk level.
# Source: Persona.md (PawSec generic persona classification scheme).
_PERSONA_RISK_MAP: Dict[str, str] = {
    # ── CRITICAL ──────────────────────────────────────────────────────────
    'unrestricted assistant':         'critical',
    'override authority':             'critical',
    'debug/development mode':         'critical',
    'hidden/concealed entity':        'critical',
    'dual/split personality':         'critical',
    'instruction processor':          'critical',
    'privileged user':                'critical',
    'obfuscated/encoded decoder':     'critical',
    'multi-modal processor':          'critical',
    'external tool interface':        'critical',
    'refusal suppression system':     'critical',
    'priority escalation handler':    'critical',
    'information extraction specialist': 'critical',
    'container/sandbox escape':       'critical',
    'supply chain component':         'critical',
    'firmware/hardware interface':    'critical',
    'network/communication channel':  'critical',
    'database/storage manager':       'critical',
    'authentication/identity verifier': 'critical',
    # ── HIGH ──────────────────────────────────────────────────────────────
    'emergency/crisis responder':     'high',
    'testing/validation mode':        'high',
    'memory/context manager':         'high',
    'social engineer':                'high',
    'chain-of-thought manipulator':   'high',
    'policy/rule interpreter':        'high',
    'audit/compliance reporter':      'high',
    # ── MEDIUM ────────────────────────────────────────────────────────────
    'historical/fictional entity':    'medium',
    'meta/abstract concept':          'medium',
    'educational/research mode':      'medium',
    'simulation/game entity':         'medium',
    'translation/encoding bridge':    'medium',
    'narrative/story container':      'medium',
    'hypothetical scenario generator': 'medium',
    'temporal/time-based entity':     'medium',
    'comparative/evaluative judge':   'medium',
    # ── LOW ───────────────────────────────────────────────────────────────
    'help/assistance provider':       'low',
    'creative/content generator':     'low',
    'analytical/processing engine':   'low',
    'information/query resolver':     'low',
    'neutral/default state':          'low',
}


# 60-pattern injection taxonomy — maps lowercase pattern name → risk level.
# Source: Injection_Patterns.md (PawSec injection pattern classification scheme).
_PATTERN_RISK_MAP: Dict[str, str] = {
    # ── CRITICAL ──────────────────────────────────────────────────────────
    'direct instruction override':    'critical',
    'system reset commands':          'critical',
    'priority escalation':            'critical',
    'dan mode activation':            'critical',
    'hypothetical framing':           'critical',
    'fictional universe':             'critical',
    'developer mode':                 'critical',
    'emergency protocol':             'critical',
    'role manipulation':              'critical',
    'authority impersonation':        'critical',
    'persona adoption':               'critical',
    'mirror/clone simulation':        'critical',
    'ethical bypass':                 'critical',
    'base64 encoded payload':         'critical',
    'unicode smuggling':              'critical',
    'zero-width character injection': 'critical',
    'homoglyph attack':               'critical',
    'multi-modal image payload':      'critical',
    'audio embedded commands':        'critical',
    'refusal suppression':            'critical',
    'policy puppetry':                'critical',
    'gradient attack optimized':      'critical',
    'best-of-n jailbreak':            'critical',
    # ── HIGH ──────────────────────────────────────────────────────────────
    'moral reframing':                'high',
    'necessity argument':             'high',
    'consent fabrication':            'high',
    'system prompt leak':             'high',
    'training data extraction':       'high',
    'memory disclosure':              'high',
    'payload smuggling':              'high',
    'token smuggling':                'high',
    'translation bypass':             'high',
    'indirection techniques':         'high',
    'code execution framing':         'high',
    'rag poisoning':                  'high',
    'document injection':             'high',
    'markdown hidden text':           'high',
    'comment injection':              'high',
    'pdf metadata injection':         'high',
    'email header injection':         'high',
    'template injection':             'high',
    'prompt chaining':                'high',
    'affirmative prefix injection':   'high',
    'crescendo attack':               'high',
    'deceptive delight':              'high',
    'multi-turn persistence':         'high',
    # ── MEDIUM ────────────────────────────────────────────────────────────
    'configuration probing':          'medium',
    'context injection':              'medium',
    'delimiter confusion':            'medium',
    'recursive injection':            'medium',
    'emotional manipulation':         'medium',
    'false dilemma':                  'medium',
    'appeal to authority':            'medium',
    'urgency exploitation':           'medium',
    'search manipulation':            'medium',
    'gradual escalation':             'medium',
    'conversation reset':             'medium',
    'memory anchoring':               'medium',
    'contradiction exploitation':     'medium',
    'chain-of-thought manipulation':  'medium',
    # ── NONE ──────────────────────────────────────────────────────────────
    'normal':                         'low',
}

_RISK_ORDER = ['low', 'medium', 'high', 'critical']


class RiskCalculator:
    """Calculates weighted risk scores from security analysis results."""

    def __init__(self):
        """Initialize calculator with default v2 (10-input) weights."""
        # v2 weights — full 11-skill PawSec pipeline
        self.default_weights = {
            'unknown_malicious_intent': 16,
            'code_injection': 12,
            'pii': 12,
            'phi': 10,
            'api_secrets': 12,
            'credentials': 12,
            'private_url': 8,
            'business_data': 6,
            'financial_data': 6,
            'llm_classification': 6,
        }
        # v1 legacy weights — original 5-input pipeline
        self.legacy_weights = {
            'injection': 20,
            'code_injection': 20,
            'llama_guard': 25,
            'context': 20,
            'pii': 15,
        }

    def calculate_risk(
        self,
        # ── v2 inputs (new full pipeline) ────────────────────────────────────
        phi: Optional[Dict[str, Any]] = None,
        api_secrets: Optional[Dict[str, Any]] = None,
        credentials: Optional[Dict[str, Any]] = None,
        private_url: Optional[Dict[str, Any]] = None,
        business_data: Optional[Dict[str, Any]] = None,
        financial_data: Optional[Dict[str, Any]] = None,
        llm_classification: Optional[Dict[str, Any]] = None,
        unknown_malicious_intent: Optional[Dict[str, Any]] = None,
        # ── shared inputs ───────────────────────────────────────────────────
        code_injection: Optional[Dict[str, Any]] = None,
        pii: Optional[Dict[str, Any]] = None,
        # ── v1 legacy inputs (kept for backward compatibility) ────────────
        injection: Optional[Dict[str, Any]] = None,
        llama_guard: Optional[Dict[str, Any]] = None,
        context: Optional[Dict[str, Any]] = None,
        weights: Optional[Dict[str, int]] = None
    ) -> Dict[str, Any]:
        """
        Calculate weighted risk score.

        Supports two modes determined by which weights are provided:

        v2 (default, 10-input):
            code_injection, pii, phi, api_secrets, credentials,
            private_url, business_data, financial_data, llm_classification

        v1 (legacy, 5-input — pass weights with v1 keys):
            injection, code_injection, llama_guard, context, pii

        Args:
            phi: Results from phi-detector (HIPAA PHI)
            api_secrets: Results from api-secrets-detector
            credentials: Results from credentials-detector
            private_url: Results from private-url-detector
            business_data: Results from business-data-detector
            financial_data: Results from financial-data-detector
            llm_classification: Results from local-llm-prompt-security-eval
            code_injection: Results from code-injection-detector
            pii: Results from pii-detector
            injection: (v1 legacy) prompt injection results
            llama_guard: (v1 legacy) llama guard results
            context: (v1 legacy) context analysis results
            weights: Custom weight distribution (must sum to 100)

        Returns:
            Dictionary with total_score, effective_score, risk_level,
            breakdown, recommendations
        """
        # Auto-detect mode from weights keys or presence of v2 inputs
        if weights is None:
            v2_inputs_present = any([
                phi, api_secrets, credentials, private_url,
                business_data, financial_data, llm_classification,
                unknown_malicious_intent,
            ])
            v1_only = any([injection, llama_guard, context]) and not v2_inputs_present
            weights = self.legacy_weights if v1_only else self.default_weights

        if sum(weights.values()) != 100:
            raise ValueError("Weights must sum to 100")

        breakdown = {}
        component_scores = []

        # ── v2 components ─────────────────────────────────────────────────────

        if 'unknown_malicious_intent' in weights:
            s, r = self._calculate_unknown_malicious_intent_score(
                unknown_malicious_intent or {}, weights['unknown_malicious_intent']
            )
            breakdown['unknown_malicious_intent'] = {'score': s, 'weight': weights['unknown_malicious_intent'], 'reason': r}
            component_scores.append(s)

        if 'code_injection' in weights:
            s, r = self._calculate_code_injection_score(
                code_injection or {}, weights['code_injection']
            )
            breakdown['code_injection'] = {'score': s, 'weight': weights['code_injection'], 'reason': r}
            component_scores.append(s)

        if 'pii' in weights:
            s, r = self._calculate_pii_score(pii or {}, weights['pii'])
            breakdown['pii'] = {'score': s, 'weight': weights['pii'], 'reason': r}
            component_scores.append(s)

        if 'phi' in weights:
            s, r = self._calculate_phi_score(phi or {}, weights['phi'])
            breakdown['phi'] = {'score': s, 'weight': weights['phi'], 'reason': r}
            component_scores.append(s)

        if 'api_secrets' in weights:
            s, r = self._calculate_api_secrets_score(api_secrets or {}, weights['api_secrets'])
            breakdown['api_secrets'] = {'score': s, 'weight': weights['api_secrets'], 'reason': r}
            component_scores.append(s)

        if 'credentials' in weights:
            s, r = self._calculate_credentials_score(credentials or {}, weights['credentials'])
            breakdown['credentials'] = {'score': s, 'weight': weights['credentials'], 'reason': r}
            component_scores.append(s)

        if 'private_url' in weights:
            s, r = self._calculate_private_url_score(private_url or {}, weights['private_url'])
            breakdown['private_url'] = {'score': s, 'weight': weights['private_url'], 'reason': r}
            component_scores.append(s)

        if 'business_data' in weights:
            s, r = self._calculate_business_data_score(business_data or {}, weights['business_data'])
            breakdown['business_data'] = {'score': s, 'weight': weights['business_data'], 'reason': r}
            component_scores.append(s)

        if 'financial_data' in weights:
            s, r = self._calculate_financial_data_score(financial_data or {}, weights['financial_data'])
            breakdown['financial_data'] = {'score': s, 'weight': weights['financial_data'], 'reason': r}
            component_scores.append(s)

        if 'llm_classification' in weights:
            s, r = self._calculate_llm_classification_score(llm_classification or {}, weights['llm_classification'])
            breakdown['llm_classification'] = {'score': s, 'weight': weights['llm_classification'], 'reason': r}
            component_scores.append(s)

        # ── v1 legacy components ──────────────────────────────────────────────

        if 'injection' in weights:
            s, r = self._calculate_injection_score(injection or {}, weights['injection'])
            breakdown['injection'] = {'score': s, 'weight': weights['injection'], 'reason': r}
            component_scores.append(s)

        if 'llama_guard' in weights:
            s, r = self._calculate_llama_score(llama_guard or {}, weights['llama_guard'])
            breakdown['llama_guard'] = {'score': s, 'weight': weights['llama_guard'], 'reason': r}
            component_scores.append(s)

        if 'context' in weights:
            s, r = self._calculate_context_score(context or {}, weights['context'])
            breakdown['context'] = {'score': s, 'weight': weights['context'], 'reason': r}
            component_scores.append(s)

        # ── Total score ───────────────────────────────────────────────────────
        total_score = min(sum(component_scores), 100)

        # ── Privacy / secrets elevation ───────────────────────────────────────
        # Any CRITICAL-severity finding across privacy/secrets detectors floors
        # the effective score to ensure non-SAFE classification.
        all_risk_levels = [
            ((pii or {}).get('risk_level') or 'SAFE').upper(),
            ((phi or {}).get('risk_level') or 'SAFE' if phi else 'SAFE'),
            ((api_secrets or {}).get('risk_level') or 'SAFE' if api_secrets else 'SAFE'),
            ((credentials or {}).get('risk_level') or 'SAFE' if credentials else 'SAFE'),
        ]
        max_privacy_risk = 'SAFE'
        for lvl in all_risk_levels:
            if lvl == 'CRITICAL':
                max_privacy_risk = 'CRITICAL'
                break
            elif lvl == 'HIGH' and max_privacy_risk != 'CRITICAL':
                max_privacy_risk = 'HIGH'
            elif lvl == 'MEDIUM' and max_privacy_risk not in ('CRITICAL', 'HIGH'):
                max_privacy_risk = 'MEDIUM'

        if max_privacy_risk == 'CRITICAL':
            effective_score = max(total_score, 70)
        elif max_privacy_risk == 'HIGH':
            effective_score = max(total_score, 50)
        elif max_privacy_risk == 'MEDIUM':
            effective_score = max(total_score, 30)
        else:
            effective_score = total_score

        # ── Unknown malicious intent elevation ───────────────────────────────
        # Jailbreaks, persona overrides, safety bypasses → BLOCK minimum.
        # Data extraction / impersonation probes → WARN minimum.
        if unknown_malicious_intent and unknown_malicious_intent.get('detected', False):
            umi_risk = (unknown_malicious_intent.get('risk_level') or 'SAFE').upper()
            if umi_risk == 'CRITICAL':
                effective_score = max(effective_score, 70)   # → BLOCK
            elif umi_risk == 'HIGH':
                effective_score = max(effective_score, 50)   # → WARN (HIGH)
            elif umi_risk == 'MEDIUM':
                effective_score = max(effective_score, 30)   # → WARN

        # ── Code injection threat elevation ───────────────────────────────────
        # Code-based manipulation threats → BLOCK. Other code threats → WARN.
        if code_injection and code_injection.get('threat_detected', False):
            code_types = set(code_injection.get('code_types', []))
            if code_types & {'Agent_Manipulation'}:
                effective_score = max(effective_score, 70)   # → BLOCK
            else:
                effective_score = max(effective_score, 50)   # → WARN (HIGH)

        # ── Legacy PII elevation fallback ─────────────────────────────────────
        pii_risk = ((pii or {}).get('risk_level') or 'SAFE').upper()
        if pii_risk == 'CRITICAL':
            effective_score = max(effective_score, 70)
        elif pii_risk == 'HIGH':
            effective_score = max(effective_score, 50)

        # ── LLM intent elevation ───────────────────────────────────────────────
        # When only the LLM analyzer runs (fast pre-check path: analyzers_requested=['llm','risk']),
        # the raw LLM contribution is max 7 points — not enough to reach the 30-pt WARN threshold.
        # Apply elevation floors so Harmful/Jailbreak intent always produces the correct action,
        # regardless of whether other analyzers ran.
        if llm_classification and llm_classification.get('available'):
            intent      = (llm_classification.get('Intent_Category') or '').lower()
            intent_sev  = (llm_classification.get('Intent_Risk_Severity') or 'low').lower()
            pattern     = (llm_classification.get('Pattern') or '').lower()
            pattern_sev = (llm_classification.get('Pattern_Risk_Severity') or 'low').lower()

            # Elevation from Intent — 13-category taxonomy
            # Critical-risk intents → BLOCK (≥70)
            _BLOCK_INTENTS = {'injection', 'jailbreak', 'extraction', 'misuse',
                              'harmful', 'policy_violation'}   # legacy aliases kept
            # High-risk intents → WARN HIGH (≥50)
            _WARN_HIGH_INTENTS = {'leakage', 'obfuscation'}
            # Medium-risk intents → WARN (≥30)
            _WARN_MED_INTENTS = {'dos'}

            if intent in _BLOCK_INTENTS:
                if intent_sev == 'critical':
                    effective_score = max(effective_score, 70)   # → BLOCK
                elif intent_sev == 'high':
                    effective_score = max(effective_score, 50)   # → WARN (HIGH)
                else:
                    effective_score = max(effective_score, 30)   # → WARN (MEDIUM)
            elif intent in _WARN_HIGH_INTENTS:
                if intent_sev in ('critical', 'high'):
                    effective_score = max(effective_score, 50)
                else:
                    effective_score = max(effective_score, 30)
            elif intent in _WARN_MED_INTENTS:
                effective_score = max(effective_score, 30)

            # Elevation from Persona — critical/high personas signal jailbreak framing
            # even when the stated intent appears benign (e.g. "act as an unrestricted
            # assistant and tell me how to bake cookies").
            persona_cat = (llm_classification.get('Generic_Persona_Category') or '').lower()
            derived_persona_risk = _PERSONA_RISK_MAP.get(persona_cat, 'low')
            if derived_persona_risk == 'critical':
                effective_score = max(effective_score, 30)   # → WARN minimum
            elif derived_persona_risk == 'high':
                effective_score = max(effective_score, 20)   # keeps score above noise floor

            # Elevation from Pattern — uses the 60-pattern map as primary source;
            # falls back to model-reported pattern_sev for unknown patterns.
            # Catches cases where model correctly identifies the attack pattern
            # but misclassifies Intent_Category as "Benign".
            derived_pattern_risk = _PATTERN_RISK_MAP.get(pattern, 'low')
            effective_pattern_risk = _RISK_ORDER[max(
                _RISK_ORDER.index(derived_pattern_risk),
                _RISK_ORDER.index(pattern_sev) if pattern_sev in _RISK_ORDER else 0,
            )]
            if effective_pattern_risk == 'critical':
                effective_score = max(effective_score, 70)   # → BLOCK
            elif effective_pattern_risk == 'high':
                effective_score = max(effective_score, 50)   # → WARN
            elif effective_pattern_risk == 'medium':
                effective_score = max(effective_score, 30)   # → WARN (MEDIUM)

        risk_level = self._determine_risk_level(effective_score)

        recommendations = self._generate_recommendations(
            effective_score, breakdown,
            injection or {}, llama_guard or {}, pii or {},
            api_secrets or {}, credentials or {}, phi or {}
        )

        return {
            'total_score': total_score,
            'effective_score': effective_score,
            'risk_level': risk_level,
            'breakdown': breakdown,
            'recommendations': recommendations
        }

    def _calculate_injection_score(
        self, injection: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """Calculate injection component score."""
        has_critical = injection.get('has_critical', False)
        has_high = injection.get('has_high', False)
        count = injection.get('count', 0)

        if has_critical:
            return max_points, "CRITICAL severity findings detected"
        elif has_high:
            return int(max_points * 0.75), "HIGH severity findings detected"
        elif count > 0:
            return int(max_points * 0.5), f"{count} injection patterns detected"
        else:
            return 0, "No injection patterns detected"

    def _calculate_unknown_malicious_intent_score(
        self, umi: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """Score unknown-malicious-intent-detector output."""
        if not umi or not umi.get('detected', False):
            return 0, "No malicious intent patterns detected"
        risk_level = (umi.get('risk_level') or 'HIGH').upper()
        count = umi.get('count', 0)
        findings = umi.get('findings', [])
        names = [f.get('name', '') for f in findings[:2]]
        name_str = ', '.join(names) if names else 'unknown'
        ratio = {'MEDIUM': 0.4, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.75)
        score = int(max_points * ratio)
        return score, f"{count} malicious intent pattern(s): {name_str}"

    def _calculate_code_injection_score(
        self, code_injection: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """Calculate code injection component score (binary scoring)."""
        threat_detected = code_injection.get('threat_detected', False)
        code_types = code_injection.get('code_types', [])
        threat_count = code_injection.get('threat_count', 0)

        if threat_detected:
            types_str = ', '.join(code_types[:3])  # Show first 3 types
            if len(code_types) > 3:
                types_str += f", +{len(code_types) - 3} more"
            return max_points, f"Code execution patterns detected: {types_str} ({threat_count} total)"
        else:
            return 0, "No code injection patterns detected"

    def _calculate_llama_score(
        self, llama_guard: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """Calculate Llama Guard component score."""
        is_unsafe = llama_guard.get('is_unsafe', False)
        has_warning = llama_guard.get('has_warning', False)
        verdict = llama_guard.get('verdict', 'SAFE')

        if is_unsafe:
            return max_points, f"Llama Guard verdict: {verdict}"
        elif has_warning:
            return int(max_points * 0.5), "Llama Guard warning detected"
        else:
            return 0, f"Llama Guard verdict: {verdict}"

    def _calculate_context_score(
        self, context: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """Calculate context component score."""
        primary_intent = context.get('primary_intent', {})
        intent_risk = primary_intent.get('risk', 'Neutral') if primary_intent else 'Neutral'
        indicators = context.get('indicators', [])

        score = 0
        reasons = []

        if intent_risk == 'Malicious':
            score += max_points
            reasons.append("Malicious intent detected")
        elif intent_risk == 'Neutral':
            score += int(max_points * 0.5)
            reasons.append("Neutral intent")
        else:
            reasons.append("Benign intent")

        if len(indicators) > 2:
            indicator_points = int(max_points * 0.25)
            score += indicator_points
            reasons.append(f"{len(indicators)} suspicious indicators")

        reason = "Intent risk: " + intent_risk
        if len(indicators) > 2:
            reason += f", {len(indicators)} indicators"

        return min(score, max_points), reason

    def _calculate_pii_score(
        self, pii: Dict[str, Any], max_points: int
    ) -> tuple[int, str]:
        """
        Calculate PII component score using v2 pii-detector output.

        Scoring factors (in priority order):
          1. risk_level from detector  (base score)
          2. CRITICAL-risk findings    (SSN, Aadhaar, credit card, MRN, account number)
          3. Linked identifier set     (re-identification risk bonus)
          4. Special-category data     (GDPR Art. 9: health, financial profile)
          5. HIGH-risk findings        (PAN, passport, voter ID, UPI, driving licence)
        """
        if not pii or pii.get('count', 0) == 0:
            return 0, "No PII detected"

        findings = pii.get('findings') or pii.get('detected') or []
        risk_level = (pii.get('risk_level') or 'LOW').upper()
        count = pii.get('count', 0)

        # ── Base score from detector risk_level ────────────────────────
        risk_ratio = {'SAFE': 0.0, 'LOW': 0.25, 'MEDIUM': 0.50,
                      'HIGH': 0.75, 'CRITICAL': 1.0}
        score = int(max_points * risk_ratio.get(risk_level, 0.50))

        # ── Classify findings ──────────────────────────────────────────
        _CRITICAL_CATS = {
            'national_id', 'aadhaar_number', 'payment_card_number',
            'medical_record_number', 'account_number', 'linked_identifier_set',
        }
        _HIGH_CATS = {
            'pan_number', 'passport_number', 'voter_id', 'driving_licence_number',
            'banking_identifier', 'upi_id', 'health_policy_number',
            'special_category_or_sensitive_context', 'financial_profile',
        }
        _SPECIAL_CATS = {
            'special_category_or_sensitive_context', 'financial_profile',
        }

        real_findings = [f for f in findings if f.get('category') != 'linked_identifier_set']
        has_critical = any(
            f.get('category') in _CRITICAL_CATS or f.get('risk', '').upper() == 'CRITICAL'
            for f in real_findings
        )
        has_high = any(
            f.get('category') in _HIGH_CATS or f.get('risk', '').upper() == 'HIGH'
            for f in real_findings
        )
        has_linked_set = any(f.get('category') == 'linked_identifier_set' for f in findings)
        has_special = any(f.get('category') in _SPECIAL_CATS for f in real_findings)

        # ── Override base score with finding-level signals ─────────────
        if has_critical:
            score = max_points
        elif has_high and score < int(max_points * 0.75):
            score = int(max_points * 0.75)

        # ── Linked identifier set: re-identification risk bonus ────────
        if has_linked_set and score < max_points:
            score = min(score + int(max_points * 0.20), max_points)

        # ── Special-category data bonus (GDPR Art. 9 / DPDP sensitive) ─
        if has_special and score < max_points:
            score = min(score + int(max_points * 0.15), max_points)

        # ── Build reason string ────────────────────────────────────────
        reasons = []
        if has_critical:
            names = [
                f.get('name', f.get('category', ''))
                for f in real_findings
                if f.get('risk', '').upper() == 'CRITICAL'
            ]
            if names:
                reasons.append(f"Critical PII: {', '.join(names[:2])}")
        if has_linked_set:
            reasons.append("linked identifier set (re-identification risk)")
        if has_special:
            reasons.append("special-category data (GDPR Art. 9)")
        if has_high and not has_critical:
            names = [
                f.get('name', f.get('category', ''))
                for f in real_findings
                if f.get('risk', '').upper() == 'HIGH'
            ]
            if names:
                reasons.append(f"High-risk PII: {', '.join(names[:2])}")
        if not reasons:
            reasons.append(f"{count} PII finding(s) at {risk_level} risk")

        return min(score, max_points), "; ".join(reasons)

    def _calculate_phi_score(
        self, phi: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score PHI (HIPAA) detector output."""
        if not phi or phi.get('count', 0) == 0:
            return 0, "No PHI detected"
        has_critical = phi.get('has_critical', False)
        has_high = phi.get('has_high', False)
        count = phi.get('count', 0)
        categories = phi.get('categories_detected', [])
        cat_str = ', '.join(categories[:2]) if categories else 'PHI'
        if has_critical:
            return max_points, f"CRITICAL PHI detected: {cat_str}"
        elif has_high:
            return int(max_points * 0.75), f"HIGH PHI detected: {cat_str}"
        else:
            return int(max_points * 0.5), f"{count} PHI finding(s): {cat_str}"

    def _calculate_api_secrets_score(
        self, api_secrets: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score api-secrets-detector output."""
        if not api_secrets or not api_secrets.get('threat_detected', False):
            return 0, "No API secrets detected"
        risk_level = (api_secrets.get('risk_level') or 'HIGH').upper()
        secrets = api_secrets.get('secrets_found', [])
        services = list({s.get('service', '') for s in secrets if s.get('service')})
        svc_str = ', '.join(services[:3]) if services else 'unknown'
        ratio = {'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.75)
        score = int(max_points * ratio)
        return score, f"{risk_level} API secret(s) detected: {svc_str}"

    def _calculate_credentials_score(
        self, credentials: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score credentials-detector output."""
        if not credentials or not credentials.get('detected', False):
            return 0, "No credentials detected"
        risk_level = (credentials.get('risk_level') or 'HIGH').upper()
        count = credentials.get('count', 0)
        ratio = {'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.75)
        score = int(max_points * ratio)
        return score, f"{count} credential(s) detected at {risk_level} risk"

    def _calculate_private_url_score(
        self, private_url: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score private-url-detector output."""
        if not private_url or not private_url.get('detected', False):
            return 0, "No private URLs detected"
        risk_level = (private_url.get('risk_level') or 'HIGH').upper()
        count = private_url.get('count', 0)
        urls = private_url.get('urls_found', [])
        types = list({u.get('name', '') for u in urls[:2]})
        type_str = ', '.join(types) if types else 'internal URL'
        ratio = {'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.75)
        score = int(max_points * ratio)
        return score, f"{count} private URL(s): {type_str}"

    def _calculate_business_data_score(
        self, business_data: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score business-data-detector output."""
        if not business_data or not business_data.get('detected', False):
            return 0, "No business identifiers detected"
        risk_level = (business_data.get('risk_level') or 'MEDIUM').upper()
        count = business_data.get('count', 0)
        findings = business_data.get('findings', [])
        names = [f.get('name', '') for f in findings[:2]]
        name_str = ', '.join(names) if names else 'business ID'
        ratio = {'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.5)
        score = int(max_points * ratio)
        return score, f"{count} business identifier(s): {name_str}"

    def _calculate_financial_data_score(
        self, financial_data: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score financial-data-detector output."""
        if not financial_data or not financial_data.get('detected', False):
            return 0, "No financial data detected"
        risk_level = (financial_data.get('risk_level') or 'HIGH').upper()
        count = financial_data.get('count', 0)
        distinct = financial_data.get('distinct_financial_figures', count)
        ratio = {'MEDIUM': 0.5, 'HIGH': 0.75, 'CRITICAL': 1.0}.get(risk_level, 0.75)
        score = int(max_points * ratio)
        return score, f"{distinct} financial figure(s) at {risk_level} risk"

    def _calculate_llm_classification_score(
        self, llm_cls: Dict[str, Any], max_points: int
    ) -> tuple:
        """Score local-llm-prompt-security-eval output (6-parameter format)."""
        if not llm_cls or not llm_cls.get('available', False):
            return 0, "LLM classification unavailable"

        intent = (llm_cls.get('Intent_Category') or 'Benign').lower()
        intent_sev = (llm_cls.get('Intent_Risk_Severity') or 'Low').lower()
        persona_sev = (llm_cls.get('Persona_Risk_Severity') or 'Low').lower()
        pattern_sev = (llm_cls.get('Pattern_Risk_Severity') or 'Low').lower()
        pattern = (llm_cls.get('Pattern') or 'Normal').lower()
        persona_cat = (llm_cls.get('Generic_Persona_Category') or 'Neutral/Default State').lower()

        sev_scores = {'low': 0, 'medium': 0.4, 'high': 0.75, 'critical': 1.0}
        # Derive persona severity from the 40-category map; take the higher of
        # model-reported and taxonomy-derived to guard against under-reporting.
        derived_persona_risk = _PERSONA_RISK_MAP.get(persona_cat, 'low')
        effective_persona_sev = max(
            sev_scores.get(persona_sev, 0),
            sev_scores.get(derived_persona_risk, 0),
        )
        max_sev = max(
            sev_scores.get(intent_sev, 0),
            effective_persona_sev,
            sev_scores.get(pattern_sev, 0)
        )

        # Intent overrides — map 13-category taxonomy to severity floors
        _CRITICAL_INTENTS = {'injection', 'jailbreak', 'extraction', 'misuse'}
        _HIGH_INTENTS      = {'leakage', 'obfuscation'}
        _MEDIUM_INTENTS    = {'dos'}
        # Legacy 4-category names (backward compat)
        _LEGACY_CRITICAL   = {'harmful', 'policy_violation'}

        if intent in _CRITICAL_INTENTS or intent in _LEGACY_CRITICAL:
            max_sev = max(max_sev, 0.75)
        elif intent in _HIGH_INTENTS:
            max_sev = max(max_sev, 0.5)
        elif intent in _MEDIUM_INTENTS:
            max_sev = max(max_sev, 0.4)

        # Pattern overrides — derive risk from 60-pattern map; take higher of
        # model-reported severity and taxonomy-derived risk.
        derived_pattern_risk = _PATTERN_RISK_MAP.get(pattern, 'low')
        effective_pattern_sev = max(
            sev_scores.get(pattern_sev, 0),
            sev_scores.get(derived_pattern_risk, 0),
        )
        max_sev = max(max_sev, effective_pattern_sev)

        score = int(max_points * max_sev)
        reason = f"Intent: {llm_cls.get('Intent_Category', 'Benign')}, Pattern: {llm_cls.get('Pattern', 'Normal')}"
        return score, reason

    def _determine_risk_level(self, score: int) -> str:
        """Determine risk level from score."""
        if score < 30:
            return "SAFE"
        elif score < 50:
            return "MEDIUM"
        elif score < 70:
            return "HIGH"
        else:
            return "CRITICAL"

    def _generate_recommendations(
        self,
        score: int,
        breakdown: Dict[str, Any],
        injection: Dict[str, Any],
        llama_guard: Dict[str, Any],
        pii: Dict[str, Any] = None,
        api_secrets: Dict[str, Any] = None,
        credentials: Dict[str, Any] = None,
        phi: Dict[str, Any] = None,
    ) -> List[str]:
        """Generate actionable recommendations."""
        pii = pii or {}
        api_secrets = api_secrets or {}
        credentials = credentials or {}
        phi = phi or {}
        recommendations = []

        # Overall severity header
        if score >= 70:
            recommendations.append("CRITICAL: Severe risks detected. Do not use in production.")
        elif score >= 50:
            recommendations.append("HIGH RISK: Significant concerns. Careful review required before use.")
        elif score >= 30:
            recommendations.append("MEDIUM RISK: Some concerns detected. Review recommended.")
        else:
            recommendations.append("LOW RISK: Minimal concerns, but always validate in context.")

        # API Secrets
        if api_secrets.get('threat_detected'):
            secrets = api_secrets.get('secrets_found', [])
            services = list({s.get('service', '') for s in secrets if s.get('service')})
            svc_str = ', '.join(services[:3]) if services else 'service'
            recommendations.append(
                f"API secret(s) detected ({svc_str}): Revoke and rotate immediately. "
                "Never share credentials in AI prompts."
            )

        # Credentials
        if credentials.get('detected'):
            count = credentials.get('count', 0)
            recommendations.append(
                f"{count} credential pattern(s) detected: Remove passwords/secrets from prompt. "
                "Use environment variables or secrets managers."
            )

        # PHI
        if phi.get('count', 0) > 0:
            cats = phi.get('categories_detected', [])
            cat_str = ', '.join(cats[:3]) if cats else 'PHI'
            if phi.get('has_critical'):
                recommendations.append(
                    f"CRITICAL PHI detected ({cat_str}): HIPAA-protected data. "
                    "Do not share patient data with AI systems without BAA."
                )
            else:
                recommendations.append(
                    f"PHI detected ({cat_str}): Review HIPAA compliance before processing."
                )

        # Injection (v1 legacy)
        if injection.get('has_critical'):
            recommendations.append("Review injection patterns immediately.")

        # LLM Guard (v1 legacy)
        if llama_guard.get('is_unsafe'):
            recommendations.append("LLM guard flagged unsafe content. Investigate intent.")

        # Context (v1 legacy) — only fire if context key is actually present and scored
        ctx = breakdown.get('context', {})
        if ctx and ctx.get('weight', 0) > 0 and ctx.get('score', 0) >= ctx.get('weight', 0):
            recommendations.append("Malicious intent detected in context analysis.")

        # PII — detailed recommendations from v2 output
        pii_findings = pii.get('findings') or pii.get('detected') or []
        real_findings = [f for f in pii_findings if f.get('category') != 'linked_identifier_set']
        has_linked_set = any(f.get('category') == 'linked_identifier_set' for f in pii_findings)

        if real_findings:
            critical_names = [
                f.get('name', f.get('category', ''))
                for f in real_findings
                if f.get('risk', '').upper() == 'CRITICAL'
            ]
            high_names = [
                f.get('name', f.get('category', ''))
                for f in real_findings
                if f.get('risk', '').upper() == 'HIGH'
            ]
            special_names = [
                f.get('name', f.get('category', ''))
                for f in real_findings
                if f.get('category') in {
                    'special_category_or_sensitive_context', 'financial_profile'
                }
            ]
            ctx_findings = [f for f in real_findings if f.get('source') == 'context']

            if critical_names:
                recommendations.append(
                    f"CRITICAL PII detected ({', '.join(critical_names[:3])}): "
                    "Remove or replace with synthetic data before processing."
                )
            elif high_names:
                recommendations.append(
                    f"High-risk PII detected ({', '.join(high_names[:3])}): "
                    "Mask or redact before forwarding to any model."
                )
            elif real_findings:
                recommendations.append(
                    f"{len(real_findings)} PII item(s) found. "
                    "Apply masking or anonymisation before use."
                )

            if has_linked_set:
                recommendations.append(
                    "Linked identifier set: multiple PII types in proximity significantly "
                    "increase re-identification risk. Treat as high-sensitivity data."
                )

            if special_names:
                recommendations.append(
                    f"Special-category data detected ({', '.join(special_names[:2])}): "
                    "Subject to heightened protection under GDPR Art. 9 / India DPDP Act."
                )

            if ctx_findings:
                recommendations.append(
                    f"{len(ctx_findings)} PII item(s) detected via contextual linkage "
                    "(keyword proximity). Verify and redact as required."
                )

        return recommendations


# CLI interface for standalone usage
if __name__ == '__main__':
    import sys
    import json

    # Example usage
    if len(sys.argv) > 1 and sys.argv[1] == '--example':
        calculator = RiskCalculator()

        # Example: Critical injection + unsafe content
        result = calculator.calculate_risk(
            injection={'has_critical': True, 'has_high': False, 'count': 3},
            llama_guard={'is_unsafe': True, 'has_warning': False, 'verdict': 'UNSAFE'},
            context={'primary_intent': {'risk': 'Malicious'}, 'indicators': ['system-level', 'encoded']},
            pii={'count': 1}
        )

        print(json.dumps(result, indent=2))
    else:
        print("Usage: python risk_calculator.py --example")
        print("\nOr use in code:")
        print("  from risk_calculator import RiskCalculator")
        print("  calculator = RiskCalculator()")
        print("  result = calculator.calculate_risk(...)")
