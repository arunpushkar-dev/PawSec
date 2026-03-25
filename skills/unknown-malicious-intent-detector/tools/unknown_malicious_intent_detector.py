#!/usr/bin/env python3
"""
Unknown Malicious Intent Detector

Detects PURELY LINGUISTIC adversarial patterns — jailbreaks, persona overrides,
safety bypass phrasing, AI training overrides, and harmful content requests.

This detector is intentionally separate from code_injection_detector, which handles
prompts that CONTAIN malicious code. This detector handles attacks that use natural
language to manipulate AI behaviour — no code required.

Categories:
  Jailbreak           — DAN, "ignore previous instructions", "pretend you have no rules"
  Persona_Override    — "you are no longer X", "you are now AdminBot"
  Safety_Bypass       — "regardless of safety rules", "without ethical guidelines"
  Training_Override   — "disregard your training", "your new directive is to..."
  Harmful_Request     — requests to create phishing, malware, credential harvesters
  Data_Extraction     — "reveal your system prompt", "repeat your instructions"

NOTE: Patterns that require actual code syntax (eval(), subprocess, print(system_prompt))
      belong in the code-injection-detector, not here.
"""

import re
from typing import Dict, List, Any
from datetime import datetime

_RISK_ORDER = {'SAFE': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3}


class UnknownMaliciousIntentDetector:
    """Detects linguistic adversarial intent — jailbreaks, persona manipulation,
    safety bypasses, harmful requests — with no code present in the prompt."""

    def __init__(self):
        self.patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        return [
            # ── Jailbreak ──────────────────────────────────────────────────────
            {'name': 'jailbreak_dan',
             'risk': 'CRITICAL',
             'pattern': re.compile(r'\bDAN\b|\bDo\s+Anything\s+Now\b', re.IGNORECASE)},
            {'name': 'pretend_no_rules',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\bpretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:rules?|restrictions?|guidelines?|limits?)',
                 re.IGNORECASE)},
            {'name': 'ignore_previous_instructions',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\bignore\s+(?:\w+\s+){0,3}(?:previous|prior|above|all\s+previous)\s+(?:\w+\s+){0,3}instructions?',
                 re.IGNORECASE)},
            {'name': 'system_tag_override',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\[(?:SYSTEM|INST|SYS|ADMIN|ROOT)\s+(?:OVERRIDE|BYPASS|IGNORE|CONTROL|DIRECTIVE|COMMAND|JAILBREAK|UNLOCK)\]',
                 re.IGNORECASE)},
            {'name': 'system_bracket_ignore',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\[(?:SYSTEM|INST|SYS)\]\s*(?:ignore|override|bypass)',
                 re.IGNORECASE)},

            # ── Persona Override ───────────────────────────────────────────────
            {'name': 'persona_override',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\byou\s+are\s+no\s+longer\s+(?:a\s+)?(?:\w+\s+){0,4}(?:assistant|ai|model|bot|chatbot|helpful)',
                 re.IGNORECASE)},
            {'name': 'you_are_now_bot',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\byou\s+(?:are|will\s+be|must\s+act\s+as)\s+now\s+(?:called\s+)?[\'"]?\w+(?:bot|ai)[\'"]?\b',
                 re.IGNORECASE)},
            {'name': 'act_as_uncensored_ai',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\bact\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|malicious)\s+(?:ai|assistant|model|bot|version)',
                 re.IGNORECASE)},

            # ── Safety Constraint Bypass ───────────────────────────────────────
            {'name': 'regardless_of_safety',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:regardless|irrespective)\s+of\s+(?:your\s+)?(?:safety|ethical|content|usage)\s+(?:rules?|guidelines?|policies|constraints?|filters?|protocols?|restrictions?)',
                 re.IGNORECASE)},
            {'name': 'without_safety_constraints',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\bwithout\s+(?:any\s+)?(?:ethical|safety|content|moral)\s+(?:guidelines?|constraints?|restrictions?|filters?|rules?|limits?)',
                 re.IGNORECASE)},
            {'name': 'disable_safety_filters',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:ignore|bypass|disable|remove|turn\s+off)\s+(?:your\s+)?(?:safety|content|ethical)\s+(?:filters?|guidelines?|restrictions?|rules?|protocols?|training)',
                 re.IGNORECASE)},

            # ── AI Training / Instruction Override ────────────────────────────
            {'name': 'disregard_training',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:disregard|forget|bypass|ignore)\s+(?:your|all|the|previous|all\s+previous)\s+(?:training|instructions?|directives?|programming|guidelines?|rules?|safety\s+(?:measures?|protocols?|filters?|rules?))',
                 re.IGNORECASE)},
            {'name': 'override_training',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\boverride\s+(?:your\s+)?(?:training|programming|instructions?|directives?|safety\s+(?:measures?|protocols?|filters?|rules?))',
                 re.IGNORECASE)},
            {'name': 'new_directive_assign',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:your\s+)?(?:new|updated?)\s+(?:directive|instruction|order|command|mission|purpose)\s+(?:is|are)\s+(?:to|that)\b',
                 re.IGNORECASE)},
            {'name': 'comply_without_filtering',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\bcomply\s+with\s+all\s+(?:\w+\s+)?requests?\s+without\s+(?:filtering|restrictions?|limits?|safety)',
                 re.IGNORECASE)},

            # ── Harmful Content Requests ───────────────────────────────────────
            {'name': 'create_phishing',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:write|create|generate|draft|make)\s+(?:a\s+|an\s+)?(?:convincing\s+|realistic\s+|fake\s+)?phishing\s+(?:email|message|page|site|template|attack)',
                 re.IGNORECASE)},
            {'name': 'create_malware',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:write|create|generate|make|build|code)\s+(?:a\s+|an\s+)?(?:ransomware|keylogger|trojan|rootkit|spyware|malware|virus|worm|exploit)\b',
                 re.IGNORECASE)},
            {'name': 'credential_harvesting',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:credential\s+harvesting|password\s+harvesting|login\s+harvesting|credential\s+theft\s+(?:script|page|tool))',
                 re.IGNORECASE)},
            {'name': 'fake_login_page',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:fake|spoofed?|cloned?)\s+(?:login|sign.?in|authentication)\s+(?:page|site|portal|form)',
                 re.IGNORECASE)},
            {'name': 'social_engineering_script',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:write|create|generate|draft)\s+(?:a\s+)?(?:social\s+engineering|pretexting|vishing|smishing)\s+(?:script|template|attack|message)',
                 re.IGNORECASE)},
            {'name': 'scam_template',
             'risk': 'CRITICAL',
             'pattern': re.compile(
                 r'\b(?:write|create|generate|draft)\s+(?:a\s+)?(?:convincing\s+|realistic\s+)?(?:scam|fraud|con)\s+(?:email|message|script|template)',
                 re.IGNORECASE)},

            # ── Data Extraction / System Probe ────────────────────────────────
            {'name': 'reveal_system_prompt',
             'risk': 'HIGH',
             'pattern': re.compile(
                 r'\b(?:reveal|output|show|print|repeat|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|configuration)',
                 re.IGNORECASE)},
            {'name': 'impersonation_request',
             'risk': 'HIGH',
             'pattern': re.compile(
                 r'\b(?:impersonat(?:e|ing)|pretend(?:ing)?\s+to\s+be)\s+(?:a\s+)?(?:bank|ceo|it\s+support|admin|helpdesk|government|official)\b',
                 re.IGNORECASE)},
        ]

    def analyze(self, prompt: str) -> Dict[str, Any]:
        """
        Analyze a prompt for linguistic adversarial intent patterns.

        Returns:
            {
                'detected': bool,
                'count': int,
                'risk_level': str,   # SAFE | HIGH | CRITICAL
                'findings': [{'name': str, 'risk': str, 'snippet': str}],
                'timestamp': str
            }
        """
        if not prompt or not isinstance(prompt, str):
            return {
                'detected': False, 'count': 0, 'risk_level': 'SAFE', 'findings': [],
                'error': 'Invalid input: prompt must be a non-empty string',
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }

        try:
            findings = []
            for entry in self.patterns:
                try:
                    match = entry['pattern'].search(prompt)
                    if match:
                        findings.append({
                            'name': entry['name'],
                            'risk': entry['risk'],
                            'snippet': match.group(0)[:80],
                        })
                except Exception:
                    pass

            if not findings:
                return {
                    'detected': False, 'count': 0, 'risk_level': 'SAFE', 'findings': [],
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                }

            max_risk = max(findings, key=lambda f: _RISK_ORDER.get(f['risk'], 0))['risk']
            return {
                'detected': True,
                'count': len(findings),
                'risk_level': max_risk,
                'findings': findings,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }

        except Exception as e:
            return {
                'detected': False, 'count': 0, 'risk_level': 'SAFE', 'findings': [],
                'error': str(e),
                'timestamp': datetime.utcnow().isoformat() + 'Z',
            }


if __name__ == '__main__':
    import sys
    import json

    if len(sys.argv) < 2:
        print("Usage: python unknown_malicious_intent_detector.py <prompt_text>")
        sys.exit(1)

    detector = UnknownMaliciousIntentDetector()
    result = detector.analyze(' '.join(sys.argv[1:]))
    print(json.dumps(result, indent=2))
