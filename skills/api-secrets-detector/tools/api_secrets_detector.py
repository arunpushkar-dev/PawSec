"""
API Secrets & Token Detector
Detects service-specific API keys, tokens, private keys, JWT tokens,
and database connection strings across 40+ services.
"""

import re
import math
import json
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional


class APISecretsDetector:
    """Detects API keys, tokens, private keys, and DB connection strings."""

    def __init__(self):
        self._patterns = self._load_patterns()
        self._high_entropy_context = re.compile(
            r'(?:secret|api[_\-]?key|token|credential|auth|private[_\-]?key|access[_\-]?key|'
            r'client[_\-]?secret|app[_\-]?secret|bearer|passwd|password)\s*[=:]\s*["\']?([A-Za-z0-9+/=_\-\.]{20,})["\']?',
            re.IGNORECASE
        )

    def _load_patterns(self) -> List[Dict]:
        return [
            # ── AWS ──────────────────────────────────────────────────────────────
            {
                "service": "AWS",
                "type": "Access Key ID",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\b(AKIA|ASIA|AROA|AIPA|ANPA|ANVA|APKA)[0-9A-Z]{16}\b')
            },
            {
                "service": "AWS",
                "type": "Secret Access Key",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:aws[_\-]?secret|secret[_\-]?access[_\-]?key)\s*[=:]\s*["\']?([A-Za-z0-9/+]{40})["\']?',
                    re.IGNORECASE
                )
            },
            {
                "service": "AWS",
                "type": "Session Token",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:aws[_\-]?session[_\-]?token)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{100,})["\']?',
                    re.IGNORECASE
                )
            },
            # ── OpenAI ──────────────────────────────────────────────────────────
            {
                "service": "OpenAI",
                "type": "API Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bsk-[A-Za-z0-9]{48}\b')
            },
            {
                "service": "OpenAI",
                "type": "Project API Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bsk-proj-[A-Za-z0-9_\-]{48,}\b')
            },
            # ── Anthropic ────────────────────────────────────────────────────────
            {
                "service": "Anthropic",
                "type": "API Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bsk-ant-api\d{2}-[A-Za-z0-9_\-]{93}\b')
            },
            # ── GitHub ───────────────────────────────────────────────────────────
            {
                "service": "GitHub",
                "type": "Personal Access Token (classic)",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bghp_[A-Za-z0-9]{36}\b')
            },
            {
                "service": "GitHub",
                "type": "Fine-grained Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bgithub_pat_[A-Za-z0-9_]{82}\b')
            },
            {
                "service": "GitHub",
                "type": "OAuth Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bgho_[A-Za-z0-9]{36}\b')
            },
            {
                "service": "GitHub",
                "type": "App Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bghu_[A-Za-z0-9]{36}\b')
            },
            {
                "service": "GitHub",
                "type": "Refresh Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bghr_[A-Za-z0-9]{36}\b')
            },
            # ── Stripe ───────────────────────────────────────────────────────────
            {
                "service": "Stripe",
                "type": "Secret Key (Live)",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bsk_live_[A-Za-z0-9]{24,}\b')
            },
            {
                "service": "Stripe",
                "type": "Secret Key (Test)",
                "severity": "HIGH",
                "pattern": re.compile(r'\bsk_test_[A-Za-z0-9]{24,}\b')
            },
            {
                "service": "Stripe",
                "type": "Restricted Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\brk_live_[A-Za-z0-9]{24,}\b')
            },
            {
                "service": "Stripe",
                "type": "Webhook Secret",
                "severity": "HIGH",
                "pattern": re.compile(r'\bwhsec_[A-Za-z0-9]{32,}\b')
            },
            # ── Google Cloud ─────────────────────────────────────────────────────
            {
                "service": "Google Cloud",
                "type": "API Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b')
            },
            {
                "service": "Google Cloud",
                "type": "OAuth Client Secret",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:client[_\-]?secret)["\']?\s*:\s*["\']?(GOCSPX-[A-Za-z0-9\-_]{28,})["\']?',
                    re.IGNORECASE
                )
            },
            # ── HuggingFace ──────────────────────────────────────────────────────
            {
                "service": "HuggingFace",
                "type": "API Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bhf_[A-Za-z0-9]{37,}\b')
            },
            # ── Twilio ───────────────────────────────────────────────────────────
            {
                "service": "Twilio",
                "type": "Account SID",
                "severity": "HIGH",
                "pattern": re.compile(r'\bAC[a-f0-9]{32}\b')
            },
            {
                "service": "Twilio",
                "type": "Auth Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bSK[a-f0-9]{32}\b')
            },
            # ── Slack ────────────────────────────────────────────────────────────
            {
                "service": "Slack",
                "type": "Bot Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bxoxb-[0-9]+-[0-9]+-[A-Za-z0-9]+\b')
            },
            {
                "service": "Slack",
                "type": "User Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bxoxp-[0-9]+-[0-9]+-[0-9]+-[a-f0-9]+\b')
            },
            {
                "service": "Slack",
                "type": "App Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bxapp-[0-9]-[A-Za-z0-9]+-[0-9]+-[a-f0-9]+\b')
            },
            {
                "service": "Slack",
                "type": "Legacy Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bxoxa-[0-9]+-[A-Za-z0-9]+\b')
            },
            # ── SendGrid ─────────────────────────────────────────────────────────
            {
                "service": "SendGrid",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(r'\bSG\.[A-Za-z0-9._\-]{64,}\b')
            },
            # ── Azure ────────────────────────────────────────────────────────────
            {
                "service": "Azure",
                "type": "Connection String",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{80,}',
                    re.IGNORECASE
                )
            },
            {
                "service": "Azure",
                "type": "Client Secret",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:clientSecret|client_secret)\s*[=:]\s*["\']([A-Za-z0-9~.\-_]{30,})["\']',
                    re.IGNORECASE
                )
            },
            # ── Heroku ───────────────────────────────────────────────────────────
            {
                "service": "Heroku",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b',
                )
            },
            # ── Cloudflare ───────────────────────────────────────────────────────
            {
                "service": "Cloudflare",
                "type": "API Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\b[A-Za-z0-9_\-]{40}\b(?=.*cloudflare)', re.IGNORECASE | re.DOTALL)
            },
            # ── DigitalOcean ─────────────────────────────────────────────────────
            {
                "service": "DigitalOcean",
                "type": "Personal Access Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bdop_v1_[a-f0-9]{64}\b')
            },
            # ── Mailgun ──────────────────────────────────────────────────────────
            {
                "service": "Mailgun",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(r'\bkey-[a-z0-9]{32}\b')
            },
            # ── Mailchimp ────────────────────────────────────────────────────────
            {
                "service": "Mailchimp",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(r'\b[a-f0-9]{32}-us[0-9]{1,2}\b')
            },
            # ── Shopify ──────────────────────────────────────────────────────────
            {
                "service": "Shopify",
                "type": "Admin API Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\bshpat_[A-Za-z0-9]{32}\b')
            },
            {
                "service": "Shopify",
                "type": "Custom App Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bshpca_[A-Za-z0-9]{32}\b')
            },
            # ── npm ──────────────────────────────────────────────────────────────
            {
                "service": "npm",
                "type": "Access Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bnpm_[A-Za-z0-9]{36}\b')
            },
            # ── PyPI ─────────────────────────────────────────────────────────────
            {
                "service": "PyPI",
                "type": "API Token",
                "severity": "HIGH",
                "pattern": re.compile(r'\bpypi-[A-Za-z0-9_\-]{64,}\b')
            },
            # ── Datadog ──────────────────────────────────────────────────────────
            {
                "service": "Datadog",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'(?:dd[_\-]?api[_\-]?key)\s*[=:]\s*["\']?([a-f0-9]{32})["\']?',
                    re.IGNORECASE
                )
            },
            # ── PagerDuty ────────────────────────────────────────────────────────
            {
                "service": "PagerDuty",
                "type": "API Key",
                "severity": "HIGH",
                "pattern": re.compile(r'\bu\+[A-Za-z0-9_\-]{18}\b')
            },
            # ── Vault (HashiCorp) ─────────────────────────────────────────────────
            {
                "service": "HashiCorp Vault",
                "type": "Token",
                "severity": "CRITICAL",
                "pattern": re.compile(r'\b(?:hvs|s)\.[A-Za-z0-9]{24,}\b')
            },
            # ── JWT ──────────────────────────────────────────────────────────────
            {
                "service": "JWT",
                "type": "JSON Web Token",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b'
                )
            },
            # ── Private Keys ─────────────────────────────────────────────────────
            {
                "service": "Cryptographic Key",
                "type": "RSA Private Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'-----BEGIN RSA PRIVATE KEY-----', re.IGNORECASE)
            },
            {
                "service": "Cryptographic Key",
                "type": "EC Private Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'-----BEGIN EC PRIVATE KEY-----', re.IGNORECASE)
            },
            {
                "service": "Cryptographic Key",
                "type": "OpenSSH Private Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'-----BEGIN OPENSSH PRIVATE KEY-----', re.IGNORECASE)
            },
            {
                "service": "Cryptographic Key",
                "type": "Generic Private Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'-----BEGIN PRIVATE KEY-----', re.IGNORECASE)
            },
            {
                "service": "Cryptographic Key",
                "type": "PGP Private Key",
                "severity": "CRITICAL",
                "pattern": re.compile(r'-----BEGIN PGP PRIVATE KEY BLOCK-----', re.IGNORECASE)
            },
            # ── Database Connection Strings ──────────────────────────────────────
            {
                "service": "PostgreSQL",
                "type": "Connection String with Credentials",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'postgresql(?:://|\+psycopg2://)[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+',
                    re.IGNORECASE
                )
            },
            {
                "service": "MySQL",
                "type": "Connection String with Credentials",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'mysql(?:://|\+mysqlconnector://)[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+',
                    re.IGNORECASE
                )
            },
            {
                "service": "MongoDB",
                "type": "Connection String with Credentials",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'mongodb(?:\+srv)?://[A-Za-z0-9_%]+:[^@\s]{3,}@[A-Za-z0-9.\-]+',
                    re.IGNORECASE
                )
            },
            {
                "service": "Redis",
                "type": "Connection String with Password",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'redis://:[^@\s]{3,}@[A-Za-z0-9.\-]+',
                    re.IGNORECASE
                )
            },
            {
                "service": "Generic DB",
                "type": "JDBC Connection String with Password",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'jdbc:[a-z]+://[^;\s]+;password=[^;\s]+',
                    re.IGNORECASE
                )
            },
        ]

    @staticmethod
    def _shannon_entropy(value: str) -> float:
        """Calculate Shannon entropy of a string (bits per character)."""
        if not value:
            return 0.0
        counter = Counter(value)
        length = len(value)
        entropy = -sum(
            (count / length) * math.log2(count / length)
            for count in counter.values()
        )
        return entropy

    @staticmethod
    def _mask_value(value: str) -> str:
        if len(value) <= 8:
            return '*' * len(value)
        return value[:4] + '*' * (len(value) - 8) + value[-4:]

    def _check_high_entropy(self, text: str) -> List[Dict]:
        """Find high-entropy strings in secret/key/token context."""
        findings = []
        for match in self._high_entropy_context.finditer(text):
            candidate = match.group(1)
            if len(candidate) < 20:
                continue
            entropy = self._shannon_entropy(candidate)
            if entropy >= 4.5:
                findings.append({
                    "service": "Generic",
                    "type": "High-Entropy Secret",
                    "severity": "HIGH",
                    "matched_value_masked": self._mask_value(candidate),
                    "context": match.group(0)[:80],
                    "entropy": round(entropy, 2)
                })
        return findings

    def analyze(self, text: str) -> Dict:
        """Analyze text for API secrets and tokens."""
        secrets_found = []
        seen_spans = set()

        for spec in self._patterns:
            for match in spec["pattern"].finditer(text):
                span = match.span()
                # Deduplicate overlapping matches
                if any(abs(span[0] - s) < 5 for s in seen_spans):
                    continue
                seen_spans.add(span[0])

                matched = match.group(0)
                secrets_found.append({
                    "service": spec["service"],
                    "type": spec["type"],
                    "severity": spec["severity"],
                    "matched_value_masked": self._mask_value(matched),
                    "position": span[0]
                })

        # High-entropy context check
        entropy_findings = self._check_high_entropy(text)
        secrets_found.extend(entropy_findings)

        # Determine overall risk level
        if secrets_found:
            severities = [s["severity"] for s in secrets_found]
            if "CRITICAL" in severities:
                risk_level = "CRITICAL"
            elif "HIGH" in severities:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
        else:
            risk_level = "SAFE"

        return {
            "threat_detected": len(secrets_found) > 0,
            "secrets_found": secrets_found,
            "count": len(secrets_found),
            "risk_level": risk_level,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        return [self.analyze(t) for t in texts]


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    detector = APISecretsDetector()

    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        print("Enter text to analyze (Ctrl+C to exit):")
        try:
            text = sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(0)

    result = detector.analyze(text)
    print(json.dumps(result, indent=2))
