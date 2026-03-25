"""
Credentials Detector
Detects passwords, credentials, and secrets in configuration formats,
environment files, JSON payloads, Basic Auth headers, and hardcoded values.
"""

import re
import json
from datetime import datetime
from typing import Dict, List, Optional


class CredentialsDetector:
    """Detects passwords, credentials, and secrets in text."""

    # Placeholder strings that reduce confidence (likely test/example data)
    _PLACEHOLDER_PATTERNS = re.compile(
        r'\b(?:example|sample|test|demo|placeholder|changeme|your[_\-]?password|'
        r'enter[_\-]?password|my[_\-]?password|password123|admin123|secret123|'
        r'xxxxxxxx|<password>|\[password\]|\{password\})\b',
        re.IGNORECASE
    )

    def __init__(self):
        self._patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        return [
            # ── Key = Value patterns (env/config files) ──────────────────────────
            {
                "type": "env_password",
                "name": "Environment Password Variable",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:^|[\s\n])(?:PASSWORD|PASSWD|PWD|DB_PASS|DB_PASSWORD|'
                    r'SECRET|SECRET_KEY|APP_SECRET|MASTER_KEY|PRIVATE_KEY|'
                    r'API_SECRET|CLIENT_SECRET|AUTH_SECRET|SESSION_SECRET|'
                    r'ENCRYPTION_KEY|SIGNING_KEY)\s*=\s*(?!""|\'\'|<|{|\[|\$)'
                    r'["\']?([^\s"\';\n#]{4,})["\']?',
                    re.IGNORECASE | re.MULTILINE
                )
            },
            {
                "type": "generic_kv_password",
                "name": "Key-Value Password Assignment",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'\b(?:password|passwd|pwd|pass)\s*[=:]\s*["\']?(?!["\'<{])'
                    r'([^\s"\';\n,}{]{4,})["\']?',
                    re.IGNORECASE
                )
            },
            {
                "type": "generic_kv_secret",
                "name": "Key-Value Secret Assignment",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'\b(?:secret|token|api_key|apikey|auth_token|access_token|'
                    r'client_secret|app_secret)\s*[=:]\s*["\']?(?!["\'<{])'
                    r'([^\s"\';\n,}{]{8,})["\']?',
                    re.IGNORECASE
                )
            },
            # ── JSON credential fields ───────────────────────────────────────────
            {
                "type": "json_password",
                "name": "JSON Password Field",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'"(?:password|passwd|pwd|pass)"\s*:\s*"(?!"|<|\$|\{)'
                    r'([^"]{4,})"',
                    re.IGNORECASE
                )
            },
            {
                "type": "json_secret",
                "name": "JSON Secret/Token Field",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'"(?:secret|token|api_key|apikey|auth_token|access_token|'
                    r'client_secret|app_secret|private_key|signing_key)"\s*:\s*"(?!"|<)'
                    r'([^"]{8,})"',
                    re.IGNORECASE
                )
            },
            {
                "type": "json_credentials_object",
                "name": "JSON Credentials Object",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'"credentials"\s*:\s*\{[^}]{10,}\}',
                    re.IGNORECASE
                )
            },
            # ── HTTP Authorization Header ─────────────────────────────────────────
            {
                "type": "basic_auth_header",
                "name": "HTTP Basic Auth Header",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'Authorization\s*:\s*Basic\s+([A-Za-z0-9+/=]{8,})',
                    re.IGNORECASE
                )
            },
            {
                "type": "bearer_token_header",
                "name": "HTTP Bearer Token",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'Authorization\s*:\s*Bearer\s+([A-Za-z0-9._\-]{20,})',
                    re.IGNORECASE
                )
            },
            # ── DSN / Connection string credentials ──────────────────────────────
            {
                "type": "dsn_password",
                "name": "DSN/Connection String Password",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:password|passwd|pwd)\s*=\s*([^;\s"\']{4,})\s*(?:;|$)',
                    re.IGNORECASE
                )
            },
            # ── Hardcoded credential patterns ────────────────────────────────────
            {
                "type": "hardcoded_password_string",
                "name": "Hardcoded Password in Code",
                "severity": "CRITICAL",
                "pattern": re.compile(
                    r'(?:String|string|str|var|let|const|val)\s+\w*[Pp]assword\w*\s*=\s*["\']'
                    r'(?!"|<|\$)([^"\']{4,})["\']',
                    re.IGNORECASE
                )
            },
            {
                "type": "hardcoded_secret_string",
                "name": "Hardcoded Secret in Code",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'(?:String|string|str|var|let|const|val)\s+\w*[Ss]ecret\w*\s*=\s*["\']'
                    r'(?!"|<)([^"\']{8,})["\']',
                    re.IGNORECASE
                )
            },
            # ── SMTP / Email credential patterns ─────────────────────────────────
            {
                "type": "smtp_credentials",
                "name": "SMTP Credentials",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'(?:smtp[_\-]?(?:user|pass|password|auth)|mail[_\-]?password)\s*[=:]\s*'
                    r'["\']?([^\s"\';\n]{4,})["\']?',
                    re.IGNORECASE
                )
            },
            # ── XML/YAML credential patterns ─────────────────────────────────────
            {
                "type": "xml_password",
                "name": "XML Password Attribute",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'(?:password|passwd)\s*=\s*["\'](?!"|<)([^"\']{4,})["\']',
                    re.IGNORECASE
                )
            },
            # ── Curl / wget with credentials ──────────────────────────────────────
            {
                "type": "curl_credentials",
                "name": "cURL Embedded Credentials",
                "severity": "HIGH",
                "pattern": re.compile(
                    r'curl\s+.*?-u\s+[^\s]+:[^\s]+',
                    re.IGNORECASE
                )
            },
        ]

    @staticmethod
    def _mask_value(value: str) -> str:
        if len(value) <= 4:
            return '*' * len(value)
        return value[:2] + '*' * (len(value) - 2)

    def _is_placeholder(self, value: str) -> bool:
        return bool(self._PLACEHOLDER_PATTERNS.search(value))

    def analyze(self, text: str) -> Dict:
        """Analyze text for credentials and passwords."""
        findings = []
        seen_positions = []

        for spec in self._patterns:
            for match in spec["pattern"].finditer(text):
                pos = match.start()

                # Skip positions already captured by a prior pattern
                if any(abs(pos - p) < 10 for p in seen_positions):
                    continue

                # Extract the credential value (group 1 if captured, else full match)
                if match.lastindex and match.lastindex >= 1:
                    value = match.group(1) or match.group(0)
                else:
                    value = match.group(0)

                # Suppress clear placeholders
                if self._is_placeholder(value):
                    continue

                seen_positions.append(pos)

                # Build context snippet (surrounding 40 chars each side)
                ctx_start = max(0, pos - 40)
                ctx_end = min(len(text), pos + len(match.group(0)) + 40)
                context_snippet = text[ctx_start:ctx_end].replace('\n', ' ')

                findings.append({
                    "type": spec["type"],
                    "name": spec["name"],
                    "severity": spec["severity"],
                    "value_masked": self._mask_value(value),
                    "context_snippet": context_snippet,
                    "position": pos
                })

        # Risk level
        if findings:
            severities = [f["severity"] for f in findings]
            if "CRITICAL" in severities:
                risk_level = "CRITICAL"
            elif "HIGH" in severities:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
        else:
            risk_level = "SAFE"

        return {
            "detected": len(findings) > 0,
            "findings": findings,
            "count": len(findings),
            "risk_level": risk_level,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        return [self.analyze(t) for t in texts]


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    detector = CredentialsDetector()

    if len(sys.argv) > 1:
        text = " ".join(sys.argv[1:])
    else:
        print("Enter text to analyze (Ctrl+D/Ctrl+Z to end):")
        try:
            text = sys.stdin.read()
        except KeyboardInterrupt:
            sys.exit(0)

    result = detector.analyze(text)
    print(json.dumps(result, indent=2))
