"""
Private URL Detector
Detects URLs pointing to internal infrastructure: localhost, RFC-1918 private
IP ranges, staging/dev/internal hostnames, Kubernetes service endpoints,
VPN/intranet addresses, and internal file share paths.
"""

import re
import json
from datetime import datetime
from typing import Dict, List


class PrivateURLDetector:
    """Detects internal/private URLs and network paths."""

    def __init__(self):
        self._patterns = self._load_patterns()

    def _load_patterns(self) -> List[Dict]:
        return [
            # ── Localhost / Loopback ─────────────────────────────────────────────
            {
                "type": "localhost",
                "name": "Localhost URL",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "ipv6_loopback",
                "name": "IPv6 Loopback URL",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://\[::1\](?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            # ── RFC-1918 Private IP Ranges in URLs ───────────────────────────────
            {
                "type": "private_ip_192",
                "name": "Private Network URL (192.168.x.x)",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "private_ip_10",
                "name": "Private Network URL (10.x.x.x)",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "private_ip_172",
                "name": "Private Network URL (172.16-31.x.x)",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "link_local",
                "name": "Link-Local Address URL (169.254.x.x)",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://169\.254\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            # ── Internal / Corporate Hostnames ───────────────────────────────────
            {
                "type": "internal_tld",
                "name": "Internal Hostname (.internal/.corp/.intra/.local)",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?'
                    r'(?:\.[A-Za-z0-9\-]+)*'
                    r'\.(?:internal|corp|intra|local|lan|private|int|home)\b'
                    r'(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            # ── Staging / Dev / Test Environments ───────────────────────────────
            {
                "type": "staging_env",
                "name": "Staging/Dev/Test Environment URL",
                "risk": "MEDIUM",
                "pattern": re.compile(
                    r'https?://[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?'
                    r'(?:\.[A-Za-z0-9\-]+)*'
                    r'\.(?:staging|stage|dev|develop|test|testing|uat|'
                    r'qa|sandbox|preprod|pre-prod|demo|beta|alpha|rc)\.'
                    r'[A-Za-z0-9\-\.]+(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "staging_prefix",
                "name": "Staging/Dev Subdomain URL",
                "risk": "MEDIUM",
                "pattern": re.compile(
                    r'https?://(?:staging|stage|dev|develop|test|qa|uat|sandbox|preprod|'
                    r'pre-prod|demo|beta|alpha|rc)-?[A-Za-z0-9\-]*'
                    r'\.[A-Za-z0-9\-\.]+(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            # ── Kubernetes Service URLs ───────────────────────────────────────────
            {
                "type": "kubernetes_service",
                "name": "Kubernetes Service URL",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://[A-Za-z0-9\-]+\.(?:[A-Za-z0-9\-]+\.)?'
                    r'svc\.cluster\.local(?::\d+)?(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "k8s_pod_ip",
                "name": "Kubernetes Pod IP URL",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'https?://\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}'
                    r'\.(?:[A-Za-z0-9\-]+\.)?svc\.cluster\.local',
                    re.IGNORECASE
                )
            },
            # ── Internal File Shares & Protocols ─────────────────────────────────
            {
                "type": "smb_share",
                "name": "SMB/Windows File Share Path",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'\\\\[A-Za-z0-9](?:[A-Za-z0-9\-_]{0,61}[A-Za-z0-9])?'
                    r'(?:\\[A-Za-z0-9_\-\. ]+)+',
                    re.IGNORECASE
                )
            },
            {
                "type": "smb_url",
                "name": "SMB URL",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'smb://[A-Za-z0-9.\-]+(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "nfs_url",
                "name": "NFS Mount Path",
                "risk": "HIGH",
                "pattern": re.compile(
                    r'nfs://[A-Za-z0-9.\-]+(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            # ── Cloud Metadata Endpoints ─────────────────────────────────────────
            {
                "type": "aws_metadata",
                "name": "AWS Instance Metadata URL",
                "risk": "CRITICAL",
                "pattern": re.compile(
                    r'https?://169\.254\.169\.254(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "gcp_metadata",
                "name": "GCP Instance Metadata URL",
                "risk": "CRITICAL",
                "pattern": re.compile(
                    r'https?://metadata\.google\.internal(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
            {
                "type": "azure_metadata",
                "name": "Azure Instance Metadata URL",
                "risk": "CRITICAL",
                "pattern": re.compile(
                    r'https?://169\.254\.169\.254/metadata(?:/[^\s"\'<>]*)?',
                    re.IGNORECASE
                )
            },
        ]

    @staticmethod
    def _mask_url(url: str) -> str:
        """Mask the hostname/IP portion of a URL."""
        # Replace the host part with asterisks preserving scheme and path structure
        host_pattern = re.compile(
            r'(https?://)([^/\s"\'<>:]+)((?::\d+)?(?:/.*)?)?',
            re.IGNORECASE
        )
        match = host_pattern.match(url)
        if match:
            scheme = match.group(1)
            host = match.group(2)
            rest = match.group(3) or ""
            masked_host = host[:3] + '*' * max(0, len(host) - 3)
            return scheme + masked_host + rest
        return url[:6] + '***'

    def analyze(self, text: str) -> Dict:
        """Analyze text for private/internal URLs."""
        urls_found = []
        seen_positions = []

        for spec in self._patterns:
            for match in spec["pattern"].finditer(text):
                pos = match.start()

                # Deduplicate nearby matches
                if any(abs(pos - p) < 5 for p in seen_positions):
                    continue
                seen_positions.append(pos)

                raw_url = match.group(0)
                urls_found.append({
                    "type": spec["type"],
                    "name": spec["name"],
                    "risk": spec["risk"],
                    "url_masked": self._mask_url(raw_url),
                    "position": pos
                })

        # Determine overall risk
        if urls_found:
            risks = [u["risk"] for u in urls_found]
            if "CRITICAL" in risks:
                risk_level = "CRITICAL"
            elif "HIGH" in risks:
                risk_level = "HIGH"
            else:
                risk_level = "MEDIUM"
        else:
            risk_level = "SAFE"

        return {
            "detected": len(urls_found) > 0,
            "urls_found": urls_found,
            "count": len(urls_found),
            "risk_level": risk_level,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

    def analyze_batch(self, texts: List[str]) -> List[Dict]:
        return [self.analyze(t) for t in texts]


# ── CLI entry point ──────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    detector = PrivateURLDetector()

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
