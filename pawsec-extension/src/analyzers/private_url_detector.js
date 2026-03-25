/**
 * PawSec in-browser private URL detector.
 * Ports the Python private-url-detector skill for offline use.
 */

const PRIVATE_PATTERNS = [
  // Cloud metadata — CRITICAL
  { name: 'AWS_IMDS',     risk: 'CRITICAL', re: /https?:\/\/169\.254\.169\.254\b/gi },
  { name: 'GCP_metadata', risk: 'CRITICAL', re: /https?:\/\/metadata\.google\.internal\b/gi },
  { name: 'Azure_metadata',risk:'CRITICAL', re: /https?:\/\/169\.254\.169\.254\/metadata\b/gi },
  // Localhost
  { name: 'localhost',    risk: 'HIGH',     re: /https?:\/\/(?:localhost|127\.0\.0\.1|0\.0\.0\.0)(?::\d+)?(?:\/[^\s]*)?/gi },
  // IPv6 loopback
  { name: 'ipv6_loopback',risk: 'HIGH',     re: /https?:\/\/\[::1\](?::\d+)?/gi },
  // RFC-1918 private IPs
  { name: 'private_ip_10',   risk: 'HIGH',  re: /https?:\/\/10\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/gi },
  { name: 'private_ip_172',  risk: 'HIGH',  re: /https?:\/\/172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?/gi },
  { name: 'private_ip_192',  risk: 'HIGH',  re: /https?:\/\/192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?/gi },
  // Link-local
  { name: 'link_local',   risk: 'HIGH',     re: /https?:\/\/169\.254\.\d{1,3}\.\d{1,3}(?::\d+)?/gi },
  // Internal TLDs
  { name: 'internal_tld', risk: 'MEDIUM',   re: /https?:\/\/[a-zA-Z0-9][\w.\-]*\.(?:internal|corp|intra|local|lan|private|int)\b(?::\d+)?/gi },
  // Staging/dev subdomains
  { name: 'staging_host', risk: 'MEDIUM',   re: /https?:\/\/(?:[a-zA-Z0-9\-]+\.)*(?:staging|stage|dev|test|uat|sandbox|preprod)\.[a-zA-Z0-9][\w.\-]+(?::\d+)?/gi },
  // Kubernetes svc
  { name: 'k8s_svc',      risk: 'HIGH',     re: /https?:\/\/[a-zA-Z0-9\-]+\.[a-zA-Z0-9\-]+\.svc\.cluster\.local\b/gi },
  // SMB / UNC paths
  { name: 'smb_path',     risk: 'HIGH',     re: /\\\\[A-Za-z0-9](?:[A-Za-z0-9\-_]{0,61}[A-Za-z0-9])?(?:\\[A-Za-z0-9_\-\. ]+)+/g },
  // SMB URL
  { name: 'smb_url',      risk: 'HIGH',     re: /smb:\/\/[A-Za-z0-9.\-]+(?:\/[^\s"'<>]*)?/gi },
  // NFS mount path
  { name: 'nfs_url',      risk: 'HIGH',     re: /nfs:\/\/[A-Za-z0-9.\-]+(?:\/[^\s"'<>]*)?/gi },
];

/**
 * @param {string} text
 * @returns {{ detected: boolean, urls_found: Array, count: number, risk_level: string }}
 */
export function analyzePrivateURLs(text) {
  const found = [];
  const riskOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

  for (const { name, risk, re } of PRIVATE_PATTERNS) {
    re.lastIndex = 0;
    const matches = [...text.matchAll(re)];
    for (const m of matches) {
      // Mask everything after host:port
      const url = m[0];
      const masked = url.replace(/(https?:\/\/[^\/?#]*)(.*)/, (_, host, path) =>
        host + (path ? '/█…' : ''));
      found.push({ type: name, risk, url_masked: masked });
    }
    re.lastIndex = 0;
  }

  const maxRisk = found.reduce((acc, f) => {
    return (riskOrder[f.risk] ?? 0) > (riskOrder[acc] ?? 0) ? f.risk : acc;
  }, 'SAFE');

  return {
    detected:   found.length > 0,
    urls_found: found,
    count:      found.length,
    risk_level: found.length ? maxRisk : 'SAFE',
  };
}
