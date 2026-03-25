# Private URL Detector

Detects URLs and network paths pointing to internal infrastructure that should never be shared externally: localhost, RFC-1918 private IP ranges, internal corporate hostnames, staging/dev environments, Kubernetes service endpoints, and cloud metadata APIs.

## Detection Coverage

### Loopback / Localhost
- `http://localhost:*`, `http://127.0.0.1:*`, `http://0.0.0.0:*`
- `http://[::1]:*` (IPv6 loopback)

### RFC-1918 Private IP Ranges in URLs
- `192.168.x.x` (Class C private)
- `10.x.x.x` (Class A private)
- `172.16.x.x – 172.31.x.x` (Class B private)
- `169.254.x.x` (Link-local / APIPA)

### Internal / Corporate Hostnames
- TLDs: `.internal`, `.corp`, `.intra`, `.local`, `.lan`, `.private`, `.int`, `.home`

### Staging / Development Environments
- Subdomain patterns: `staging.`, `dev.`, `test.`, `uat.`, `sandbox.`, `preprod.`, `qa.`
- Prefix patterns: `staging-`, `dev-`, `test-` subdomains

### Kubernetes / Container Environments
- `*.svc.cluster.local` service DNS
- Pod IP URL patterns

### Internal File Shares
- UNC paths: `\\server\share`
- SMB URLs: `smb://server/path`
- NFS mounts: `nfs://server/path`

### Cloud Metadata APIs (CRITICAL)
- AWS: `169.254.169.254` IMDS endpoint
- GCP: `metadata.google.internal`
- Azure: `169.254.169.254/metadata`

## Output Format
```json
{
  "detected": true,
  "urls_found": [
    {
      "type": "localhost",
      "name": "Localhost URL",
      "risk": "HIGH",
      "url_masked": "htt***://loc***:8080/api/users",
      "position": 23
    }
  ],
  "count": 1,
  "risk_level": "HIGH"
}
```

## Usage
```python
from tools.private_url_detector import PrivateURLDetector

detector = PrivateURLDetector()
result = detector.analyze("API endpoint is http://192.168.1.100:8080/api")
print(result["risk_level"])  # HIGH
```
