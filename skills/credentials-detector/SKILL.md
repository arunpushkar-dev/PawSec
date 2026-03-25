# Credentials Detector

Detects passwords, secrets, and authentication credentials in configuration formats, environment files, JSON payloads, HTTP headers, and hardcoded source code patterns.

## Detection Coverage

### Environment / Config File Patterns
- Variables: `PASSWORD=`, `PASSWD=`, `SECRET_KEY=`, `API_SECRET=`, `DB_PASSWORD=`, etc.
- Detects `KEY=VALUE` assignments with sensitive key names
- Suppresses common placeholder values (e.g., `changeme`, `password123`, `<password>`)

### JSON Credential Fields
- `"password": "..."`, `"secret": "..."`, `"api_key": "..."`, `"access_token": "..."`
- `"credentials": {...}` objects

### HTTP Authorization Headers
- `Authorization: Basic <base64>` — decoded Basic Auth
- `Authorization: Bearer <token>`

### DSN / Connection String Credentials
- `password=value` within DSN/connection strings
- Pattern: `host=... user=... password=...`

### Hardcoded Credentials in Source Code
- `String password = "..."` (Java/C#)
- `let password = "..."` (JS/TypeScript)
- `const secret = "..."` patterns

### SMTP / Email Credentials
- `smtp_password=`, `mail_password=`

### HTTP/CLI Embedded Credentials
- `curl -u user:password` patterns

## Output Format
```json
{
  "detected": true,
  "findings": [
    {
      "type": "json_password",
      "name": "JSON Password Field",
      "severity": "CRITICAL",
      "value_masked": "se**",
      "context_snippet": "...\"password\": \"secret123\"...",
      "position": 15
    }
  ],
  "count": 1,
  "risk_level": "CRITICAL"
}
```

## Risk Levels
| Level | Condition |
|-------|-----------|
| SAFE | No credentials detected |
| MEDIUM | Low-confidence match |
| HIGH | Key-value secret assignment |
| CRITICAL | JSON password field, Basic Auth header, hardcoded password |

## Usage
```python
from tools.credentials_detector import CredentialsDetector

detector = CredentialsDetector()
result = detector.analyze('DB_PASSWORD=hunter2')
print(result["risk_level"])  # CRITICAL
```

## Performance
- Pure Python regex, no external dependencies
- < 30ms for typical prompts
