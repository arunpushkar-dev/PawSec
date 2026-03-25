# API Secrets & Token Detector

Detects service-specific API keys, authentication tokens, cryptographic private keys, JWT tokens, and database connection strings across 40+ cloud services and platforms.

## Detection Coverage

### Cloud Service API Keys (40+ services)
- **AWS**: Access Key IDs (AKIA/ASIA prefix), Secret Access Keys, Session Tokens
- **OpenAI**: `sk-` and `sk-proj-` format keys
- **Anthropic**: `sk-ant-api` format keys
- **GitHub**: Personal Access Tokens (ghp_), Fine-grained tokens, OAuth/App tokens
- **Stripe**: Live/Test secret keys (`sk_live_`, `sk_test_`), Restricted keys, Webhook secrets
- **Google Cloud**: API Keys (`AIza` prefix), OAuth Client Secrets
- **HuggingFace**: API tokens (`hf_` prefix)
- **Twilio**: Account SIDs and Auth Tokens
- **Slack**: Bot/User/App/Legacy tokens (xoxb-, xoxp-, xapp-, xoxa-)
- **SendGrid**: API keys (`SG.` prefix)
- **Azure**: Connection strings, Client secrets
- **Heroku**: UUID-format API keys
- **Cloudflare**: API tokens
- **DigitalOcean**: Personal access tokens (`dop_v1_`)
- **Mailgun**: API keys (`key-` prefix)
- **Mailchimp**: API keys with datacenter suffix
- **Shopify**: Admin/Custom app tokens
- **npm**: Access tokens (`npm_`)
- **PyPI**: API tokens (`pypi-`)
- **Datadog**: API keys
- **PagerDuty**: API keys
- **HashiCorp Vault**: Tokens

### Cryptographic Keys
- RSA Private Keys (`-----BEGIN RSA PRIVATE KEY-----`)
- EC Private Keys
- OpenSSH Private Keys
- Generic Private Keys
- PGP Private Key Blocks

### JWT Tokens
- Standard three-part JWT format (`eyJ...`)

### Database Connection Strings with Credentials
- PostgreSQL, MySQL, MongoDB, Redis, JDBC

### High-Entropy Secret Detection
- Generic secrets in `key=value` / `secret: "..."` context with Shannon entropy ≥ 4.5 bits/char

## Output Format
```json
{
  "threat_detected": true,
  "secrets_found": [
    {
      "service": "AWS",
      "type": "Access Key ID",
      "severity": "CRITICAL",
      "matched_value_masked": "AKIA****EXAMPLE",
      "position": 42
    }
  ],
  "count": 1,
  "risk_level": "CRITICAL",
  "timestamp": "2026-03-18T10:00:00Z"
}
```

## Risk Levels
| Level | Condition |
|-------|-----------|
| SAFE | No secrets detected |
| MEDIUM | Low-severity matches only |
| HIGH | Service token detected |
| CRITICAL | Production key, private key, or DB connection string |

## Usage
```python
from tools.api_secrets_detector import APISecretsDetector

detector = APISecretsDetector()
result = detector.analyze("My OpenAI key is sk-abcdef...")
print(result["risk_level"])  # CRITICAL
```

## Performance
- Pure Python regex, no external dependencies
- < 50ms for typical prompts (< 10,000 characters)
