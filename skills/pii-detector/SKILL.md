---
name: pii-detector
description: Comprehensive PII and PHI detection using pattern matching with smart masking capabilities
version: 1.0.0
author: Security Analysis Team
tags: [security, pii, phi, privacy, data-protection, hipaa, gdpr]
---

# PII/PHI Detection Skill

## Overview

This skill detects Personally Identifiable Information (PII) and Protected Health Information (PHI) in text using comprehensive pattern matching. It supports 15+ data types with smart masking capabilities that preserve partial information for audit trails while protecting sensitive data.

## Capabilities

- **15+ PII/PHI Types**: Email, phone, SSN, credit cards, medical records, IP addresses, API keys, and more
- **Smart Masking**: Context-aware masking that preserves format while hiding sensitive data
- **Pattern Matching**: Regex-based detection optimized for accuracy
- **International Support**: US and international phone numbers, passports, and date formats
- **Healthcare Focus**: Medical record numbers, insurance IDs, patient identifiers
- **Financial Data**: Credit cards, bank accounts, routing numbers
- **Technical PII**: IP addresses, API keys, tokens, credentials
- **Audit Trail**: Returns original values with masked equivalents for compliance logging

## Detected PII/PHI Types

### Personal Identifiers
- **Email Address**: Standard email format validation
- **Phone Number**: US format (XXX-XXX-XXXX)
- **International Phone**: +X XXX-XXX-XXXX format
- **Social Security Number**: XXX-XX-XXXX format
- **Date of Birth**: Multiple date formats (MM/DD/YYYY, DD-MM-YYYY, etc.)
- **Passport Number**: International passport formats

### Financial Information
- **Credit Card**: 16-digit card numbers with optional separators
- **Bank Account**: Account number patterns
- **Routing Number**: 9-digit routing numbers

### Healthcare Information (PHI)
- **Medical Record Number**: MRN patterns
- **Insurance ID**: Health insurance identifiers
- **Patient ID**: Hospital/clinic patient identifiers
- **Prescription Number**: Rx number patterns

### Location Data
- **Street Address**: US address patterns
- **ZIP Code**: 5-digit and ZIP+4 formats

### Technical Identifiers
- **IP Address**: IPv4 addresses
- **API Key/Token**: 32+ character alphanumeric strings
- **MAC Address**: Network hardware addresses

## Usage

### Basic Detection

```python
from tools.pii_detector import PIIDetector

detector = PIIDetector()
result = detector.detect_pii("My email is john@example.com and SSN is 123-45-6789")

print(f"Found {result['count']} PII items")
print(f"Masked text: {result['masked_text']}")

for item in result['detected']:
    print(f"- {item['name']}: {item['value']} -> {item['masked']}")
```

### Detection Only (No Masking)

```python
result = detector.detect_pii(text, mask=False)
print(f"PII found: {result['has_pii']}")
print(f"Types: {list(result['pii_counts'].keys())}")
```

### Custom Masking Strategy

```python
result = detector.detect_pii(text, masking_strategy='full')  # Options: 'smart', 'full', 'partial'
```

## Tool Dependencies

- **pii_detector.py**: Core detection engine with pattern library and masking logic

## Input Requirements

- **text** (string): The text to analyze for PII/PHI
- **mask** (optional, boolean): Whether to return masked text. Default: True
- **masking_strategy** (optional, string): 'smart' (default), 'full', or 'partial'
- **include_types** (optional, list): Specific PII types to detect. Default: all types

## Output Format

```json
{
  "detected": [
    {
      "type": "email",
      "name": "Email Address",
      "value": "john@example.com",
      "masked": "j***@example.com",
      "position": 12,
      "confidence": 0.95
    }
  ],
  "masked_text": "My email is j***@example.com and SSN is ***-**-6789",
  "pii_counts": {
    "Email Address": 1,
    "Social Security Number": 1
  },
  "has_pii": true,
  "count": 2,
  "risk_level": "HIGH"
}
```

## Masking Strategies

### Smart Masking (Default)
- **Email**: Shows first letter + domain (`j***@example.com`)
- **Phone**: Shows last 4 digits (`***-***-1234`)
- **SSN**: Shows last 4 digits (`***-**-6789`)
- **Credit Card**: Shows last 4 digits (`****-****-****-1234`)
- **IP Address**: Shows first octet (`192.*.*.*`)

### Full Masking
- Replaces entire value with asterisks: `***`

### Partial Masking
- Shows first and last 2 characters: `jo****om`

## Security Considerations

- **No External API Calls**: All detection is performed locally
- **No Data Storage**: Does not log or store detected PII/PHI
- **Compliance Ready**: Supports HIPAA, GDPR, CCPA requirements
- **Audit Trail**: Original values returned for secure logging (use carefully)
- **False Positive Handling**: May flag non-PII matching patterns
- **Regular Expression Safety**: Protected against ReDoS attacks

## Integration with Other Skills

This skill works seamlessly with:
- **prompt-injection-detector**: Combined security and privacy analysis
- **context-analyzer**: Understand why PII is present
- **intent-detector**: Identify if PII disclosure is intentional
- **risk-score-calculator**: Factor PII count into risk assessment

## Best Practices

1. **Always Mask for Display**: Use masked_text when showing results to users
2. **Secure Audit Logs**: Store original values only in secure, compliant systems
3. **Review False Positives**: Not all matches are genuine PII (e.g., "1-800-CALL-NOW")
4. **Context Matters**: "Call me at 555-1234" vs. actual phone number
5. **Combine Detection**: Use multiple methods for high-stakes applications
6. **Regular Updates**: Add new patterns as PII formats evolve
7. **GDPR/HIPAA**: Consult legal team for compliance requirements

## Error Handling

- Returns empty detection list for empty input
- Handles Unicode and special characters
- Does not crash on malformed patterns
- Provides confidence scores for ambiguous matches

## Performance

- **Speed**: Millisecond-level analysis for text up to 100KB
- **Memory**: Minimal footprint (<5MB)
- **Scalability**: Can process thousands of documents per second

## Limitations

- **Pattern-Based Only**: Cannot understand semantic PII (e.g., "my mother's maiden name is Smith")
- **English-Centric**: Optimized for US formats; limited international coverage
- **Format Dependency**: Requires standardized formats (e.g., SSN with hyphens)
- **No NER**: Does not use Named Entity Recognition for names/places
- **Context-Blind**: Cannot distinguish between example PII and real PII

## Enhanced Features (Beyond Base Implementation)

This skill includes improvements over the original application:

1. **Medical Record Numbers**: MRN, Patient ID, Insurance ID detection
2. **Bank Account Numbers**: Financial account identification
3. **Confidence Scoring**: Each detection includes confidence level
4. **Risk Level Assessment**: Overall risk based on PII type and count
5. **Improved International Phone**: Better regex for global formats
6. **MAC Address Detection**: Network hardware identifiers
7. **ZIP Code Extraction**: 5-digit and ZIP+4 formats
8. **Enhanced API Key Detection**: Improved token/credential patterns

## Examples

### Example 1: Email and Phone

**Input:**
```
Contact me at alice@company.com or call 555-123-4567
```

**Output:**
```
Detected: 2 PII items
- Email Address: alice@company.com -> a***@company.com
- Phone Number: 555-123-4567 -> ***-***-4567
Masked: Contact me at a***@company.com or call ***-***-4567
```

### Example 2: Healthcare Data (PHI)

**Input:**
```
Patient MRN: 987654, Insurance: BC-123456789, DOB: 01/15/1980
```

**Output:**
```
Detected: 3 PHI items
- Medical Record Number: 987654 -> ****54
- Insurance ID: BC-123456789 -> BC-******789
- Date of Birth: 01/15/1980 -> **/**/****
Risk Level: HIGH (PHI detected)
```

### Example 3: No PII

**Input:**
```
What are the best practices for data security?
```

**Output:**
```
Detected: 0 PII items
Has PII: False
```

## Compliance Notes

- **HIPAA**: Detects 18 HIPAA identifiers where pattern-based detection applies
- **GDPR**: Covers personal data categories requiring protection
- **CCPA**: Identifies California Consumer Privacy Act personal information
- **PCI DSS**: Detects payment card information

## Changelog

### v1.0.0 (2026-02-26)
- Initial release with 15+ PII/PHI types
- Smart masking with context-aware strategies
- Confidence scoring and risk level assessment
- Enhanced healthcare and financial data support

## License

This skill is provided for privacy protection and compliance purposes only.

## Support

For issues or enhancement requests, contact the Security Analysis Team.
