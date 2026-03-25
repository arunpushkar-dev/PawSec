# Business Data Detector

Detects business-specific identifiers: US EIN, DUNS numbers, EU VAT numbers, UK company registration numbers, Australian ABN/ACN, Canadian BN, and US driver's licenses across all 50 states.

## Detection Coverage

### US Business Identifiers
- **EIN (Employer Identification Number)**: `XX-XXXXXXX` format with context (EIN, FEIN, Federal Tax ID, Employer Identification)
- **DUNS Number**: 9-digit identifier with DUNS/Dun & Bradstreet context

### European Union VAT Numbers
Full coverage of all 27 EU member states (AT, BE, BG, CY, CZ, DE, DK, EE, EL, ES, FI, FR, HR, HU, IE, IT, LT, LU, LV, MT, NL, PL, PT, RO, SE, SI, SK) with country-specific format validation.

### United Kingdom
- Company Registration Number (Companies House format)

### Australia
- ABN (Australian Business Number) — 11-digit format
- ACN (Australian Company Number) — 9-digit format

### Canada
- Business Number (BN) with program identifier suffix (RT/RP/RC/RZ)

### US Driver's Licenses (All 50 States)
State-specific patterns with context requirement (requires "driver's license", "DLN", "license number", "DL", or "state ID" within 150 characters):
- All 50 US states with validated format patterns
- Requires context keywords to trigger detection

## Output Format
```json
{
  "detected": true,
  "findings": [
    {
      "type": "ein",
      "name": "US Employer Identification Number (EIN)",
      "jurisdiction": "United States",
      "severity": "HIGH",
      "value_masked": "12**456",
      "position": 10
    }
  ],
  "count": 1,
  "risk_level": "HIGH"
}
```

## Usage
```python
from tools.business_data_detector import BusinessDataDetector

detector = BusinessDataDetector()
result = detector.analyze("Our EIN is 12-3456789 for tax filings")
print(result["risk_level"])  # HIGH
```
