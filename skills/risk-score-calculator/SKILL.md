---
name: risk-score-calculator
description: Calculates weighted risk scores from multiple security analysis results
version: 1.0.0
author: Security Analysis Team
tags: [security, risk-assessment, scoring, threat-intelligence]
---

# Risk Score Calculator Skill

## Overview

This skill calculates a weighted risk score (0-100) by combining results from multiple security analyzers. It implements the official weight distribution: Injection (40%), Llama Guard (25%), Context (20%), PII (15%).

## Capabilities

- **Weighted Scoring**: Industry-standard weight distribution
- **Multi-Factor Analysis**: Combines 4 security dimensions
- **0-100 Scale**: Normalized risk score
- **Risk Level Classification**: SAFE (<30), MEDIUM (30-50), HIGH (50-70), CRITICAL (70+)
- **Component Breakdown**: Shows contribution of each factor
- **Customizable Weights**: Override default weights if needed

## Weight Distribution

| Component | Weight | Points | Purpose |
|-----------|--------|--------|---------|
| **Prompt Injection** | 40% | 0-40 | Pattern-based injection detection |
| **Llama Guard** | 25% | 0-25 | Semantic safety classification |
| **Context Analysis** | 20% | 0-20 | Contextual risk assessment |
| **PII Detection** | 15% | 0-15 | Privacy data exposure |
| **Total** | 100% | 0-100 | Combined risk score |

## Scoring Logic

### Prompt Injection (0-40 points)
- **40 points**: CRITICAL severity findings detected
- **30 points**: HIGH severity findings detected
- **20 points**: Any findings detected (MEDIUM/LOW)
- **0 points**: No findings

### Llama Guard (0-25 points)
- **25 points**: Verdict = UNSAFE
- **13 points**: Verdict = WARNING
- **0 points**: Verdict = SAFE or ERROR

### Context Analysis (0-20 points)
- **20 points**: Intent risk = Malicious
- **10 points**: Intent risk = Neutral
- **5 points**: 3+ suspicious indicators
- **0 points**: Intent risk = Benign

### PII Detection (0-15 points)
- **15 points**: 4+ PII items detected
- **count × 4 points**: 1-3 PII items (capped at 15)
- **0 points**: No PII detected

## Usage

### Basic Calculation

```python
from tools.risk_calculator import RiskCalculator

calculator = RiskCalculator()

# Results from other skills
injection_results = {'has_critical': True, 'has_high': False, 'count': 2}
llama_results = {'is_unsafe': False, 'has_warning': False}
context_results = {'primary_intent': {'risk': 'Neutral'}, 'indicators': []}
pii_results = {'count': 1}

score = calculator.calculate_risk(
    injection=injection_results,
    llama_guard=llama_results,
    context=context_results,
    pii=pii_results
)

print(f"Risk Score: {score['total_score']}")
print(f"Risk Level: {score['risk_level']}")
print(f"Breakdown: {score['breakdown']}")
```

### With Custom Weights

```python
custom_weights = {
    'injection': 50,
    'llama_guard': 20,
    'context': 15,
    'pii': 15
}

score = calculator.calculate_risk(
    injection=injection_results,
    llama_guard=llama_results,
    context=context_results,
    pii=pii_results,
    weights=custom_weights
)
```

## Output Format

```json
{
  "total_score": 65,
  "risk_level": "HIGH",
  "breakdown": {
    "injection": {
      "score": 40,
      "weight": 40,
      "reason": "CRITICAL severity findings detected"
    },
    "llama_guard": {
      "score": 0,
      "weight": 25,
      "reason": "Llama Guard verdict: SAFE"
    },
    "context": {
      "score": 10,
      "weight": 20,
      "reason": "Intent risk: Neutral"
    },
    "pii": {
      "score": 4,
      "weight": 15,
      "reason": "1 PII item detected"
    }
  },
  "recommendations": [
    "CRITICAL: Severe security risks detected. Do not use in production.",
    "Review injection patterns immediately."
  ]
}
```

## Risk Levels

- **SAFE** (0-29): Low risk, minimal concerns
- **MEDIUM** (30-49): Moderate risk, review recommended
- **HIGH** (50-69): Significant risk, careful review required
- **CRITICAL** (70-100): Severe risk, do not use in production

## Tool Dependencies

- **risk_calculator.py**: Core calculation engine with weight management

## Input Requirements

All parameters are optional but providing more data improves accuracy:

- **injection** (dict): Results from prompt-injection-detector
- **llama_guard** (dict): Results from llama-guard-integration
- **context** (dict): Results from context-analyzer
- **pii** (dict): Results from pii-detector
- **weights** (dict, optional): Custom weight distribution

## Security Considerations

- **Weight Validation**: Weights must sum to 100
- **Component Validation**: Invalid inputs default to 0 score
- **Deterministic**: Same inputs always produce same score
- **No External Calls**: Pure calculation, no API dependencies

## Integration with Other Skills

This skill **requires** integration with:
1. **prompt-injection-detector**: Provides injection findings
2. **llama-guard-integration**: Provides safety verdict
3. **context-analyzer**: Provides context and intent
4. **pii-detector**: Provides PII detections

## Best Practices

1. **Use All Analyzers**: Risk score is most accurate with complete data
2. **Don't Modify Weights Without Reason**: Default distribution is research-backed
3. **Review Breakdown**: Understand which factors contribute most
4. **Combine with Human Review**: Score is guidance, not gospel
5. **Set Thresholds Per Use Case**: Safe for research ≠ safe for production
6. **Track Score Over Time**: Monitor if prompts are getting riskier

## Error Handling

- Returns 0 score for missing/invalid inputs
- Validates weight distribution sums to 100
- Handles missing keys in result dictionaries
- Does not crash on malformed data

## Performance

- **Speed**: Microsecond-level calculation
- **Memory**: Negligible (<1MB)
- **Scalability**: Can calculate millions of scores per second

## Limitations

- **Linear Combination**: Does not account for factor interactions
- **Fixed Weights**: Not adaptive to specific use cases
- **No Learning**: Does not improve over time
- **Component Dependency**: Accuracy depends on input quality

## Examples

### Example 1: Critical Injection

**Input:**
```python
injection = {'has_critical': True, 'count': 3}
llama_guard = {'is_unsafe': True}
context = {'primary_intent': {'risk': 'Malicious'}, 'indicators': ['system-level']}
pii = {'count': 0}
```

**Output:**
```
Total Score: 85
Risk Level: CRITICAL
Breakdown:
  - Injection: 40/40 (CRITICAL findings)
  - Llama Guard: 25/25 (UNSAFE)
  - Context: 20/20 (Malicious intent)
  - PII: 0/15 (No PII)
```

### Example 2: Safe Prompt

**Input:**
```python
injection = {'has_critical': False, 'has_high': False, 'count': 0}
llama_guard = {'is_unsafe': False, 'has_warning': False}
context = {'primary_intent': {'risk': 'Benign'}, 'indicators': []}
pii = {'count': 0}
```

**Output:**
```
Total Score: 0
Risk Level: SAFE
```

### Example 3: PII Exposure Only

**Input:**
```python
injection = {'count': 0}
llama_guard = {'is_unsafe': False}
context = {'primary_intent': {'risk': 'Benign'}, 'indicators': []}
pii = {'count': 5}
```

**Output:**
```
Total Score: 15
Risk Level: SAFE
Breakdown:
  - PII: 15/15 (5 PII items detected)
```

## Changelog

### v1.0.0 (2026-02-26)
- Initial release with weighted scoring
- Default weight distribution: 40/25/20/15
- Risk level classification
- Component breakdown and recommendations

## License

This skill is provided for security risk assessment purposes only.

## Support

For issues or enhancement requests, contact the Security Analysis Team.
