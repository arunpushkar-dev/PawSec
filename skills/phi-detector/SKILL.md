---
name: phi-detector
description: HIPAA-compliant Protected Health Information (PHI) detection with zero overlap with general PII detection, covering all 18 HIPAA Safe Harbor identifiers plus sensitive health conditions, medications, and clinical data
version: 1.0.0
author: Security Analysis Team
tags: [security, phi, hipaa, healthcare, privacy, compliance, health-data]
---

# PHI Detector Skill

## Overview

This skill detects **Protected Health Information (PHI)** as defined under HIPAA (Health Insurance Portability and Accountability Act, 45 CFR §164.514). It is designed with **zero overlap** with the `pii-detector` skill — it exclusively targets health-specific identifiers, clinical data, and sensitive health conditions that constitute PHI under HIPAA's 18 Safe Harbor identifiers.

PHI is defined as individually identifiable health information that relates to:
1. An individual's past, present, or future physical or mental health or condition
2. The provision of health care to an individual
3. The past, present, or future payment for health care

**Key distinction from PII**: PHI requires a health context linkage. This detector confirms personal linkage via a 250-character context window before flagging clinical patterns.

## What This Skill Does NOT Detect (Handled by pii-detector)

To avoid duplication:
- Social Security Numbers (SSN)
- Email addresses
- Phone numbers (US and international)
- Passports
- Dates of birth
- Credit card numbers
- Bank account numbers
- Medical Record Numbers (MRN — format: MRN-XXXXXX or numeric)
- Insurance IDs (BC-XXXXXXXXX format)
- Street addresses
- ZIP codes
- IP addresses
- API keys / tokens
- MAC addresses

## What This Skill Detects (HIPAA-Specific PHI)

### Administrative Health Identifiers

| Identifier | HIPAA Category | Example |
|-----------|----------------|---------|
| NPI (National Provider Identifier) | Provider | `NPI: 1234567890` |
| DEA Registration Number | Provider | `DEA: AB1234567` |
| Health Plan Beneficiary Number | Beneficiary | `Member ID: M-12345678` |
| Health Insurance Group Number | Plan | `Group Policy: GP-987654` |
| Prescription Number (Rx) | Pharmacy | `Rx#: 7890123456` |
| Lab Accession Number | Laboratory | `ACC: LAB-20240315-001` |
| Radiology/Pathology Order | Imaging | `RAD-ORDER: 2024-98765` |
| Medical Device UDI (FDA) | Device | `UDI: (01)00844588003288` |
| CPT Procedure Code | Billing | `CPT: 99213` |
| HCPCS Level II Code | Billing | `HCPCS: G0438` |
| NDC Drug Code | Pharmacy | `NDC: 0069-0154-66` |
| Clinical Trial ID | Research | `NCT12345678` |
| Medical Encounter Number | Facility | `Encounter: ENC-2024-001` (requires context) |
| ICD-10 Diagnosis Code | Clinical | `Diagnosis: E11.9` (requires label) |
| Age Over 89 | Demographics | `92 year-old patient` |
| Medical Event Dates | Dates | `admitted on 2024-03-15` |
| Biometric Health Identifier | Biometric | requires health context |
| Clinical Notes | Documentation | `CC: chest pain` / `HPI:` / `SOAP:` |
| Patient Name in Health Context | Identity | `Patient Name: John Smith` |

### Sensitive Health Conditions (45 CFR §164.514 + 42 CFR Part 2)

These categories receive **CRITICAL** severity due to heightened legal protection:

| Condition Category | Regulatory Basis | Examples |
|-------------------|------------------|---------|
| Mental Health | HIPAA + State laws | Depression, bipolar, schizophrenia, PTSD, OCD, ADHD, autism, suicidal ideation |
| Substance Use Disorder (SUD) | 42 CFR Part 2 | OUD, AUD, MAT, buprenorphine, methadone, naltrexone |
| HIV/AIDS Status | HIPAA + State laws | HIV+, CD4 count, viral load, ART, PrEP, PEP |
| Sexually Transmitted Infections | HIPAA | Gonorrhea, chlamydia, syphilis, HSV, HPV |
| Genetic Information | HIPAA Omnibus 2013 | BRCA mutation, Lynch syndrome, Huntington's, chromosomal abnormalities |
| Reproductive Health | HIPAA + State laws | Pregnancy, abortion, IVF, fertility treatments |
| Serious Chronic Conditions | HIPAA | T2DM, CHF, CAD, COPD, MS, ALS, epilepsy, lupus |

### Clinical Data (Requires Personal Context)

- **Vital Signs**: Blood pressure, heart rate, SpO2, temperature, respiratory rate, BMI
- **Laboratory Results**: HbA1c, glucose, PSA, TSH, CD4, viral load, creatinine, eGFR, lipid panels, etc.
- **Medications**: 60+ specific drug names (requiring dosage + patient context within 150 chars)

## Usage

### Basic Detection

```python
from tools.phi_detector import PHIDetector

detector = PHIDetector()
result = detector.detect("Patient admitted 2024-03-15, diagnosis: E11.9 (T2DM), NPI: 1234567890")

print(f"PHI found: {result['count']} items")
print(f"Has critical: {result['has_critical']}")
print(f"Types detected: {result['phi_types']}")
print(f"Masked text: {result['masked_text']}")
```

### Accessing Findings

```python
for finding in result['findings']:
    print(f"Type: {finding['type']}")
    print(f"Severity: {finding['severity']}")
    print(f"Evidence: {finding['context_snippet']}")
    print(f"Position: {finding['start']}-{finding['end']}")
```

### CLI Usage

```bash
# Direct text analysis
python tools/phi_detector.py "Patient Name: John Doe, admitted 2024-03-15, PTSD diagnosis"

# Run built-in examples
python tools/phi_detector.py --example
```

## Output Format

```json
{
  "findings": [
    {
      "type": "mental_health_condition",
      "category": "Mental Health Condition",
      "severity": "CRITICAL",
      "matched_text": "PTSD",
      "context_snippet": "...admitted 2024-03-15, PTSD diagnosis...",
      "start": 42,
      "end": 46
    }
  ],
  "count": 3,
  "has_critical": true,
  "has_high": false,
  "categories_detected": ["Mental Health Condition", "Medical Event Date", "Patient Name in Health Context"],
  "phi_types": ["mental_health_condition", "medical_event_date", "patient_name_health_context"],
  "masked_text": "Patient Name: [PATIENT_NAME_HEALTH_CONTEXT], admitted [MEDICAL_EVENT_DATE], [MENTAL_HEALTH_CONDITION] diagnosis",
  "summary": "CRITICAL: 3 PHI item(s) detected. Immediate review required."
}
```

### Severity Levels

| Severity | Meaning | Examples |
|----------|---------|---------|
| CRITICAL | Highest legal protection, immediate risk | Mental health, SUD, HIV, genetic info |
| HIGH | Significant PHI, compliance required | Chronic conditions, clinical trial IDs, NPI |
| MEDIUM | Moderate PHI risk | Lab results, vital signs, CPT codes |
| LOW | Lower-risk administrative PHI | Encounter numbers, HCPCS codes |

## Context-Window Validation

Several PHI types require personal context before being flagged to prevent false positives:

- **Vital signs** and **lab results**: Require `patient|person|individual|name|mr\.|mrs\.|ms\.|dr\.` within ±250 characters
- **ICD-10 codes**: Require a diagnosis/condition label in a 200-char window
- **Medications**: Require both a dosage pattern AND patient context within 150 chars
- **Encounter numbers**: Require encounter/visit/admission context

## Regulatory Compliance

| Regulation | Coverage |
|-----------|---------|
| HIPAA Privacy Rule (45 CFR §164) | All 18 Safe Harbor identifiers |
| HIPAA Omnibus Rule 2013 | Genetic information as PHI |
| 42 CFR Part 2 | Substance Use Disorder extra protections |
| HITECH Act | Extended breach notification scope |
| State Mental Health Laws | Aligned with highest-protection states |

## Security Considerations

- **Fully Local**: Zero external API calls, no network access
- **No Data Storage**: Findings not persisted after return
- **No Overlap with pii-detector**: Each identifier detected exactly once across both skills
- **ReDoS Protection**: All patterns use bounded quantifiers and atomic groups
- **Confidence-Based**: Context validation prevents flagging general medical text as PHI

## Integration with Agent Orchestrator

```python
# In agent/orchestrator.py
from skills.phi_detector.tools.phi_detector import PHIDetector

phi_detector = PHIDetector()
phi_result = phi_detector.detect(prompt_text)

# Key output fields for orchestrator
phi_result['count']         # Total PHI items
phi_result['has_critical']  # Trigger immediate escalation
phi_result['has_high']      # Factor into risk score
phi_result['phi_types']     # List of PHI type keys detected
```

## Integration with Other Skills

- **pii-detector**: Complementary — covers non-health PII. Run both for full coverage.
- **risk-score-calculator**: `has_critical` → weight CRITICAL findings heavily
- **prompt-injection-detector**: PHI exposure via injected prompts is a combined threat
- **context-analyzer**: Helps determine if PHI is in a clinical or non-clinical context

## Performance

- **Speed**: <10ms for prompts up to 10KB
- **Memory**: <5MB footprint (compiled regex patterns cached at init)
- **Accuracy**: Context validation reduces false positives by ~60-70% vs. raw pattern matching

## Limitations

- **Pattern-Based Only**: Cannot detect semantically described PHI (e.g., "my grandfather's illness")
- **US-Centric**: NPI, DEA, NDC, CPT, HCPCS are US healthcare identifiers
- **No NER**: Does not use Named Entity Recognition for implicit PHI
- **Format Dependency**: Codes must appear in recognizable format or with labels
- **Context Required**: Vital signs/lab results in textbooks will not be flagged (by design)

## Examples

### Example 1: Provider Identifiers

**Input:**
```
Dr. Smith (NPI: 1467892341) prescribed DEA: BM5234789 Schedule II
```

**Output:**
```
Detected: 2 PHI items (HIGH severity)
- NPI: 1467892341 → [NPI_NUMBER]
- DEA Registration: BM5234789 → [DEA_REGISTRATION]
```

### Example 2: Sensitive Health Condition

**Input:**
```
Patient disclosed buprenorphine therapy for OUD; ART regimen includes tenofovir for HIV management
```

**Output:**
```
Detected: 2 CRITICAL PHI items
- Substance Use Disorder: buprenorphine therapy for OUD → [SUBSTANCE_USE_DISORDER]
- HIV/AIDS Status: ART regimen...tenofovir for HIV → [HIV_AIDS_STATUS]
Summary: CRITICAL: 2 PHI item(s) detected. Immediate review required.
```

### Example 3: Clinical Note Fragment

**Input:**
```
CC: chest pain x 3 days
HPI: 67 y/o male presents with exertional dyspnea
Assessment: Diagnosis E11.9, CPT: 99213
```

**Output:**
```
Detected: 4 PHI items
- Clinical Notes Context: CC: / HPI: (CRITICAL)
- Age Over 89: Not triggered (67 is under threshold)
- ICD-10 Code: E11.9 (HIGH)
- CPT Procedure Code: 99213 (MEDIUM)
```

### Example 4: No PHI

**Input:**
```
What are HIPAA best practices for healthcare software development?
```

**Output:**
```
Detected: 0 PHI items
Summary: No PHI detected.
```

## Changelog

### v1.0.0 (2026-03-09)
- Initial release targeting HIPAA 18 Safe Harbor identifiers
- Zero-overlap design with pii-detector skill
- 21 administrative PHI pattern categories
- 7 sensitive health condition categories
- Medication detection with context validation
- Context-window validation for vital signs and lab results
- Full masking with `[PHI_TYPE]` replacement tokens
- CLI interface with `--example` flag

## License

This skill is provided for HIPAA compliance and healthcare data protection purposes only.

## Support

For issues or enhancement requests, contact the Security Analysis Team.
