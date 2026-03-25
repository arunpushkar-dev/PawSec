# Contributing to PawSec Skills

## The Sync Rule

Every browser analyzer `.js` file **must match** its server-side `.py` file exactly in:
- **Filename** (snake_case, same name): e.g. `phi_detector.py` ↔ `phi_detector.js`
- **Detection patterns**: same regex patterns, same risk levels, same pattern names
- **Return shape**: same field names and structure in the result object

Whenever you change either file, you **must** update the corresponding counterpart in the same commit.

| Server (Python) | Browser (JavaScript) |
|---|---|
| `skills/phi-detector/tools/phi_detector.py` | `pawsec-extension/src/analyzers/phi_detector.js` |
| `skills/pii-detector/tools/pii_detector.py` | `pawsec-extension/src/analyzers/pii_detector.js` |
| `skills/api-secrets-detector/tools/api_secrets_detector.py` | `pawsec-extension/src/analyzers/api_secrets_detector.js` |
| `skills/credentials-detector/tools/credentials_detector.py` | `pawsec-extension/src/analyzers/credentials_detector.js` |
| `skills/code-injection-detector/tools/code_injection_detector.py` | `pawsec-extension/src/analyzers/code_injection_detector.js` |
| `skills/private-url-detector/tools/private_url_detector.py` | `pawsec-extension/src/analyzers/private_url_detector.js` |
| `skills/business-data-detector/tools/business_data_detector.py` | `pawsec-extension/src/analyzers/business_data_detector.js` |
| `skills/financial-data-detector/tools/financial_data_detector.py` | `pawsec-extension/src/analyzers/financial_data_detector.js` |

## Why This Matters

Skills folders are reusable shared modules. The Python `.py` files run server-side (Ollama pipeline, API endpoints). The JavaScript `.js` files run in-browser (offline, zero-latency). Both must produce identical detection results for the same input so that in-browser pre-screening and server-side audit are consistent.

## Adding a New Detector

1. Create the Python skill under `skills/<detector-name>/tools/<detector_name>.py`
2. Create the matching JS file at `pawsec-extension/src/analyzers/<detector_name>.js`
3. Import and wire into `pawsec-extension/src/content/content_base.js` (Promise.all)
4. Add a weight to `pawsec-extension/src/analyzers/risk_scorer.js` (rebalance all weights to sum to 1.0)
5. Add a finding tag to `pawsec-extension/src/content/ui/warning_banner.js` (`buildFindingTags`)
6. Add the mapping row to this file
7. Run `npm run build:all` and verify all three distributions build cleanly
