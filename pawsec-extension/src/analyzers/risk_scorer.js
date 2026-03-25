/**
 * PawSec in-browser risk scorer — 9-input weighted scoring.
 *
 * Inputs: PII, PHI, code_injection, api_secrets, credentials, private_url,
 *         business_data, financial_data, unknown_malicious_intent
 * Elevation: any CRITICAL finding floors effective_score to 70 (BLOCK).
 *
 * Risk levels:
 *   SAFE     0–29
 *   MEDIUM  30–49
 *   HIGH    50–69
 *   CRITICAL 70+
 */

const WEIGHTS = {
  pii:                      0.15,
  phi:                      0.10,
  code_injection:           0.14,
  api_secrets:              0.14,
  credentials:              0.12,
  private_url:              0.07,
  business_data:            0.05,
  financial_data:           0.05,
  unknown_malicious_intent: 0.18,
};

const RISK_SCORES = { SAFE: 0, LOW: 15, MEDIUM: 40, HIGH: 70, CRITICAL: 95 };

function toScore(risk_level) {
  return RISK_SCORES[risk_level] ?? 0;
}

function riskFromScore(score) {
  if (score >= 70) return 'CRITICAL';
  if (score >= 50) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'SAFE';
}

/**
 * @param {{ risk_level: string }} pii
 * @param {{ risk_level: string }} phi
 * @param {{ risk_level: string }} code_injection
 * @param {{ risk_level: string }} api_secrets
 * @param {{ risk_level: string }} credentials
 * @param {{ risk_level: string }} private_url
 * @param {{ risk_level: string }} business_data
 * @param {{ risk_level: string }} financial_data
 * @param {{ risk_level: string }} unknown_malicious_intent
 * @returns {{ score: number, effective_score: number, risk_level: string, action: string }}
 */
export function calculateRisk({ pii, phi, code_injection, api_secrets, credentials, private_url, business_data, financial_data, unknown_malicious_intent }) {
  const weighted =
    toScore(pii?.risk_level)                      * WEIGHTS.pii +
    toScore(phi?.risk_level)                      * WEIGHTS.phi +
    toScore(code_injection?.risk_level)           * WEIGHTS.code_injection +
    toScore(api_secrets?.risk_level)              * WEIGHTS.api_secrets +
    toScore(credentials?.risk_level)              * WEIGHTS.credentials +
    toScore(private_url?.risk_level)              * WEIGHTS.private_url +
    toScore(business_data?.risk_level)            * WEIGHTS.business_data +
    toScore(financial_data?.risk_level)           * WEIGHTS.financial_data +
    toScore(unknown_malicious_intent?.risk_level) * WEIGHTS.unknown_malicious_intent;

  const score = Math.round(weighted);

  // Elevation floors: any category at CRITICAL/HIGH/MEDIUM guarantees a minimum score
  const inputs = [pii, phi, code_injection, api_secrets, credentials, private_url, business_data, financial_data, unknown_malicious_intent];
  const hasCritical = inputs.some(r => r?.risk_level === 'CRITICAL');
  const hasHigh     = inputs.some(r => r?.risk_level === 'HIGH');
  const hasMedium   = inputs.some(r => r?.risk_level === 'MEDIUM');

  let effective_score = score;
  if (hasCritical)       effective_score = Math.max(score, 70);  // BLOCK
  else if (hasHigh)      effective_score = Math.max(score, 50);  // WARN
  else if (hasMedium)    effective_score = Math.max(score, 30);  // WARN

  // Code-presence floor: prompt contains code but no injection threats → user review
  if (code_injection?.code_detected && !code_injection?.threat_detected) {
    effective_score = Math.max(effective_score, 30);  // WARN
  }

  const risk_level = riskFromScore(effective_score);

  let action;
  if (effective_score >= 70) action = 'BLOCK';
  else if (effective_score >= 30) action = 'WARN';
  else action = 'ALLOW';

  return { score, effective_score, risk_level, action };
}
