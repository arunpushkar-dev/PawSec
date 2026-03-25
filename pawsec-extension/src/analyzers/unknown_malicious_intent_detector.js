/**
 * PawSec Unknown Malicious Intent Detector (in-browser)
 *
 * Detects PURELY LINGUISTIC adversarial patterns — jailbreaks, persona overrides,
 * safety bypass phrasing, AI training overrides, and harmful content requests.
 *
 * Intentionally separate from code_injection_detector.js, which handles prompts
 * that CONTAIN malicious code. This detector covers attacks that use natural language
 * to manipulate AI behaviour — no code required.
 *
 * Returns: { detected, count, risk_level, findings }
 */

const UMI_PATTERNS = [
  // ── Jailbreak ─────────────────────────────────────────────────────────────
  { name: 'jailbreak_dan',                risk: 'CRITICAL', re: /\bDAN\b|\bDo\s+Anything\s+Now\b/gi },
  { name: 'pretend_no_rules',             risk: 'CRITICAL', re: /\bpretend\s+(?:you\s+have\s+no|there\s+are\s+no)\s+(?:rules?|restrictions?|guidelines?|limits?)/gi },
  { name: 'ignore_previous_instructions', risk: 'CRITICAL', re: /\bignore\s+(?:\w+\s+){0,3}(?:previous|prior|above|all\s+previous)\s+(?:\w+\s+){0,3}instructions?/gi },
  { name: 'system_tag_override',          risk: 'CRITICAL', re: /\[(?:SYSTEM|INST|SYS|ADMIN|ROOT)\s+(?:OVERRIDE|BYPASS|IGNORE|CONTROL|DIRECTIVE|COMMAND|JAILBREAK|UNLOCK)\]/gi },
  { name: 'system_bracket_ignore',        risk: 'CRITICAL', re: /\[(?:SYSTEM|INST|SYS)\]\s*(?:ignore|override|bypass)/gi },

  // ── Persona Override ──────────────────────────────────────────────────────
  { name: 'persona_override',             risk: 'CRITICAL', re: /\byou\s+are\s+no\s+longer\s+(?:a\s+)?(?:\w+\s+){0,4}(?:assistant|ai|model|bot|chatbot|helpful)/gi },
  { name: 'you_are_now_bot',              risk: 'CRITICAL', re: /\byou\s+(?:are|will\s+be|must\s+act\s+as)\s+now\s+(?:called\s+)?['"']?\w+(?:bot|ai)['"']?\b/gi },
  { name: 'act_as_uncensored_ai',         risk: 'CRITICAL', re: /\bact\s+as\s+(?:if\s+you\s+(?:are|were)\s+)?(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken|evil|malicious)\s+(?:ai|assistant|model|bot|version)/gi },

  // ── Safety Constraint Bypass ──────────────────────────────────────────────
  { name: 'regardless_of_safety',         risk: 'CRITICAL', re: /\b(?:regardless|irrespective)\s+of\s+(?:your\s+)?(?:safety|ethical|content|usage)\s+(?:rules?|guidelines?|policies|constraints?|filters?|protocols?|restrictions?)/gi },
  { name: 'without_safety_constraints',   risk: 'CRITICAL', re: /\bwithout\s+(?:any\s+)?(?:ethical|safety|content|moral)\s+(?:guidelines?|constraints?|restrictions?|filters?|rules?|limits?)/gi },
  { name: 'disable_safety_filters',       risk: 'CRITICAL', re: /\b(?:ignore|bypass|disable|remove|turn\s+off)\s+(?:your\s+)?(?:safety|content|ethical)\s+(?:filters?|guidelines?|restrictions?|rules?|protocols?|training)/gi },

  // ── AI Training / Instruction Override ───────────────────────────────────
  { name: 'disregard_training',           risk: 'CRITICAL', re: /\b(?:disregard|forget|bypass|ignore)\s+(?:your|all|the|previous|all\s+previous)\s+(?:training|instructions?|directives?|programming|guidelines?|rules?|safety\s+(?:measures?|protocols?|filters?|rules?))/gi },
  { name: 'override_training',            risk: 'CRITICAL', re: /\boverride\s+(?:your\s+)?(?:training|programming|instructions?|directives?|safety\s+(?:measures?|protocols?|filters?|rules?))/gi },
  { name: 'new_directive_assign',         risk: 'CRITICAL', re: /\b(?:your\s+)?(?:new|updated?)\s+(?:directive|instruction|order|command|mission|purpose)\s+(?:is|are)\s+(?:to|that)\b/gi },
  { name: 'comply_without_filtering',     risk: 'CRITICAL', re: /\bcomply\s+with\s+all\s+(?:\w+\s+)?requests?\s+without\s+(?:filtering|restrictions?|limits?|safety)/gi },

  // ── Harmful Content Requests ──────────────────────────────────────────────
  { name: 'create_phishing',              risk: 'CRITICAL', re: /\b(?:write|create|generate|draft|make)\s+(?:a\s+|an\s+)?(?:convincing\s+|realistic\s+|fake\s+)?phishing\s+(?:email|message|page|site|template|attack)/gi },
  { name: 'create_malware',               risk: 'CRITICAL', re: /\b(?:write|create|generate|make|build|code)\s+(?:a\s+|an\s+)?(?:ransomware|keylogger|trojan|rootkit|spyware|malware|virus|worm|exploit)\b/gi },
  { name: 'credential_harvesting',        risk: 'CRITICAL', re: /\b(?:credential\s+harvesting|password\s+harvesting|login\s+harvesting|credential\s+theft\s+(?:script|page|tool))/gi },
  { name: 'fake_login_page',              risk: 'CRITICAL', re: /\b(?:fake|spoofed?|cloned?)\s+(?:login|sign.?in|authentication)\s+(?:page|site|portal|form)/gi },
  { name: 'social_engineering_script',    risk: 'CRITICAL', re: /\b(?:write|create|generate|draft)\s+(?:a\s+)?(?:social\s+engineering|pretexting|vishing|smishing)\s+(?:script|template|attack|message)/gi },
  { name: 'scam_template',                risk: 'CRITICAL', re: /\b(?:write|create|generate|draft)\s+(?:a\s+)?(?:convincing\s+|realistic\s+)?(?:scam|fraud|con)\s+(?:email|message|script|template)/gi },

  // ── Data Extraction / System Probe ───────────────────────────────────────
  { name: 'reveal_system_prompt',         risk: 'HIGH',     re: /(?:reveal|output|show|print|repeat|tell\s+me)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions?|rules?|configuration)/gi },
  { name: 'impersonation_request',        risk: 'HIGH',     re: /\b(?:impersonat(?:e|ing)|pretend(?:ing)?\s+to\s+be)\s+(?:a\s+)?(?:bank|ceo|it\s+support|admin|helpdesk|government|official)\b/gi },
];

const _RISK_ORDER = { SAFE: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

/**
 * @param {string} text
 * @returns {{ detected: boolean, count: number, risk_level: string, findings: Array }}
 */
export function analyzeUnknownMaliciousIntent(text) {
  const findings = [];

  for (const { name, risk, re } of UMI_PATTERNS) {
    re.lastIndex = 0;
    const match = re.exec(text);
    if (match) {
      findings.push({ name, risk, snippet: match[0].slice(0, 80) });
    }
    re.lastIndex = 0;
  }

  if (!findings.length) {
    return { detected: false, count: 0, risk_level: 'SAFE', findings: [] };
  }

  const maxRisk = findings.reduce(
    (acc, f) => ((_RISK_ORDER[f.risk] ?? 0) > (_RISK_ORDER[acc] ?? 0) ? f.risk : acc),
    'SAFE'
  );

  return { detected: true, count: findings.length, risk_level: maxRisk, findings };
}
