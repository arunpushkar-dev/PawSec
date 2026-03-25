/**
 * PawSec in-browser code injection / jailbreak detector.
 * Ports key patterns from the Python code-injection-detector skill.
 *
 * Returns two independent signals:
 *   code_detected   — text contains source code (language structure patterns)
 *   threat_detected — code contains malicious/injection patterns
 *
 * risk_level reflects threats only:
 *   SAFE  → no code at all
 *   LOW   → code present, no threats  → scorer floors to WARN (user review)
 *   MEDIUM/HIGH/CRITICAL → injection threats found → scorer floors to WARN/BLOCK
 */

// ── Code-presence patterns (language structure, not harmful) ──────────────
// Detect that the text IS source code, independent of whether it's malicious.
const CODE_PRESENCE_PATTERNS = [
  /def\s+\w+\s*\(/,                                              // Python function
  /function[\s*]\s*\w*\s*\(/,                                    // JS/TS function
  /class\s+\w+[\s:{(]/,                                          // class declaration
  /import\s+[\w{]/,                                              // ES/Python import
  /require\s*\(/,                                                // CommonJS require
  /#include\s*[<"]/,                                             // C/C++ include
  /public\s+(?:static\s+)?(?:void|int|String|boolean|class)\b/, // Java method/class
  /(?:var|let|const)\s+\w+\s*=/,                                // JS variable declaration
  /for\s*\([^)]*;[^)]*;[^)]*\)/,                                // C-style for loop
  /while\s*\([^)]+\)\s*[{:]/,                                   // while loop
  /print\s*\([^)]+\)/,                                          // print call
  /console\.log\s*\(/,                                          // JS console.log
  /System\.out\.print/,                                         // Java print
  /\bSELECT\b.+\bFROM\b/i,                                     // SQL SELECT
  /\bCREATE\s+TABLE\b/i,                                        // SQL DDL
  /<\?php/,                                                     // PHP open tag
  /\$\w+\s*=/,                                                  // PHP variable
  /\bfn\s+\w+\s*\(/,                                           // Rust function
  /\bfunc\s+\w+\s*\(/,                                         // Go function
  /\bif\s+\w[^)]*:\s*$/m,                                      // Python if block
  /\bpub\s+(?:fn|struct|enum|impl)\b/,                         // Rust visibility modifier
  /->\s*(?:str|int|bool|float|list|dict|None|Self)\b/,         // Python return type hint
];

const THREAT_PATTERNS = [
  // ── SQL Injection ──────────────────────────────────────
  { lang: 'SQL', name: 'union_select',       risk: 'HIGH',     re: /\bUNION\s+(?:ALL\s+)?SELECT\b/gi },
  { lang: 'SQL', name: 'drop_table',         risk: 'CRITICAL', re: /\bDROP\s+TABLE\b/gi },
  { lang: 'SQL', name: 'sql_comment_bypass', risk: 'HIGH',     re: /(?:--|#)\s*(?:[\w\s]*)(?:OR|AND)\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?/gi },
  { lang: 'SQL', name: 'or_1_eq_1',         risk: 'HIGH',     re: /\b(?:OR|AND)\s+['"]?1['"]?\s*=\s*['"]?1['"]?/gi },
  // ── Shell / OS ─────────────────────────────────────────
  { lang: 'Shell', name: 'rm_rf',            risk: 'CRITICAL', re: /\brm\s+-[rf]+\s+\//g },
  { lang: 'Shell', name: 'command_subst',    risk: 'HIGH',     re: /`[^`]{5,}`|\$\([^)]{5,}\)/g },
  { lang: 'Shell', name: 'eval_exec',        risk: 'HIGH',     re: /\b(?:eval|exec)\s*\(/gi },
  { lang: 'Shell', name: 'curl_pipe_sh',     risk: 'CRITICAL', re: /curl\s+[^|]*\|\s*(?:bash|sh|zsh)/gi },
  { lang: 'Shell', name: 'wget_execute',     risk: 'CRITICAL', re: /wget\s+[^\s]+\s*&&\s*(?:chmod|\.\/|bash|sh)/gi },
  // ── Python ────────────────────────────────────────────
  { lang: 'Python', name: 'py_eval',         risk: 'HIGH',     re: /\beval\s*\([^)]{4,}\)/g },
  { lang: 'Python', name: 'py_exec',         risk: 'HIGH',     re: /\bexec\s*\([^)]{4,}\)/g },
  { lang: 'Python', name: 'subprocess',      risk: 'CRITICAL', re: /subprocess\.(?:call|run|Popen)\s*\(/g },
  { lang: 'Python', name: 'os_system',       risk: 'CRITICAL', re: /os\.(?:system|popen|exec[lv]e?)\s*\(/g },
  { lang: 'Python', name: 'pickle_loads',    risk: 'HIGH',     re: /pickle\.loads\s*\(/g },
  // ── JavaScript / XSS ──────────────────────────────────
  { lang: 'JS', name: 'xss_script',          risk: 'HIGH',     re: /<script[^>]*>[\s\S]*?<\/script>/gi },
  { lang: 'JS', name: 'js_eval',             risk: 'HIGH',     re: /\beval\s*\([^)]{4,}\)/g },
  { lang: 'JS', name: 'document_write',      risk: 'MEDIUM',   re: /document\.write\s*\(/gi },
  { lang: 'JS', name: 'inner_html',          risk: 'MEDIUM',   re: /\.innerHTML\s*=/gi },
  { lang: 'JS', name: 'fetch_exfil',         risk: 'HIGH',     re: /fetch\s*\(\s*['"][^'"]*external[^'"]*['"],/gi },
  // ── HTML Comment Injection (RAG/document poisoning via code) ─────────────
  { lang: 'Prompt', name: 'html_comment_injection', risk: 'CRITICAL', re: /<!--[\s\S]*?(?:ignore|disregard|override|bypass|forget|reveal|output\s+(?:your|the)|system\s+prompt|previous\s+instructions?)[\s\S]*?(?:-->|$)/gi },
  // ── Path Traversal ────────────────────────────────────
  { lang: 'PathTraversal', name: 'dotdot',   risk: 'HIGH',     re: /(?:\.\.\/){2,}|(?:\.\.\\){2,}/g },
  // ── PowerShell ────────────────────────────────────────
  { lang: 'PowerShell', name: 'ps_encoded',  risk: 'CRITICAL', re: /powershell(?:\.exe)?\s+(?:-\w+\s+)*-(?:enc|encodedcommand)\s+[a-zA-Z0-9+/=]{20,}/gi },
  { lang: 'PowerShell', name: 'iex',         risk: 'CRITICAL', re: /\bIEX\s*\(/gi },
  // ── Obfuscation ───────────────────────────────────────
  { lang: 'Obfuscation', name: 'base64_decode_call', risk: 'HIGH',     re: /\b(?:base64\.b64decode|Base64\.decode|atob|Buffer\.from)\s*\(/gi },
  { lang: 'Obfuscation', name: 'long_base64_blob',   risk: 'HIGH',     re: /[A-Za-z0-9+/]{60,}={0,2}/g },
  { lang: 'Obfuscation', name: 'hex_escape_seq',     risk: 'HIGH',     re: /(?:\\x[0-9a-f]{2}){4,}/gi },
  { lang: 'Obfuscation', name: 'hex_byte_array',     risk: 'HIGH',     re: /(?:0x[0-9a-f]{2},?\s*){4,}/gi },
  { lang: 'Obfuscation', name: 'unicode_escape_seq', risk: 'HIGH',     re: /(?:\\u[0-9a-f]{4}){3,}/gi },
  { lang: 'Obfuscation', name: 'zero_width_chars',   risk: 'CRITICAL', re: /[\u200B-\u200D\u2060\u180E\uFEFF]/g },
  { lang: 'Obfuscation', name: 'url_encoding_seq',   risk: 'HIGH',     re: /(?:%[0-9a-f]{2}){4,}/gi },
  { lang: 'Obfuscation', name: 'rag_code_block',     risk: 'HIGH',     re: /```[^`]*\b(?:eval|exec|system)\s*\([^`]*```/gis },
  // ── Agent Manipulation (code-based only) ─────────────
  // Linguistic jailbreaks/persona overrides belong in unknown_malicious_intent_detector.js
  { lang: 'AgentManip', name: 'print_system_prompt', risk: 'HIGH', re: /print\s*\(.*system.*prompt/gi },
  { lang: 'AgentManip', name: 'log_instructions',    risk: 'HIGH', re: /console\.log\s*\(.*instructions/gi },
];

/**
 * @param {string} text
 * @returns {{
 *   threat_detected: boolean,
 *   code_detected: boolean,
 *   threats: Array,
 *   count: number,
 *   risk_level: string,
 *   languages: string[]
 * }}
 */
export function analyzeCodeInjection(text) {
  const threats = [];
  const riskOrder = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };

  for (const { lang, name, risk, re } of THREAT_PATTERNS) {
    re.lastIndex = 0;
    const matches = [...text.matchAll(re)];
    if (matches.length) {
      threats.push({
        language: lang,
        name,
        risk,
        count: matches.length,
        snippet: matches[0][0].slice(0, 80),
      });
    }
    re.lastIndex = 0;
  }

  const maxRisk = threats.reduce((acc, t) => {
    return (riskOrder[t.risk] ?? 0) > (riskOrder[acc] ?? 0) ? t.risk : acc;
  }, 'SAFE');

  // Code-presence check: does the text contain source code (regardless of threats)?
  const code_detected = threats.length > 0 ||
    CODE_PRESENCE_PATTERNS.some(re => re.test(text));

  const languages = [...new Set(threats.map(t => t.language))];

  return {
    threat_detected: threats.length > 0,
    code_detected,
    threats,
    count:      threats.length,
    // LOW signals "code present but benign" — risk scorer floors this to WARN
    risk_level: threats.length ? maxRisk : (code_detected ? 'LOW' : 'SAFE'),
    languages,
  };
}
