/**
 * PawSec content script base.
 * Provides: InterceptManager, AnalysisOrchestrator, MessageBus.
 * Each site adapter imports this and registers itself via InterceptManager.
 */

import { analyzePII }                    from '../analyzers/pii_detector.js';
import { analyzeCodeInjection }          from '../analyzers/code_injection_detector.js';
import { analyzeAPISecrets }             from '../analyzers/api_secrets_detector.js';
import { analyzeCredentials }            from '../analyzers/credentials_detector.js';
import { analyzePrivateURLs }            from '../analyzers/private_url_detector.js';
import { analyzePHI }                    from '../analyzers/phi_detector.js';
import { analyzeBusinessData }           from '../analyzers/business_data_detector.js';
import { analyzeFinancialData }          from '../analyzers/financial_data_detector.js';
import { analyzeUnknownMaliciousIntent } from '../analyzers/unknown_malicious_intent_detector.js';
import { calculateRisk }                 from '../analyzers/risk_scorer.js';
import { showWarningBanner, showBlockOverlay, showAnalyzingIndicator, removeAnalyzingIndicator } from './ui/warning_banner.js';

// ─── MessageBus ──────────────────────────────────────────

export const MessageBus = {
  send(type, payload) {
    chrome.runtime.sendMessage({ type, ...payload }).catch(() => {});
  }
};

// ─── AnalysisOrchestrator ────────────────────────────────

const AZ_DEFAULTS = {
  az_pii: true, az_code_injection: true, az_api_secrets: true,
  az_credentials: true, az_private_url: true,
  az_phi: true, az_business_data: true, az_financial_data: true,
  az_unknown_malicious: true,
};

// Null result for a skipped analyzer — safe default that scores 0
const _skip = () => ({ detected: false, threat_detected: false, findings: [], risk_level: 'SAFE', risk_score: 0 });

export class AnalysisOrchestrator {
  async analyze(text) {
    const cfg = await new Promise(r => chrome.storage.sync.get(AZ_DEFAULTS, r));

    const [pii, code_injection, api_secrets, credentials, private_url, phi, business_data, financial_data, unknown_malicious_intent] = await Promise.all([
      cfg.az_pii              ? Promise.resolve(analyzePII(text))                       : Promise.resolve(_skip()),
      cfg.az_code_injection   ? Promise.resolve(analyzeCodeInjection(text))             : Promise.resolve(_skip()),
      cfg.az_api_secrets      ? Promise.resolve(analyzeAPISecrets(text))                : Promise.resolve(_skip()),
      cfg.az_credentials      ? Promise.resolve(analyzeCredentials(text))               : Promise.resolve(_skip()),
      cfg.az_private_url      ? Promise.resolve(analyzePrivateURLs(text))               : Promise.resolve(_skip()),
      cfg.az_phi              ? Promise.resolve(analyzePHI(text))                       : Promise.resolve(_skip()),
      cfg.az_business_data    ? Promise.resolve(analyzeBusinessData(text))              : Promise.resolve(_skip()),
      cfg.az_financial_data   ? Promise.resolve(analyzeFinancialData(text))             : Promise.resolve(_skip()),
      cfg.az_unknown_malicious? Promise.resolve(analyzeUnknownMaliciousIntent(text))    : Promise.resolve(_skip()),
    ]);

    const risk = calculateRisk({ pii, code_injection, api_secrets, credentials, private_url, phi, business_data, financial_data, unknown_malicious_intent });
    return { pii, code_injection, api_secrets, credentials, private_url, phi, business_data, financial_data, unknown_malicious_intent, risk };
  }
}

// ─── InterceptManager ────────────────────────────────────

export class InterceptManager {
  #orchestrator = new AnalysisOrchestrator();
  #interceptFn  = null;  // Set by site adapter
  #pendingEvent = null;  // Captured event being held
  #enabled      = true;

  constructor() {
    // Listen for settings changes from popup/service worker
    chrome.runtime.onMessage.addListener((msg) => {
      if (msg.type === 'PAWSEC_TOGGLE') this.#enabled = msg.enabled;
    });
    // Load initial enabled state
    chrome.storage.sync.get({ pawsec_enabled: true }, (s) => {
      this.#enabled = s.pawsec_enabled;
    });
  }

  /**
   * Register the capture-phase intercept function.
   * The function receives (event) and must call event.preventDefault()
   * to hold the submission.
   */
  register(interceptFn) {
    this.#interceptFn = interceptFn;
  }

  /**
   * Called by site adapters when a submit is captured.
   * @param {Event} event - The original submit/click/keydown event
   * @param {string} text - The extracted prompt text
   * @param {Function} submitFn - Native submit function to call on proceed
   */
  async handleCapture(event, text, submitFn) {
    if (!this.#enabled || !text.trim()) {
      submitFn?.();
      return;
    }

    event.preventDefault();
    event.stopImmediatePropagation();

    const trimmed = text.trim();

    // Read LLM + server settings to decide whether to run LLM in parallel
    const cfg = await new Promise(r =>
      chrome.storage.sync.get({ server_url: '', az_llm: true }, r)
    );
    const runLLM = cfg.az_llm && !!cfg.server_url && trimmed.length >= 15;

    // Show analyzing indicator immediately if LLM will run (network round-trip)
    if (runLLM) showAnalyzingIndicator();

    // Run in-browser analyzers and LLM (if enabled) in parallel
    const [result, llmResult] = await Promise.all([
      this.#orchestrator.analyze(trimmed),
      runLLM
        ? new Promise(resolve =>
            chrome.runtime.sendMessage(
              { type: 'LLM_PRE_CHECK', text: trimmed, platform: location.hostname },
              r => resolve(r || { action: 'ALLOW' })
            )
          )
        : Promise.resolve(null),
    ]);

    if (runLLM) removeAnalyzingIndicator();

    // Notify background for session tracking and server submission
    MessageBus.send('PAWSEC_ANALYSIS', {
      text:        trimmed,
      text_length: trimmed.length,
      platform:    location.hostname,
      result,
    });

    const { action, effective_score } = result.risk;

    // Combine in-browser and LLM results — take the more severe action/score
    // In-browser actions: ALLOW | WARN | BLOCK
    // LLM actions from server: ALLOWED | WARNED | BLOCKED
    const SEV = { BLOCK: 3, BLOCKED: 3, WARN: 2, WARNED: 2, ALLOW: 1, ALLOWED: 1 };
    let finalAction = action;
    let finalScore  = effective_score;

    if (llmResult) {
      const llmAction = llmResult.action || 'ALLOW';
      const llmScore  = llmResult.risk_score || 0;
      if ((SEV[llmAction] ?? 1) > (SEV[finalAction] ?? 1)) {
        // Normalize to in-browser format
        finalAction = llmAction === 'BLOCKED' ? 'BLOCK' : llmAction === 'WARNED' ? 'WARN' : 'ALLOW';
        finalScore  = Math.max(finalScore, llmScore);
      }
    }

    if (finalAction === 'WARN') {
      MessageBus.send('PAWSEC_WARNED', { platform: location.hostname, score: finalScore });
      showWarningBanner(
        { ...result, effective_score: finalScore },
        () => submitFn?.(),
        () => {},
      );
      return;
    }

    if (finalAction === 'BLOCK') {
      showBlockOverlay({ ...result, effective_score: finalScore }, () => {});
      MessageBus.send('PAWSEC_BLOCKED', { platform: location.hostname, score: finalScore });
      return;
    }

    // ALLOW
    MessageBus.send('PAWSEC_ALLOWED', { platform: location.hostname });
    submitFn?.();
  }
}

export const interceptManager = new InterceptManager();
