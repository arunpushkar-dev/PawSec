/**
 * PawSec site adapter — Microsoft Copilot (copilot.microsoft.com)
 * Intercepts: #searchbox, cib-text-input textarea (shadow DOM).
 *
 * Copilot uses shadow DOM internally. The observer must stay alive for SPA nav;
 * listenersAttached guard prevents duplicate registration.
 */

import { interceptManager } from '../content_base.js';

const INPUT_SEL  = '#searchbox, cib-text-input textarea, textarea[id*="search"]';
const SUBMIT_SEL = 'button[aria-label*="Submit"], button[type="submit"], cib-chat-main-container button[aria-label*="send" i]';

// Walk shadow roots to find inputs inside shadow DOM
function queryShadowAll(root, selector) {
  const results = [];
  const walk = (node) => {
    if (!node) return;
    if (node.matches?.(selector)) results.push(node);
    if (node.shadowRoot) walk(node.shadowRoot);
    node.childNodes?.forEach(walk);
  };
  walk(root);
  return results;
}

function getPromptTextDeep() {
  const inputs = queryShadowAll(document.body, 'textarea, [contenteditable="true"]');
  for (const el of inputs) {
    const val = (el.value ?? el.innerText ?? el.textContent ?? '').trim();
    if (val) return val;
  }
  return '';
}

let listenersAttached = false;

function attachListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  // ── Enter key (no Shift) ──────────────────────────────────
  document.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e._pawsec_pass) return;
    const text = getPromptTextDeep();
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
      const el  = document.querySelector(INPUT_SEL) ?? e.target;
      const ev2 = new KeyboardEvent('keydown', {
        key: 'Enter', bubbles: true, cancelable: true,
        keyCode: 13, which: 13,
      });
      Object.defineProperty(ev2, '_pawsec_pass', { value: true });
      el.dispatchEvent(ev2);
    });
  }, true);

  // ── Send button click ─────────────────────────────────────
  document.addEventListener('click', async (e) => {
    if (e._pawsec_pass) return;
    const btn = e.target.closest(SUBMIT_SEL);
    if (!btn) return;
    const text = getPromptTextDeep();
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
      const ev2 = new MouseEvent('click', { bubbles: true, cancelable: true });
      Object.defineProperty(ev2, '_pawsec_pass', { value: true });
      btn.dispatchEvent(ev2);
    });
  }, true);
}

// Keep observing — Copilot loads components dynamically and SPA-navigates
const observer = new MutationObserver(() => {
  const found = queryShadowAll(document.body, 'textarea').length ||
                document.querySelector(INPUT_SEL);
  if (found) {
    attachListeners();
  }
});

observer.observe(document.body, { childList: true, subtree: true });
