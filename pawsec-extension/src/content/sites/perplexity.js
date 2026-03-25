/**
 * PawSec site adapter — Perplexity (perplexity.ai)
 * Intercepts: textarea (home) and contenteditable div (conversation thread) + send button.
 *
 * Perplexity uses a textarea on the home/search page and a contenteditable div
 * in the threaded conversation view. Both must be handled.
 */

import { interceptManager } from '../content_base.js';

// Match both textarea and contenteditable, with common Perplexity attributes
const INPUT_SEL = [
  'textarea[placeholder*="Ask"]',
  'textarea[placeholder*="ask"]',
  'textarea[name="q"]',
  'textarea',
  'div[contenteditable="true"][role="textbox"]',
  'div[contenteditable="true"]',
].join(', ');

const SUBMIT_SEL = [
  'button[aria-label="Submit"]',
  'button[aria-label*="Submit"]',
  'button[aria-label*="Send"]',
  'button[type="submit"]',
  'button[data-testid*="send"]',
  'button[data-testid*="submit"]',
].join(', ');

const EXCLUDE_LABELS = [
  'stop', 'cancel', 'clear', 'attach', 'upload',
  'voice', 'microphone', 'image', 'file', 'new',
  'settings', 'more', 'menu', 'pro',
];

function getInputEl() {
  const active = document.activeElement;
  if (active && active.matches(INPUT_SEL)) return active;
  return document.querySelector(INPUT_SEL);
}

function getText(el) {
  if (!el) return '';
  return (el.value ?? el.innerText ?? el.textContent ?? '').trim();
}

function isSendBtn(btn) {
  const label = (btn.getAttribute('aria-label') || '').toLowerCase();
  return !EXCLUDE_LABELS.some(w => label.includes(w));
}

let listenersAttached = false;

function attachListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  // ── Enter key (no Shift) ──────────────────────────────────
  document.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e._pawsec_pass) return;
    const el = e.target.closest(INPUT_SEL);
    if (!el) return;
    const text = getText(el);
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
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
    if (!btn || !isSendBtn(btn)) return;
    const text = getText(getInputEl());
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
      const ev2 = new MouseEvent('click', { bubbles: true, cancelable: true });
      Object.defineProperty(ev2, '_pawsec_pass', { value: true });
      btn.dispatchEvent(ev2);
    });
  }, true);

  // ── Form submit (fallback) ────────────────────────────────
  document.addEventListener('submit', async (e) => {
    if (e._pawsec_pass) return;
    const text = getText(getInputEl());
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
      const ev2 = new Event('submit', { bubbles: true, cancelable: true });
      Object.defineProperty(ev2, '_pawsec_pass', { value: true });
      e.target.dispatchEvent(ev2);
    });
  }, true);
}

// Keep observing — Perplexity SPA navigation replaces the input on each page
const observer = new MutationObserver(() => {
  if (document.querySelector(INPUT_SEL)) {
    attachListeners();
  }
});

if (document.querySelector(INPUT_SEL)) {
  attachListeners();
}
observer.observe(document.body, { childList: true, subtree: true });
