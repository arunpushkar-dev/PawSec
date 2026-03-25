/**
 * PawSec site adapter — Grok (grok.com / x.com/i/grok)
 * Intercepts: textarea or contenteditable input + send button click / Enter key.
 *
 * Grok's DOM may use a textarea or a contenteditable div depending on the view.
 * The send button is a <button> element; we match broadly since it may be SVG-only.
 */

import { interceptManager } from '../content_base.js';

// Input: textarea first, contenteditable as fallback
const INPUT_SEL = 'textarea, div[contenteditable="true"]';

// Send button: type=submit, data-testid variants, or any aria-label button
// (filtered below to exclude non-send actions)
const SUBMIT_SEL = [
  'button[type="submit"]',
  'button[data-testid*="send"]',
  'button[data-testid*="submit"]',
  'button[aria-label]',
].join(', ');

const EXCLUDE_LABELS = [
  'stop', 'cancel', 'clear', 'attach', 'upload',
  'voice', 'microphone', 'image', 'file', 'new',
  'settings', 'more', 'menu',
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

function attachListeners() {
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

// Wait for input to appear in SPA navigation
const observer = new MutationObserver(() => {
  if (document.querySelector(INPUT_SEL)) {
    observer.disconnect();
    attachListeners();
  }
});

if (document.querySelector(INPUT_SEL)) {
  attachListeners();
} else {
  observer.observe(document.body, { childList: true, subtree: true });
}
