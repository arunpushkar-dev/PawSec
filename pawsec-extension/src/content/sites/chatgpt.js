/**
 * PawSec site adapter — ChatGPT (chat.openai.com / chatgpt.com)
 * Intercepts: contenteditable #prompt-textarea, Enter key, Send button.
 *
 * ChatGPT is a SPA — the input is re-created on new conversations.
 * Observer must stay alive; listenersAttached guard prevents duplicate registration.
 */

import { interceptManager } from '../content_base.js';

const INPUT_SEL = [
  '#prompt-textarea',
  '[data-id="root"] [contenteditable="true"]',
  'div[contenteditable="true"][role="textbox"]',
  'div[contenteditable="true"]',
].join(', ');

const SUBMIT_SEL = [
  'button[data-testid="send-button"]',
  'button[aria-label*="Send"]',
  'button[type="submit"]',
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
}

// Keep observing — ChatGPT SPA replaces the input on every new conversation
const observer = new MutationObserver(() => {
  if (document.querySelector(INPUT_SEL)) {
    attachListeners();
  }
});

if (document.querySelector(INPUT_SEL)) {
  attachListeners();
}
observer.observe(document.body, { childList: true, subtree: true });
