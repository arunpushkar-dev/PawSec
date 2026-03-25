/**
 * PawSec site adapter — Gemini (gemini.google.com)
 * Intercepts: .ql-editor (Quill) / contenteditable in Angular rich-textarea.
 *
 * Gemini is a heavy Angular SPA — the editor is re-created on conversation switch.
 * Listeners are on document (capture phase) so they survive SPA re-renders.
 * listenersAttached guard prevents duplicate registration.
 */

import { interceptManager } from '../content_base.js';

// Covers Quill editor, rich-textarea wrapper, generic textbox, any contenteditable
// (including contenteditable="plaintext-only" used by newer Gemini builds),
// and textarea fallbacks Google sometimes uses.
const INPUT_SEL = [
  '.ql-editor[contenteditable]',
  'rich-textarea [contenteditable]',
  'rich-textarea div[contenteditable]',
  '[contenteditable][role="textbox"]',          // catches any contenteditable textbox
  '[contenteditable="true"][role="textbox"]',
  '[contenteditable="plaintext-only"]',          // newer Gemini / Chrome-only mode
  'div[contenteditable="true"]',
  'div[contenteditable]',
  'textarea[aria-label*="message" i]',
  'textarea[placeholder*="prompt" i]',
  'textarea[placeholder*="Enter" i]',
  'textarea',
].join(', ');

// Covers current and legacy Gemini send buttons.
const SUBMIT_SEL = [
  'button.send-button',
  'button[aria-label="Send message"]',
  'button[aria-label*="Send" i]',               // case-insensitive for localised UIs
  'button[jsname="Qx7uuf"]',                    // known Gemini send jsname
  'button[jsname="c7Uo3d"]',                    // alternate jsname seen in some builds
  'button[data-testid*="send" i]',
  'button[mat-icon-button][aria-label*="send" i]',
  '[role="button"][aria-label*="send" i]',      // non-button element acting as button
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
  const label = (btn.getAttribute('aria-label') || btn.textContent || '').toLowerCase();
  return !EXCLUDE_LABELS.some(w => label.includes(w));
}

let listenersAttached = false;

function attachListeners() {
  if (listenersAttached) return;
  listenersAttached = true;

  // ── Enter key (no Shift) ──────────────────────────────────
  document.addEventListener('keydown', async (e) => {
    if (e.key !== 'Enter' || e.shiftKey || e._pawsec_pass) return;
    // Check the target itself, its closest match, or the active input
    const el = e.target.closest?.(INPUT_SEL) ?? (e.target.matches?.(INPUT_SEL) ? e.target : null) ?? getInputEl();
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

  // ── Pointerdown fallback (Angular/Material may consume 'click' before it bubbles) ──
  document.addEventListener('pointerdown', async (e) => {
    if (e._pawsec_pass) return;
    const btn = e.target.closest(SUBMIT_SEL);
    if (!btn || !isSendBtn(btn)) return;
    // Only intercept if there is actually text — avoids false positives on icon clicks
    const text = getText(getInputEl());
    if (!text) return;

    await interceptManager.handleCapture(e, text, () => {
      const ev2 = new PointerEvent('pointerdown', {
        bubbles: true, cancelable: true,
        pointerId: e.pointerId, pointerType: e.pointerType,
      });
      Object.defineProperty(ev2, '_pawsec_pass', { value: true });
      btn.dispatchEvent(ev2);
    });
  }, true);

  // ── Form submit fallback (some Gemini builds wrap in a form) ──
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

// Attach immediately — document-level listeners work for any future element.
// Don't wait for the MutationObserver; if Angular hasn't finished yet, the
// listeners still fire when the user interacts with any matching element.
attachListeners();

// Also re-run on every DOM mutation as a safety net for SPA conversation switches.
// The listenersAttached guard makes subsequent calls free.
try {
  const observer = new MutationObserver(() => setTimeout(attachListeners, 100));
  observer.observe(document.body || document.documentElement, {
    childList: true, subtree: true,
  });
} catch (_) { /* body not ready — immediate call above is sufficient */ }
