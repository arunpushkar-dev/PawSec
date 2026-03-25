/**
 * Session detail panel — loads and renders the full session
 * including the prompt timeline.
 */

import { buildPromptCard } from './prompt_detail.js';
import { exportSessionCSV } from './export.js';

const PLATFORM_ICONS = {
  chatgpt: '🤖', claude: '🔶', gemini: '💎',
  perplexity: '🔍', copilot: '💠', grok: '𝕏', unknown: '❓'
};

export class SessionDetailManager {
  #apiBase;
  #apiKey;
  #currentSessionId = null;
  #prompts = [];

  constructor(apiBase, apiKey) {
    this.#apiBase = apiBase;
    this.#apiKey  = apiKey;
  }

  async loadSession(sessionId) {
    this.#currentSessionId = sessionId;
    this.#prompts = [];
    this.#renderLoading();

    try {
      const headers = this.#apiKey ? { 'X-API-Key': this.#apiKey } : {};
      const res = await fetch(`${this.#apiBase}/api/v1/sessions/${sessionId}`, { headers });
      if (!res.ok) { this.#renderError('Failed to load session'); return; }
      const data = await res.json();
      this.#prompts = data.prompts ?? [];
      this.#renderSession(data);
    } catch {
      this.#renderError('Server unreachable');
    }
  }

  /** Called by WS event to prepend a new prompt if it belongs to open session. */
  handleNewPrompt(event) {
    if (event.session_id !== this.#currentSessionId) return;
    // Re-fetch full prompt detail asynchronously and prepend
    this.#fetchAndPrependPrompt(event.prompt_id);
  }

  async #fetchAndPrependPrompt(promptId) {
    try {
      const headers = this.#apiKey ? { 'X-API-Key': this.#apiKey } : {};
      const res = await fetch(
        `${this.#apiBase}/api/v1/sessions/${this.#currentSessionId}/prompts/${promptId}`, { headers }
      );
      if (!res.ok) return;
      const prompt = await res.json();
      this.#prompts.unshift(prompt);
      const timeline = document.getElementById('prompt-timeline');
      if (timeline) timeline.prepend(buildPromptCard(prompt));
    } catch { /* ignore */ }
  }

  #renderLoading() {
    const detail = document.getElementById('session-detail');
    document.getElementById('empty-state').style.display = 'none';
    detail.style.display = 'block';
    detail.innerHTML = '<div style="display:flex;justify-content:center;padding:40px"><div class="spinner"></div></div>';
  }

  #renderError(msg) {
    const detail = document.getElementById('session-detail');
    detail.style.display = 'block';
    detail.innerHTML = `<p style="color:var(--red);padding:20px">${msg}</p>`;
  }

  #renderSession(data) {
    const detail = document.getElementById('session-detail');
    const plat = data.platform_hint ?? 'unknown';
    const icon = PLATFORM_ICONS[plat] ?? '🌐';
    const started = new Date(data.started_at).toLocaleString();

    detail.innerHTML = `
      <div class="session-detail-header">
        <div>
          <h2>${icon} ${plat} session</h2>
          <div style="font-size:12px;color:var(--text-muted);font-family:var(--mono);margin-top:4px">${data.session_id}</div>
          <div style="font-size:12px;color:var(--text-secondary);margin-top:2px">Started ${started} · v${data.extension_version ?? '?'}</div>
        </div>
        <div style="display:flex;gap:8px">
          <button class="btn btn-teal" id="export-btn">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
            Export CSV
          </button>
        </div>
      </div>

      <div style="display:flex;gap:16px;margin-bottom:16px;flex-wrap:wrap">
        ${(data.warned_count  ?? 0) > 0 ? `<span class="risk-badge WARNED">${data.warned_count} warned</span>`   : ''}
        ${(data.blocked_count ?? 0) > 0 ? `<span class="risk-badge BLOCKED">${data.blocked_count} blocked</span>` : ''}
        <span style="font-size:13px;color:var(--text-secondary)">${data.prompt_count ?? 0} total prompts</span>
      </div>

      <div class="prompt-timeline" id="prompt-timeline"></div>`;

    const timeline = document.getElementById('prompt-timeline');
    if (!this.#prompts.length) {
      timeline.innerHTML = '<p style="color:var(--text-muted);padding:16px 0">No prompts recorded yet.</p>';
    } else {
      for (const p of this.#prompts) {
        timeline.appendChild(buildPromptCard(p));
      }
    }

    document.getElementById('export-btn').addEventListener('click', () => {
      exportSessionCSV(data.session_id, this.#prompts);
    });
  }
}
