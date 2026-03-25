/**
 * Stats bar — loads initial totals from /api/v1/stats and
 * handles live incremental updates from WebSocket events.
 */

export class StatsManager {
  #totals = { total: 0, blocked: 0, warned: 0, allowed: 0 };
  #platforms = {};

  constructor(apiBase) {
    this.apiBase = apiBase;
  }

  async load(apiKey) {
    try {
      const res = await fetch(`${this.apiBase}/api/v1/stats`, {
        headers: apiKey ? { 'X-API-Key': apiKey } : {}
      });
      if (!res.ok) return;
      const data = await res.json();
      this.#totals = {
        total:   data.total_prompts ?? 0,
        blocked: data.blocked       ?? 0,
        warned:  data.warned        ?? 0,
        allowed: data.allowed       ?? 0,
      };
      this.#platforms = data.platform_breakdown ?? {};
    } catch { /* server offline */ }
    this.#render();
  }

  /** Recompute totals from the currently displayed sessions list. */
  computeFromSessions(sessions) {
    this.#totals   = { total: 0, blocked: 0, warned: 0, allowed: 0 };
    this.#platforms = {};
    for (const s of sessions) {
      this.#totals.total   += s.prompt_count  ?? 0;
      this.#totals.blocked += s.blocked_count ?? 0;
      this.#totals.warned  += s.warned_count  ?? 0;
      this.#totals.allowed += s.allowed_count ?? 0;
      const plat = s.platform_hint ?? s.platform ?? 'unknown';
      this.#platforms[plat] = (this.#platforms[plat] ?? 0) + (s.prompt_count ?? 0);
    }
    this.#render();
  }

  handleNewPrompt(event) {
    this.#totals.total++;
    const action = event.action_taken;
    if (action === 'BLOCKED') this.#totals.blocked++;
    else if (action === 'WARNED') this.#totals.warned++;
    else this.#totals.allowed++;

    const plat = event.platform ?? 'unknown';
    this.#platforms[plat] = (this.#platforms[plat] ?? 0) + 1;
    this.#render();
  }

  /** Zero out all displayed counters without touching server data. */
  resetView() {
    this.#totals   = { total: 0, blocked: 0, warned: 0, allowed: 0 };
    this.#platforms = {};
    this.#render();
  }

  #render() {
    document.getElementById('stat-total').textContent   = this.#totals.total.toLocaleString();
    document.getElementById('stat-blocked').textContent = this.#totals.blocked.toLocaleString();
    document.getElementById('stat-warned').textContent  = this.#totals.warned.toLocaleString();
    document.getElementById('stat-allowed').textContent = this.#totals.allowed.toLocaleString();

    const bar = document.getElementById('platform-bar');
    bar.innerHTML = '';
    const ICONS = { chatgpt: '🤖', claude: '🔶', gemini: '💎', perplexity: '🔍', copilot: '💠', grok: '𝕏', unknown: '❓' };
    for (const [plat, count] of Object.entries(this.#platforms)) {
      const chip = document.createElement('span');
      chip.style.cssText = 'font-size:12px;color:var(--text-secondary);display:flex;align-items:center;gap:4px;';
      chip.innerHTML = `${ICONS[plat] ?? '🌐'} <strong style="color:var(--text-primary)">${count}</strong> ${plat}`;
      bar.appendChild(chip);
    }
  }
}
