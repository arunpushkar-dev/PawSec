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

  static #friendlyName(hostname) {
    const map = {
      'chatgpt.com':             'ChatGPT',
      'claude.ai':               'Claude',
      'gemini.google.com':       'Google',
      'www.perplexity.ai':       'Perplexity',
      'copilot.microsoft.com':   'Copilot',
      'x.com':                   'Grok',
    };
    return map[hostname] ?? hostname;
  }

  static #dotColor(hostname) {
    const red  = ['chatgpt.com', 'gemini.google.com', 'x.com', 'copilot.microsoft.com'];
    return red.includes(hostname) ? 'var(--red)' : '#3aaa6e';
  }

  #render() {
    const { total, blocked, warned, allowed } = this.#totals;
    document.getElementById('stat-total').textContent   = total.toLocaleString();
    document.getElementById('stat-blocked').textContent = blocked.toLocaleString();
    document.getElementById('stat-warned').textContent  = warned.toLocaleString();
    document.getElementById('stat-allowed').textContent = allowed.toLocaleString();

    // Progress bars — each as % of total
    const pct = (n) => total > 0 ? Math.round((n / total) * 100) : 0;
    document.getElementById('fill-total').style.width   = '100%';
    document.getElementById('fill-blocked').style.width = `${pct(blocked)}%`;
    document.getElementById('fill-warned').style.width  = `${pct(warned)}%`;
    document.getElementById('fill-passed').style.width  = `${pct(allowed)}%`;

    // Platform traffic list
    const bar = document.getElementById('platform-bar');
    bar.innerHTML = '';
    const sorted = Object.entries(this.#platforms).sort((a, b) => b[1] - a[1]);
    for (const [plat, count] of sorted) {
      const row = document.createElement('div');
      row.className = 'platform-row';
      row.innerHTML = `
        <span class="platform-dot" style="background:${StatsManager.#dotColor(plat)}"></span>
        <span class="platform-name">${StatsManager.#friendlyName(plat)}</span>
        <span class="platform-count">${count}</span>`;
      bar.appendChild(row);
    }
  }
}
