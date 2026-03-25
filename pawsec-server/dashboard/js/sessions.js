/**
 * Sessions sidebar — paginated list with search + filter.
 */

const PLATFORM_ICONS = {
  chatgpt: '🤖', claude: '🔶', gemini: '💎',
  perplexity: '🔍', copilot: '💠', grok: '𝕏', unknown: '❓'
};

export class SessionsManager {
  #sessions = [];
  #filter = 'all';
  #search = '';
  #onSelect;
  #apiBase;
  #apiKey;

  constructor(apiBase, apiKey, onSelect) {
    this.#apiBase = apiBase;
    this.#apiKey  = apiKey;
    this.#onSelect = onSelect;
    this.#bindControls();
  }

  // Returns the cleared-at timestamp in ms, or 0 if not set
  static #clearedAt() {
    const v = localStorage.getItem('pawsec_local_cleared_at');
    return v ? new Date(v).getTime() : 0;
  }

  getSessions() { return this.#sessions; }

  async load() {
    try {
      const clearedAt = localStorage.getItem('pawsec_local_cleared_at');
      const qs = new URLSearchParams({ page: 1, page_size: 50 });
      if (clearedAt) qs.set('since', clearedAt);
      const res = await fetch(`${this.#apiBase}/api/v1/sessions?${qs}`, {
        headers: this.#apiKey ? { 'X-API-Key': this.#apiKey } : {}
      });
      if (!res.ok) return;
      const data = await res.json();
      this.#sessions = data.sessions ?? [];
      document.getElementById('session-count').textContent = `${this.#sessions.length} total`;
    } catch { /* offline */ }
    this.#render();
  }

  prependSession(event) {
    // Skip events that pre-date the last Clear View
    const clearedAt = SessionsManager.#clearedAt();
    if (clearedAt && new Date(event.timestamp).getTime() <= clearedAt) return;
    // Add stub session from WS event; full detail loads on click
    const existing = this.#sessions.find(s => s.session_id === event.session_id);
    if (existing) {
      existing.prompt_count = (existing.prompt_count ?? 0) + 1;
      if (event.action_taken === 'BLOCKED') existing.blocked_count = (existing.blocked_count ?? 0) + 1;
      else if (event.action_taken === 'WARNED')  existing.warned_count  = (existing.warned_count  ?? 0) + 1;
      else existing.allowed_count = (existing.allowed_count ?? 0) + 1;
    } else {
      this.#sessions.unshift({
        session_id:    event.session_id,
        started_at:    event.timestamp,
        platform_hint: event.platform,
        prompt_count:  1,
        blocked_count: event.action_taken === 'BLOCKED' ? 1 : 0,
        warned_count:  event.action_taken === 'WARNED'  ? 1 : 0,
        allowed_count: event.action_taken === 'ALLOWED' ? 1 : 0,
      });
    }
    this.#render();
  }

  #bindControls() {
    document.getElementById('search-input').addEventListener('input', (e) => {
      this.#search = e.target.value.trim().toLowerCase();
      this.#render();
    });

    document.querySelectorAll('.filter-btn').forEach(btn => {
      btn.addEventListener('click', () => {
        document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
        btn.classList.add('active');
        this.#filter = btn.dataset.filter;
        this.#render();
      });
    });
  }

  #render() {
    const list = document.getElementById('sessions-list');
    const filtered = this.#sessions.filter(s => {
      // Hide empty sessions (no activity at all — just extension startup artifacts)
      if (!s.prompt_count && !s.blocked_count && !s.warned_count && !s.allowed_count) return false;
      if (this.#filter === 'BLOCKED' && !(s.blocked_count > 0)) return false;
      if (this.#filter === 'WARNED'  && !(s.warned_count  > 0)) return false;
      if (this.#search && !s.session_id.toLowerCase().includes(this.#search) &&
          !(s.platform_hint ?? s.platform ?? '').toLowerCase().includes(this.#search)) return false;
      return true;
    });

    list.innerHTML = '';
    if (!filtered.length) {
      list.innerHTML = '<div style="padding:20px;color:var(--text-muted);text-align:center;font-size:13px;">No sessions found</div>';
      return;
    }

    for (const s of filtered) {
      const el = document.createElement('div');
      el.className = 'session-item';
      el.setAttribute('role', 'listitem');
      el.dataset.sessionId = s.session_id;

      const plat = s.platform_hint ?? s.platform ?? 'unknown';
      const count = s.prompt_count ?? 0;
      const highestBadge = s.blocked_count > 0 ? 'BLOCKED' : s.warned_count > 0 ? 'WARNED' : count > 0 ? 'ALLOWED' : null;
      const time = new Date(s.started_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
      const date = new Date(s.started_at).toLocaleDateString([], { month: 'short', day: 'numeric' });

      el.innerHTML = `
        <div class="session-platform-icon">${PLATFORM_ICONS[plat] ?? '🌐'}</div>
        <div class="session-meta">
          <div class="session-id">${s.session_id}</div>
          <div class="session-time">${date} ${time} · ${plat}</div>
        </div>
        <div class="session-counts">
          <span class="prompt-count">${count} prompts</span>
          ${highestBadge ? `<span class="risk-badge ${highestBadge}">${highestBadge}</span>` : ''}
        </div>`;

      el.addEventListener('click', () => {
        document.querySelectorAll('.session-item.active').forEach(i => i.classList.remove('active'));
        el.classList.add('active');
        this.#onSelect(s.session_id);
      });
      list.appendChild(el);
    }
  }
}
