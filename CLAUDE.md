# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What This Project Is

**PawSec** is a three-tier prompt security system that intercepts and analyzes prompts before they are sent to AI chat platforms (ChatGPT, Claude.ai, Gemini, Perplexity, Copilot, Grok).

- **`pawsec-extension/`** — Browser extension (MV3 Chrome, MV2 Firefox, MV3 Edge) that runs 8 in-browser analyzers before any prompt is submitted
- **`pawsec-server/`** — FastAPI backend for deep analysis, session tracking, and the admin/user dashboards
- **`skills/`** — Portable, self-contained detector modules (Python primary, JavaScript mirror)

---

## Build Commands

### Browser Extension

All commands run from `pawsec-extension/`:

```bash
npm run build:all       # Build all three distributions (Chrome, Firefox, Edge)
npm run build           # Chrome only (minified) → dist/  and mirrors icons to dist-chrome/
npm run build:firefox   # Firefox MV2 → dist-firefox/
npm run build:edge      # Edge MV3 → dist-edge/
npm run dev             # Chrome dev build (unminified) → dist/
npm run package:all     # Build + zip all three for store submission
```

Output folders: `dist/` (Chrome), `dist-chrome/` (legacy mirror, kept in sync by `build.js`), `dist-firefox/`, `dist-edge/`

**Always run `npm run build` after editing any `src/` file.** The extension loads from `dist/`, not `src/`.

**To regenerate extension icons** (after colour/shape changes):
```bash
python make_icons.py    # writes to pawsec-extension/icons/, then rebuild
npm run build           # copies new icons into dist/ and dist-chrome/
```

### Server

Run from `pawsec-server/`:

```bash
pip install -r requirements.txt
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Copy `.env.example` → `.env` and set `PAWSEC_API_KEY` before running.

### Skill Tests

```bash
# Run the code injection detector tests (only skill with tests currently)
python -m pytest skills/code-injection-detector/tests/
```

---

## Architecture

### Extension Data Flow

```
User types in ChatGPT/Claude/etc.
  ↓
Site adapter (src/content/sites/<platform>.js)
  intercepts submit via keydown / click / pointerdown / form capture-phase listener
  ↓
content_base.js — InterceptManager.handleCapture()
  event.preventDefault() + stopImmediatePropagation()
  ↓
AnalysisOrchestrator — runs 8 analyzers in parallel via Promise.all
  + optional LLM pre-check via Ollama (runs concurrently, 8 s abort timeout)
  ↓
risk_scorer.js — computes weighted score (0–100)
  More severe of (in-browser score, LLM score) is used as finalAction
  ↓
ALLOW  → PAWSEC_ALLOWED → service_worker → session allowed_count++
WARN   → PAWSEC_WARNED  → service_worker → warned stat++ + warning banner shown
BLOCK  → PAWSEC_BLOCKED → service_worker → blocked stat++ + badge count + block overlay
  ↓
PAWSEC_ANALYSIS always sent → service_worker → submitToServer()
  ↓
POST /api/v1/analyze (if server configured):
  score < min_score_to_send (30) → sends [REDACTED] + analyzers_requested:[] → session counter only
  score ≥ 30                     → sends full text + all analyzers → prompt record stored (masked)
```

### Message Protocol (content scripts ↔ service worker)

| Message type | Sender | Receiver | Purpose |
|---|---|---|---|
| `PAWSEC_ANALYSIS` | content_base | SW | Every captured prompt — triggers server submission |
| `PAWSEC_BLOCKED` | content_base | SW | Prompt blocked — badge count + blocked stat |
| `PAWSEC_WARNED` | content_base | SW | Prompt warned — warned stat |
| `PAWSEC_ALLOWED` | content_base | SW | Prompt allowed — total stat |
| `LLM_PRE_CHECK` | content_base | SW | Ollama pre-check — async, returns `{ action, risk_score }` |
| `PAWSEC_TOGGLE` | popup | SW | Enable/disable protection |
| `PAWSEC_CLEAR_STATS` | popup | SW | Reset badge + in-memory blocked count |

Stats (`pawsec_stats: { total, blocked, warned }`) live in `chrome.storage.local`. Popup reads on open and listens via `chrome.storage.onChanged` for live updates.

### Server Submission Semantics

`submitToServer()` in `service_worker.js` **always calls the server** (when configured), but varies what it sends:

- **Safe prompts** (`score < min_score_to_send=30`): `prompt_text: '[REDACTED]'`, `analyzers_requested: []` — server just increments `session.allowed_count`, no text stored or transmitted
- **Risky prompts** (`score ≥ 30`): full text (up to 4000 chars) + all analyzers — server runs deep analysis, stores masked text

This ensures every AI platform session is visible in the dashboard even when prompts score safe.

Offline queue: up to 50 items in `chrome.storage.local` (`pawsec_offline_queue`), flushed on `chrome.runtime.onStartup`. Oldest item dropped when capacity exceeded. No retry/backoff between flushes.

### LLM Parallel Pre-Check

When `az_llm: true` AND `server_url` is configured AND text length ≥ 15:
1. `showAnalyzingIndicator()` is shown immediately
2. In-browser analyzers + `LLM_PRE_CHECK` message run via `Promise.all` (concurrent)
3. Service worker calls `POST /api/v1/analyze` with `analyzers_requested: ['llm','risk']`; aborts after 8 s (fails open → ALLOW)
4. More severe of `(in-browser action, LLM action)` wins using severity map: `BLOCK=3, WARN=2, ALLOW=1`

### Site Adapters Pattern

All six site adapters (`chatgpt.js`, `claude.js`, `gemini.js`, `perplexity.js`, `copilot.js`, `grok.js`) follow the same pattern:

- `INPUT_SEL` — broad selector covering `textarea`, `div[contenteditable]`, `[contenteditable="plaintext-only"]` variants
- `getText(el)` — `el.value ?? el.innerText ?? el.textContent` (handles both textarea and contenteditable)
- `listenersAttached` guard — prevents duplicate `document.addEventListener` calls on SPA navigation
- **Persistent MutationObserver** — never calls `observer.disconnect()`
- All listeners use capture phase

**Gemini is different**: listeners are attached immediately at script load (not gated on `querySelector` match) because Angular may not have rendered the input at `document_idle`. Also has a `pointerdown` fallback because Angular Material buttons may swallow `click` events. Input selector covers `contenteditable="plaintext-only"` (newer Chrome-only mode).

**Grok** matches both `grok.com/*` and `x.com/i/grok*` (specific path within X.com).

### Platform Identifiers

The `platform` field in the database and message bus uses `location.hostname`:

| Platform | hostname value |
|---|---|
| ChatGPT | `chatgpt.com` |
| Claude | `claude.ai` |
| Gemini | `gemini.google.com` |
| Perplexity | `www.perplexity.ai` |
| Copilot | `copilot.microsoft.com` |
| Grok | `x.com` |

Dashboard filter dropdowns must use these exact strings as option values.

### Analyzer / Skill Sync Rule

Every detector exists as a matched pair. **Both files must be kept in sync** — same patterns, same return shape, same field names:

| Python (server + skills/) | JavaScript (extension) |
|---|---|
| `skills/pii-detector/tools/pii_detector.py` | `src/analyzers/pii_detector.js` |
| `skills/phi-detector/tools/phi_detector.py` | `src/analyzers/phi_detector.js` |
| `skills/api-secrets-detector/tools/api_secrets_detector.py` | `src/analyzers/api_secrets_detector.js` |
| `skills/credentials-detector/tools/credentials_detector.py` | `src/analyzers/credentials_detector.js` |
| `skills/code-injection-detector/tools/code_injection_detector.py` | `src/analyzers/code_injection_detector.js` |
| `skills/private-url-detector/tools/private_url_detector.py` | `src/analyzers/private_url_detector.js` |
| `skills/business-data-detector/tools/business_data_detector.py` | `src/analyzers/business_data_detector.js` |
| `skills/financial-data-detector/tools/financial_data_detector.py` | `src/analyzers/financial_data_detector.js` |

### Adding a New Detector

1. Create `skills/<name>/tools/<name>.py`
2. Create `pawsec-extension/src/analyzers/<name>.js` (matching patterns/return shape)
3. Import and add to `Promise.all` in `src/content/content_base.js`
4. Add weight to `src/analyzers/risk_scorer.js` — **rebalance all weights to sum to 1.0**
5. Add finding tag in `src/content/ui/warning_banner.js` → `buildFindingTags()`
6. Add adapter in `pawsec-server/analyzers/` (see Analyzer Adapter Contract below)
7. Add row to `skills/CONTRIBUTING.md`
8. Run `npm run build:all`

### Server Pipeline

`POST /api/v1/analyze` runs all 8 regex skills in a `ThreadPoolExecutor(8)`, concurrently runs the Ollama LLM check, then passes all results to `risk_adapter.py`. Only **masked text** (PII replaced with `█████`) is stored in the database — raw prompts are never persisted. ALLOWED prompts (score < 30) never have their text stored even server-side.

Session lifecycle: 30-min idle timeout, keyed in `chrome.storage.local` as `pawsec_current_session`. Session creation happens inside `ensureSession()` which is called by `submitToServer()` for every prompt sent to the server. The session cache is also keyed by date (YYYY-MM-DD) — a new day always creates a new session regardless of timeout.

### Analyzer Adapter Contract

Each file in `pawsec-server/analyzers/<name>_adapter.py` wraps one Python skill:

- Exports a sync `run(text: str) -> dict` function
- Initializes the detector once at module load
- Returns `_raw` field — full skill output for the risk calculator to access detailed findings
- Returns `_error` field on exception (safe defaults returned, pipeline never crashes)
- If a skill is absent from `analyzers_requested` list, `analyzer_runner.py` returns safe defaults without calling the adapter

### Risk Score Weights (current)

In `src/analyzers/risk_scorer.js`:
- `pii: 0.18, phi: 0.12, code_injection: 0.18, api_secrets: 0.18, credentials: 0.14, private_url: 0.08, business_data: 0.06, financial_data: 0.06`
- Default thresholds: warn ≥ 30, block ≥ 70

**Elevation floors** (override weighted score regardless of weights):
- Any input at CRITICAL → effective score ≥ 70 (BLOCK)
- Any input at HIGH → effective score ≥ 50 (WARN)
- Any input at MEDIUM → effective score ≥ 30 (WARN)
- Code detected but no active threat → effective score ≥ 30 (WARN for user review)

### Database Schema

Three SQLAlchemy models in `pawsec-server/database/models.py`:

**User** — `user_id` (UUID), `api_key` (`psk_` + 24-char base64), `is_admin`, `is_active`, `company_id` (nullable tenant), `last_used_at`

**Session** — `session_id`, `user_id` (FK, nullable for legacy), `platform_hint` (hostname), counters: `prompt_count`, `blocked_count`, `warned_count`, `allowed_count`

**PromptRecord** — `prompt_id` (`prt_` prefix), `session_id`, `user_id`, `masked_text` only (raw never stored), `action_taken`, `risk_level`, `analysis_result` (JSON all 10 outputs), `in_browser_result` (JSON snapshot from extension), denormalized per-detector counts

**Privacy rule**: ALLOWED prompts create NO PromptRecord — only `Session.allowed_count` increments. The dashboard allowed count comes from session counters, not prompt records.

**Startup migrations** (`main.py`): ALTER TABLE adds `user_id` FK columns to sessions and prompt_records if missing (enables zero-downtime upgrades). Orphan sessions (`user_id IS NULL`) are purged at startup.

### Authentication

Two-tier system in `pawsec-server/api/auth.py`:

1. **API key** — `X-API-Key` header validated against `users.api_key`. Updates `last_used_at` on each request.
2. **Localhost trusted bypass** — requests from `127.0.0.1` / `::1` with no API key auto-authenticate as the first active admin. Allows the admin dashboard to work out-of-the-box on localhost. Returns 503 with `no_admin` error code if no admin user exists.

WebSocket auth (`/ws/dashboard`) uses `?token=<api_key>` query param; closes with code 4001 on failure.

### API Endpoints

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/api/v1/analyze` | API key | Main analysis endpoint |
| `POST` | `/api/v1/sessions` | API key | Create session, returns `session_id` |
| `GET` | `/api/v1/stats` | API key | Per-user summary stats |
| `GET` | `/api/v1/me` | API key | Validate key + return user info |
| `GET` | `/health` | None | Ollama probe + DB status |
| `GET` | `/api/v1/admin/users` | Admin | List/manage users |
| `POST` | `/api/v1/admin/users/{id}/rotate-key` | Admin | Regenerate API key |
| `DELETE` | `/api/v1/admin/users/{id}/records` | Admin | Wipe all prompts for user |
| `GET` | `/ws/dashboard` | token param | WebSocket push updates |

`GET /health` probes Ollama at `/api/tags` (3 s timeout) and returns `ollama_available` bool.

### Settings Storage Split

**`chrome.storage.sync`** (synced across devices):
- `server_url`, `server_api_key`
- `warn_threshold`, `block_threshold`
- `pawsec_enabled`
- All 8 analyzer toggles + `az_llm`

**`chrome.storage.local`** (device-local):
- `pawsec_current_session` — session cache with date key
- `pawsec_offline_queue` — failed submissions (max 50)
- `pawsec_stats` — `{ total, blocked, warned }` counters
- `pawsec_user_name`, `pawsec_company_id` — identity fetched from server

### Browser Manifest Differences

Three source manifests in `pawsec-extension/` root, consumed by `build.js`:

| Feature | Chrome (`manifest.chrome.json`) | Firefox (`manifest.firefox.json`) | Edge (`manifest.edge.json`) |
|---|---|---|---|
| MV version | 3 | 2 | 3 |
| Background | `service_worker` + `type: "module"` | `background.scripts[]` array | `service_worker` + `type: "module"` |
| Action key | `action` | `browser_action` | `action` |
| Settings | `options_page` | `options_ui` + `open_in_tab: true` | `options_page` |
| Permissions | `host_permissions` array | `permissions` array | `host_permissions` array |
| Gecko | — | `browser_specific_settings.gecko` | — |
| `tabs` perm | yes | yes | no |

### Dashboard / Admin

The server serves SPAs at `/dashboard` and `/dashboard/admin`. The dashboard CSS lives at `pawsec-server/dashboard/css/dashboard.css` and is shared by both. The admin page has its own inline `<style>` block with a duplicate `:root` — both must be updated together when changing the theme.

Dashboard JS is split into modules: `app.js` (entry), `stats.js`, `sessions.js`, `session_detail.js`, `websocket_client.js`. Auto-refresh runs every 30 s unconditionally (not gated on WebSocket state); WebSocket provides instant updates on top.

### Warning Banner (Shadow DOM)

`src/content/ui/warning_banner.js` uses Shadow DOM (`mode: 'closed'`). All styles are inlined strings inside the JS file — there is no external CSS. SVG filter IDs must be unique per instance (`ps-fluffy`, `pp-fluffy`, `ps-hdr-fluffy`, etc.) to avoid cross-document conflicts.

---

## Key Config

**Extension defaults** (`src/settings/settings.js` and `service_worker.js`):
- `warn_threshold: 30`, `block_threshold: 70`
- `min_score_to_send: 30` — prompts below this score are sent as `[REDACTED]` (session counter only)
- `az_llm: true` — enables parallel Ollama LLM pre-check (requires server + Ollama)
- All 8 in-browser analyzers enabled by default
- No server URL by default

**Server** (`pawsec-server/config.py`): reads from `.env`. Key variables: `PAWSEC_API_KEY`, `DB_PATH`, `OLLAMA_URL`, `OLLAMA_MODEL`, `CORS_ORIGINS`.

**Ollama** is optional — the server degrades gracefully if it's unavailable (LLM check skipped, regex scores still work).

---

## Theming

The UI uses a **light pastel theme** across all surfaces:
- Background: `#fdf6f9` | Cards: `#fff8fb` | Borders: `#f0d6e4`
- Accent (rose): `#c87fa4` / `#a85f84` | Text: `#2d1f2a` / `#6b4f62` / `#a07890`
- These variables are defined in `popup.css`, `settings.css`, `dashboard.css`, and the admin `<style>` block — all four must be kept in sync.

The cat paw logo SVG (`icons/pawsec-logo.svg`) uses `feMorphology dilate` + `feGaussianBlur` + `feFlood` white composite to create the fluffy halo effect. It appears in: `popup.html`, `settings.html`, `dashboard/index.html`, `dashboard/admin/index.html`, and inline in `warning_banner.js`. Extension PNG icons are generated from `make_icons.py` (Pillow only) — they mirror the SVG design (pink `#F2AABD` paw on white rounded-square card with `#f0d6e4` border).
