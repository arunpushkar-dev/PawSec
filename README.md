# 🐾 PawSec

> **Stop sensitive data from reaching AI chat platforms — before you press Enter.**

[![License: MIT](https://img.shields.io/badge/License-MIT-pink.svg)](LICENSE)
[![Chrome Extension](https://img.shields.io/badge/Chrome-MV3-blue?logo=googlechrome)](pawsec-extension/)
[![Firefox Extension](https://img.shields.io/badge/Firefox-MV2-orange?logo=firefox)](pawsec-extension/)
[![Edge Extension](https://img.shields.io/badge/Edge-MV3-teal?logo=microsoftedge)](pawsec-extension/)
[![FastAPI](https://img.shields.io/badge/Server-FastAPI-009688?logo=fastapi)](pawsec-server/)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python)](pawsec-server/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

---

## 🔍 The Problem

Every time an employee types into ChatGPT, Claude, Gemini, or any AI assistant, they risk:

- Pasting API keys, passwords, or database credentials
- Sharing patient records, SSNs, or financial data
- Sending internal business data to a third-party service
- Being manipulated by a colleague's malicious prompt injection
- Leaking source code with embedded secrets

Traditional DLP tools act **after** data leaves. By then, it's too late.

---

## ✅ The Solution

PawSec is a **three-tier prompt security system** that intercepts AI prompts in the browser *before* they are submitted — with zero latency and zero data leaving your machine.

```
You type → PawSec analyzes → Risk assessed → Block / Warn / Allow → Then submitted
```

No proxy. No traffic rerouting. No cloud dependency. Just a browser extension that reads the prompt, checks it, and stops it if needed.

---

## ✨ Key Features

- **9 in-browser detectors** — all run locally, in milliseconds, before any network request
- **Zero-latency protection** — analysis completes before the prompt is submitted
- **Works on 6 major AI platforms** — ChatGPT, Claude, Gemini, Perplexity, Microsoft Copilot, Grok
- **Block or Warn** — configurable thresholds; show a warning or hard-block the submission
- **Optional LLM deep analysis** — pair with a local Ollama model for semantic threat detection
- **Privacy-first** — raw prompts are never stored; only masked text (PII replaced with `█████`)
- **Real-time dashboard** — live WebSocket feed of sessions, prompts, and risk scores
- **Multi-user / multi-tenant** — API key auth, per-user session tracking, admin panel
- **Cross-browser** — Chrome MV3, Firefox MV2, Edge MV3

---

## 🛡️ What It Detects

| Detector | What It Catches | Risk |
|---|---|---|
| **PII** | Names, SSNs, emails, phone numbers, driver's licences (all 50 US states) | HIGH–CRITICAL |
| **PHI** | Patient data, diagnoses, medical record numbers, prescription info | HIGH–CRITICAL |
| **API Secrets** | AWS keys, GitHub tokens, Stripe keys, JWT tokens, OAuth secrets | CRITICAL |
| **Credentials** | Passwords, connection strings, private keys | CRITICAL |
| **Code Injection** | SQL injection, shell commands, XSS, path traversal in prompts | HIGH–CRITICAL |
| **Private URLs** | Internal IPs, localhost URLs, VPN endpoints, cloud metadata endpoints | MEDIUM–HIGH |
| **Business Data** | Company registration numbers, EINs, VAT IDs, SWIFT codes | MEDIUM |
| **Financial Data** | Credit cards, IBAN, bank account numbers, routing numbers | HIGH–CRITICAL |
| **Unknown Malicious Intent** | Jailbreaks, persona overrides, safety bypass phrasing, DAN attacks | CRITICAL |

---

## 🔄 How It Works

```
1. User types a prompt in ChatGPT / Claude / Gemini / etc.

2. PawSec intercepts the submit event (before it reaches the AI)

3. Nine analyzers run in parallel, in milliseconds, entirely in-browser
   ├─ PII detector          ├─ PHI detector
   ├─ API secrets           ├─ Credentials
   ├─ Code injection        ├─ Private URLs
   ├─ Business data         ├─ Financial data
   └─ Unknown malicious intent

4. A weighted risk score (0–100) is computed
   ├─ Score < 30  → ALLOW  (prompt proceeds normally)
   ├─ Score 30–69 → WARN   (user sees a warning banner)
   └─ Score ≥ 70  → BLOCK  (prompt is stopped, overlay shown)

5. Analysis result is sent to the PawSec Server (optional)
   ├─ Safe prompts: sent as [REDACTED], session counter only
   └─ Risky prompts: masked text + full analysis stored for audit

6. Dashboard shows live session activity, risk breakdown, and findings
```

---

## 🏗️ Architecture

PawSec follows a **WAT architecture** — Workflows (config), Agents (the AI), Tools (deterministic execution).

```
┌────────────────────────────────────────────────────────────┐
│                    BROWSER EXTENSION                       │
│  Site Adapters (chatgpt.js, claude.js, gemini.js …)       │
│         ↓ captures submit events                           │
│  AnalysisOrchestrator                                      │
│         ↓ Promise.all (9 analyzers in parallel)            │
│  risk_scorer.js → ALLOW / WARN / BLOCK                     │
│         ↓                                                  │
│  service_worker.js → submitToServer() + badge updates      │
└────────────────────────────┬───────────────────────────────┘
                             │ POST /api/v1/analyze
                             ▼
┌────────────────────────────────────────────────────────────┐
│                     PAWSEC SERVER (FastAPI)                │
│  9 Python skill adapters (ThreadPoolExecutor)              │
│  + Optional Ollama LLM classifier (concurrent)             │
│  risk_adapter.py → final score + action                    │
│  SQLite DB → masked text only (raw never stored)           │
│  WebSocket → live dashboard push                           │
└────────────────────────────────────────────────────────────┘
                             │
                             ▼
┌────────────────────────────────────────────────────────────┐
│                    SKILLS LIBRARY                          │
│  Portable Python + JavaScript detector pairs               │
│  Reusable outside PawSec (standalone CLI / API)            │
└────────────────────────────────────────────────────────────┘
```

**Key design principle:** The JavaScript and Python detectors in each skill pair use identical patterns and return the same schema. In-browser pre-screening and server-side audit always agree.

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Browser Extension | Vanilla JavaScript (ES Modules), MV3/MV2, esbuild |
| Server | Python 3.10+, FastAPI, SQLAlchemy (async), SQLite |
| LLM Analysis (optional) | Ollama (local, any compatible model) |
| Dashboard | Vanilla JS SPA, WebSocket, CSS custom properties |
| Detector Skills | Python 3.10+ (server), JavaScript ES2020 (browser) |
| Build | esbuild (extension), pip (server), Node.js 18+ |

---

## 🚀 Installation

### Prerequisites

- **Node.js 18+** (for building the extension)
- **Python 3.10+** (for the server)
- **Ollama** (optional — for local LLM semantic analysis)

---

### Option A — Quick Start (Extension Only)

The extension works standalone — no server required for core protection.

```bash
# 1. Clone the repo
git clone https://github.com/arunpushkar-dev/PawSec.git
cd pawsec/pawsec-extension

# 2. Install build dependencies
npm install

# 3. Build for all three browsers
npm run build:all
```

Then load the extension into your browser:

- **Chrome / Edge:** Go to `chrome://extensions` → Enable *Developer mode* → *Load unpacked* → select `dist/`
- **Firefox:** Go to `about:debugging` → *This Firefox* → *Load Temporary Add-on* → select any file in `dist-firefox/`

---

### Option B — Full Stack (Extension + Server)

```bash
# Clone
git clone https://github.com/arunpushkar-dev/PawSec.git
cd pawsec

# ── Build the extension ────────────────────────────────────
cd pawsec-extension
npm install
npm run build:all
cd ..

# ── Set up the server ──────────────────────────────────────
cd pawsec-server
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate

pip install -r requirements.txt

# Copy and edit the config
cp .env.example .env
# Edit .env — set PAWSEC_API_KEY to a strong secret

# Start the server
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

On first run, the server prints your admin API key — **save it**.

Open the browser extension settings and enter:
- **Server URL:** `http://localhost:8000`
- **API Key:** *(the key printed at startup)*

---

### Option C — Docker

```bash
git clone https://github.com/arunpushkar-dev/PawSec.git
cd pawsec

# Start the server
docker compose up -d
```

`docker-compose.yml`:

```yaml
version: "3.9"
services:
  pawsec-server:
    build: ./pawsec-server
    ports:
      - "8000:8000"
    environment:
      - PAWSEC_API_KEY=change-me-in-production
      - DB_PATH=/data/pawsec.db
      - OLLAMA_URL=http://host.docker.internal:11434/api/chat
    volumes:
      - pawsec-data:/data

volumes:
  pawsec-data:
```

> **Note:** For LLM analysis, run Ollama on your host and set `OLLAMA_URL` to point to it.

---

## 📖 Usage Guide

### Extension Popup

Click the PawSec icon in your toolbar to see:
- Total / Blocked / Warned prompt counts for the current session
- Enable / Disable toggle
- Link to Settings and Dashboard

### Settings Page

Right-click the extension icon → *Options* (or visit the extension's options page):

| Setting | Description |
|---|---|
| Server URL | Your PawSec Server address (leave blank for offline-only mode) |
| API Key | Key shown at server startup |
| Warn Threshold | Score at which a warning banner appears (default: 30) |
| Block Threshold | Score at which the prompt is hard-blocked (default: 70) |
| Analyzer toggles | Enable / disable individual detectors |
| Local LLM Analysis | Enable Ollama semantic analysis (requires server) |

### Dashboard

Open `http://localhost:8000/dashboard` in your browser.

- View all sessions and prompt history
- Expand any prompt card to see per-detector finding counts
- LLM intent classification tags (if Ollama is enabled)
- Real-time updates via WebSocket

### Admin Panel

Open `http://localhost:8000/dashboard/admin`.

- Manage users and API keys
- View per-user statistics
- Rotate API keys
- Delete user data (GDPR compliance)

---

## ⚙️ Configuration

All server settings are read from `.env`:

```ini
# Required
PAWSEC_API_KEY=your-strong-secret-here

# Optional — defaults shown
DB_PATH=./pawsec.db
HOST=0.0.0.0
PORT=8000

# Ollama (local LLM)
OLLAMA_URL=http://localhost:11434/api/chat
OLLAMA_MODEL=qwen2.5-finetuned
OLLAMA_TIMEOUT=10

# CORS (comma-separated origins, or * for open)
CORS_ORIGINS=*

# Admin bootstrap (used only on first run)
ADMIN_EMAIL=admin@pawsec.local
```

Extension settings sync across devices via `chrome.storage.sync` and are configurable per-user in the Settings page.

---

## 📸 Screenshots

### User Dashboard

![PawSec Security Dashboard — jailbreak prompt blocked at score 70, LLM Analysis chip showing 3 findings: Jailbreak, Unrestricted Assistant, Configuration probing](docs/screenshots/dashboard.png)

### Admin Dashboard

![PawSec Admin Dashboard — enterprise overview showing 2 users, 105 total prompts, 11 blocked, 2 warned, 92 allowed, with per-user breakdown](docs/screenshots/admin_dashboard.png)

### Browser Plugin

![PawSec Browser Plugin popup — Protected status, 8 blocked / 2 warned / 108 total, server connected, signed in as Arun Pushkar X1977](docs/screenshots/browser_plugin.png)

### Plugin Settings

![PawSec Plugin Settings — server configuration, risk thresholds (warn ≥ 30, block ≥ 70), in-browser analyzers toggles, and local LLM analysis option](docs/screenshots/plugin_settings.png)

### Extension Block Overlay

![PawSec Extension Block Overlay — prompt blocked at score 70/100 with Malicious Intent tag on ChatGPT, blurred background, Dismiss button](docs/screenshots/block_overlay.png)

### Extension Warning Banner

![PawSec Extension Warning Banner — sensitive content detected at score 50 with Malicious Intent tag on ChatGPT, Cancel and Send Anyway options](docs/screenshots/warning_banner.png)

---

## 🔌 API Reference

Full interactive docs available at `http://localhost:8000/docs`.

| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/analyze` | API key | Submit a prompt for analysis |
| `POST` | `/api/v1/sessions` | API key | Create a new session |
| `GET` | `/api/v1/stats` | API key | Fetch per-user summary stats |
| `GET` | `/api/v1/me` | API key | Validate key + return user info |
| `GET` | `/health` | None | Server health + Ollama status |
| `GET` | `/api/v1/admin/users` | Admin | List all users |
| `POST` | `/api/v1/admin/users/{id}/rotate-key` | Admin | Rotate a user's API key |
| `DELETE` | `/api/v1/admin/users/{id}/records` | Admin | Wipe user's prompt history |
| `WS` | `/ws/dashboard` | token param | Real-time prompt push events |

**Example — analyze a prompt:**

```bash
curl -X POST http://localhost:8000/api/v1/analyze \
  -H "X-API-Key: your-api-key" \
  -H "Content-Type: application/json" \
  -d '{
    "prompt_text": "My AWS key is AKIAIOSFODNN7EXAMPLE",
    "platform": "chatgpt.com",
    "session_id": "your-session-id",
    "analyzers_requested": ["pii", "api_secrets", "credentials", "risk"]
  }'
```

**Response:**

```json
{
  "prompt_id": "prt_a1b2c3d4e5f6g7h8",
  "action_taken": "BLOCKED",
  "risk_score": 94,
  "risk_level": "CRITICAL",
  "analysis": {
    "api_secrets": { "detected": true, "count": 1, "risk_level": "CRITICAL" },
    "pii": { "detected": false, "count": 0, "risk_level": "SAFE" }
  },
  "recommendations": ["Remove API keys before submitting to AI services."]
}
```

---

## 📁 Project Structure

```
pawsec/
│
├── pawsec-extension/              # Browser extension
│   ├── src/
│   │   ├── analyzers/             # 9 JavaScript detector modules
│   │   │   ├── pii_detector.js
│   │   │   ├── phi_detector.js
│   │   │   ├── api_secrets_detector.js
│   │   │   ├── credentials_detector.js
│   │   │   ├── code_injection_detector.js
│   │   │   ├── private_url_detector.js
│   │   │   ├── business_data_detector.js
│   │   │   ├── financial_data_detector.js
│   │   │   ├── unknown_malicious_intent_detector.js
│   │   │   └── risk_scorer.js
│   │   ├── content/
│   │   │   ├── content_base.js    # Intercept + orchestration
│   │   │   ├── ui/
│   │   │   │   └── warning_banner.js
│   │   │   └── sites/             # Per-platform adapters
│   │   │       ├── chatgpt.js
│   │   │       ├── claude.js
│   │   │       ├── gemini.js
│   │   │       ├── perplexity.js
│   │   │       ├── copilot.js
│   │   │       └── grok.js
│   │   ├── popup/                 # Extension popup UI
│   │   ├── settings/              # Settings page
│   │   └── background/
│   │       └── service_worker.js  # Badge, stats, server relay
│   ├── manifest.chrome.json
│   ├── manifest.firefox.json
│   ├── manifest.edge.json
│   ├── build.js                   # esbuild pipeline
│   └── make_icons.py              # Icon generator (Pillow)
│
├── pawsec-server/                 # FastAPI backend
│   ├── main.py                    # App entry point + lifespan
│   ├── config.py                  # Settings from .env
│   ├── api/
│   │   ├── routes/
│   │   │   ├── analyze.py         # POST /api/v1/analyze
│   │   │   ├── sessions.py        # Session + prompt endpoints
│   │   │   ├── stats.py           # Stats endpoint
│   │   │   ├── health.py          # Health check
│   │   │   └── admin.py           # Admin user management
│   │   ├── auth.py                # API key + localhost bypass
│   │   ├── models.py              # Pydantic request/response models
│   │   └── websocket.py           # WS connection manager
│   ├── analyzers/                 # Python skill adapters
│   │   ├── analyzer_runner.py     # Parallel orchestration
│   │   ├── pii_adapter.py
│   │   ├── phi_adapter.py
│   │   ├── api_secrets_adapter.py
│   │   ├── credentials_adapter.py
│   │   ├── code_injection_adapter.py
│   │   ├── private_url_adapter.py
│   │   ├── business_data_adapter.py
│   │   ├── financial_data_adapter.py
│   │   ├── unknown_malicious_intent_adapter.py
│   │   ├── llm_adapter.py
│   │   └── risk_adapter.py
│   ├── database/
│   │   ├── models.py              # SQLAlchemy: User, Session, PromptRecord
│   │   ├── crud.py                # Async CRUD operations
│   │   └── db.py                  # Async engine + session factory
│   └── dashboard/                 # SPA dashboards (served as static)
│       ├── index.html             # User dashboard
│       ├── css/dashboard.css
│       ├── js/
│       │   ├── app.js
│       │   ├── stats.js
│       │   ├── sessions.js
│       │   ├── session_detail.js
│       │   ├── prompt_detail.js
│       │   └── websocket_client.js
│       └── admin/
│           └── index.html         # Admin dashboard
│
└── skills/                        # Portable, standalone detectors
    ├── pii-detector/
    ├── phi-detector/
    ├── api-secrets-detector/
    ├── credentials-detector/
    ├── code-injection-detector/
    ├── private-url-detector/
    ├── business-data-detector/
    ├── financial-data-detector/
    ├── unknown-malicious-intent-detector/
    └── CONTRIBUTING.md            # Sync rule + how to add a detector
```

---

## 🤝 Contributing

Contributions are welcome — especially new detectors, new site adapters, and dashboard improvements.

### Getting Started

```bash
git clone https://github.com/arunpushkar-dev/PawSec.git
cd pawsec/pawsec-extension
npm install
npm run dev          # Chrome dev build (unminified, auto-rebuilds)
```

### Adding a New Detector

Every detector is a **matched pair**: one Python file (server-side) and one JavaScript file (browser-side). They must use identical patterns and return the same schema.

1. Create `skills/<name>/tools/<name>.py`
2. Create `pawsec-extension/src/analyzers/<name>.js` (same patterns + return shape)
3. Import and add to `Promise.all` in `src/content/content_base.js`
4. Add weight in `src/analyzers/risk_scorer.js` — rebalance all weights to sum to `1.0`
5. Add finding tag in `src/content/ui/warning_banner.js` → `buildFindingTags()`
6. Add adapter in `pawsec-server/analyzers/<name>_adapter.py`
7. Add to `analyzer_runner.py` and `_SAFE_DEFAULTS`
8. Add chip row in `pawsec-server/dashboard/js/prompt_detail.js`
9. Update `skills/CONTRIBUTING.md`
10. Run `npm run build:all` and verify all three distributions build cleanly

### Scope Rule (Important)

Each detector owns **only** what its name implies:
- PII detector → personal identity data only
- PHI detector → healthcare/medical data only
- Credentials detector → authentication secrets only
- etc.

If a pattern doesn't fit a detector's named domain, it belongs in the correct detector or a new one — never appended to the nearest "close enough" file.

### Adding a New Site Adapter

1. Create `pawsec-extension/src/content/sites/<platform>.js`
2. Follow the pattern of existing adapters: `INPUT_SEL`, `getText()`, `listenersAttached` guard, persistent MutationObserver
3. Register the match pattern in all three manifests
4. Add the platform icon to the dashboard (`session_detail.js` → `PLATFORM_ICONS`)

### Code Style

- JavaScript: ES Modules, no frameworks, no TypeScript
- Python: `async/await`, Pydantic v2, no ORM magic outside `database/`
- Tests: `pytest` for Python skills (see `skills/code-injection-detector/tests/`)

---

## 🗺️ Roadmap

| Priority | Item |
|---|---|
| 🔴 High | Firefox store submission |
| 🔴 High | Chrome Web Store submission |
| 🟡 Medium | Organization-wide policy sync (MDM / admin-pushed config) |
| 🟡 Medium | Export session history as PDF / CSV |
| 🟡 Medium | Slack / Teams alert integration for blocked prompts |
| 🟢 Low | Safari extension (MV3) |
| 🟢 Low | Custom pattern rules (user-defined regex) |
| 🟢 Low | Fine-tuned open-source LLM for semantic analysis |
| 🟢 Low | SIEM log output (CEF / JSON syslog) |
| 🟢 Low | Multi-language PII support (EU locales) |

---

## 🔒 Security Considerations

**Privacy by design:**
- Raw prompt text is **never** stored. Only masked text (PII replaced with `█████`) is persisted.
- ALLOWED prompts (score < 30) are sent to the server as `[REDACTED]` — no text, no analysis.
- The server only stores text for prompts that scored ≥ 30 (WARN or BLOCK), and even then only the masked version.

**Self-hosted:**
- PawSec Server is designed to run entirely on your own infrastructure.
- No external SaaS dependency. No telemetry.

**API Key security:**
- Generate a strong, random `PAWSEC_API_KEY` before production deployment.
- The default `dev-key-change-in-production` is intentionally weak — replace it.
- Localhost (`127.0.0.1`) requests are auto-authenticated as admin for local dev convenience. Set `CORS_ORIGINS` explicitly in production.

**Extension permissions:**
- The extension only requests host permissions for the six supported AI platforms.
- No `<all_urls>` permission. No access to other sites.

**Responsible use:**
- This tool is designed for **data loss prevention**, not surveillance.
- Do not deploy in a way that monitors employee communications without disclosure.
- Review your jurisdiction's requirements before enterprise deployment.

---

## 📄 License

This project is licensed under the **MIT License** — see [LICENSE](LICENSE) for details.

---

## 👤 Author / Maintainer

**PawSec** was built as an open-source security tool for teams using AI assistants.

- GitHub: [@arunpushkar-dev](https://github.com/arunpushkar-dev)
- Issues & Feature Requests: [GitHub Issues](https://github.com/arunpushkar-dev/PawSec/issues)
- Security Vulnerabilities: Please report privately via GitHub's Security Advisory feature — do not open a public issue.

---

## ❓ FAQ

**Q: Does PawSec send my prompts to any cloud service?**
> No. All 9 in-browser analyzers run locally inside the browser extension. If you configure a PawSec Server, analysis summaries (masked text only) are sent to *your own server*, which you host. Nothing goes to us.

**Q: Does it work offline?**
> Yes. The in-browser analyzers work with no server configured. The extension will block and warn entirely offline. The server is only needed for the audit dashboard and optional Ollama LLM analysis.

**Q: Will it slow down my browser or the AI chat site?**
> No measurable impact. All 9 analyzers run in under 5ms for typical prompts. The analysis completes in the same event loop tick as the submit event.

**Q: Can it be bypassed?**
> The extension intercepts submit events at the capture phase, which runs before the page's own handlers. It also covers keyboard submission, button clicks, and pointer events. However, it is a client-side control — a determined and technically sophisticated user could bypass it. For enterprise use, pair it with server-side controls.

**Q: Does it work with custom enterprise versions of ChatGPT / Copilot?**
> Currently, adapters target the public-facing hostnames. Enterprise deployments on custom domains would need a custom adapter. This is on the roadmap.

**Q: How do I add a new AI platform?**
> See the **Adding a New Site Adapter** section under Contributing.

**Q: What Ollama model should I use?**
> Any instruction-tuned model works. The default config uses `qwen2.5-finetuned`. For best results, use a model fine-tuned for security classification. The Ollama analysis is optional — regex-based detection works without it.

---

## ⚡ Quick Start (TL;DR)

```bash
# 1. Clone and build the extension
git clone https://github.com/arunpushkar-dev/PawSec.git
cd pawsec/pawsec-extension && npm install && npm run build

# 2. Load dist/ into Chrome (chrome://extensions → Developer mode → Load unpacked)

# 3. (Optional) Start the server
cd ../pawsec-server && pip install -r requirements.txt
cp .env.example .env && uvicorn main:app --port 8000

# 4. Open ChatGPT and type something with a password in it — PawSec will stop it
```

That's it. PawSec is now watching.

---

<div align="center">

Made with 🐾 to keep your data safe from AI.

[Report a Bug](https://github.com/arunpushkar-dev/PawSec/issues) · [Request a Feature](https://github.com/arunpushkar-dev/PawSec/issues) · [Read the Docs](http://localhost:8000/docs)

</div>
