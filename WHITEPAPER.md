# 🛡️ VibeCheck — Malware Scanner for AI-Generated Code

> **Version:** 1.0.0  
> **Repository:** [github.com/rasrobo/sqs-vibe-check](https://github.com/rasrobo/sqs-vibe-check)  
> **Marketplace:** Installable as a one-click app on any Claw Way VPS  
> **Engine:** ClamAV (Cisco Talos, open source GPLv2)

---

## Abstract

VibeCheck is an open-source malware and virus scanner purpose-built for
AI-generated and "vibe-coded" repositories. As LLMs produce more code that
gets shipped to production without human review, the attack surface for
supply-chain malware expands. VibeCheck provides a zero-friction way to
scan any Git repository — public or private — for known malware signatures
before deploying.

---

## Table of Contents

1. [Motivation](#1-motivation)
2. [Architecture](#2-architecture)
3. [Installation](#3-installation)
4. [API Reference](#4-api-reference)
5. [Frontend](#5-frontend)
6. [Security Model](#6-security-model)
7. [Marketplace Integration](#7-marketplace-integration)
8. [CI/CD Integration](#8-cicd-integration)
9. [Development Guide](#9-development-guide)
10. [Roadmap](#10-roadmap)

---

## 1. Motivation

### The Problem

LLMs generate code at incredible speed. A developer can prompt an AI to
"build a React dashboard" and have hundreds of files in seconds. But:

- LLMs can hallucinate package names that don't exist yet — an attacker
  can publish a malicious package under that name (dependency confusion).
- LLMs can be prompted to include known-vulnerable code or backdoors.
- Vibe-coded projects often skip traditional code review because the
  output feels "correct" even when it isn't.
- Malware in AI-generated code is a growing attack vector with no
  dedicated defense tool.

### The Solution

VibeCheck wraps ClamAV — the industry-standard open-source antivirus
engine maintained by Cisco Talos — in a developer-friendly Docker image
and web UI. Paste a GitHub URL, VibeCheck clones it, scans every file,
and reports any threats found.

---

## 2. Architecture

```
┌─────────────┐     ┌──────────────────┐     ┌───────────┐
│   Browser   │────▶│  Caddy / nginx   │────▶│  Express  │
│  (xterm.js) │     │  reverse proxy   │     │  Server   │
└─────────────┘     └──────────────────┘     └─────┬─────┘
                                                    │
                          ┌─────────────────────────┴──────────┐
                          │                                     │
                    ┌─────▼──────┐                      ┌───────▼──────┐
                    │   clamscan │                      │   git clone  │
                    │  (ClamAV)  │                      │  (via exec)  │
                    └────────────┘                      └──────────────┘
                          │                                     │
                    ┌─────▼──────┐                      ┌───────▼──────┐
                    │  /var/lib/ │                      │   /repos/    │
                    │clamav/*.cvd│                      │  (mounted)   │
                    └────────────┘                      └──────────────┘
```

### Stack

| Component | Technology | Purpose |
|---|---|---|
| Web server | Express (Node.js 20) | HTTP API, static file serving |
| Scanner | ClamAV (clamscan) | Signature-based malware detection |
| Auth | JWT (jsonwebtoken) | Guest tokens + claw_auth SSO |
| Frontend | Vanilla HTML/CSS/JS | Dark-themed web UI |
| Container | Docker, single image | Node + ClamAV + git bundled |

---

## 3. Installation

### Standalone (Docker)

```bash
git clone https://github.com/rasrobo/sqs-vibe-check.git
cd sqs-vibe-check/registry/vibecheck
docker compose up -d
# UI at http://localhost:3210
```

### Marketplace (Claw Way VPS)

1. Navigate to Apps in your Hub dashboard
2. Click Install on the VibeCheck card
3. Visit `https://vibecheck.{claw}.sqs.chat`
4. Paste a GitHub URL and scan

### CLI

```bash
# Scan a local directory using the standalone script
./vibecheck-scan /path/to/repo

# Or use the official ClamAV Docker image
docker run --rm -v /path/to/repo:/scan:ro clamav/clamav:latest \
  clamscan -r --infected --no-summary /scan
```

---

## 4. API Reference

### Authentication

All endpoints except `/health` require a JWT bearer token.

**Guest token** (no login required):
```bash
curl -X POST https://vibecheck.host/api/auth/guest
# → { "token": "eyJ...", "name": "Guest XXXX" }
```

**SSO via claw_auth cookie** (when deployed in SQS Marketplace):
```bash
curl -H "Cookie: claw_auth=..." https://vibecheck.host/api/auth/session
# → { "token": "eyJ...", "email": "...", "name": "..." }
```

### Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/health` | None | Health check → `{"status":"ok"}` |
| POST | `/api/auth/guest` | None | Create ephemeral guest session |
| GET | `/api/auth/session` | Cookie | SSO via claw_auth JWT cookie |
| GET | `/api/repos` | Bearer | List cloned repos on disk |
| POST | `/api/repos/clone` | Bearer | Clone a GitHub repo (optional PAT) |
| DELETE | `/api/repos/:name` | Bearer | Delete a cloned repo |
| GET | `/api/scans` | Bearer | Scan history (in-memory) |
| POST | `/api/scan` | Bearer | Run a ClamAV scan |
| GET | `/api/scan/:id` | Bearer | Poll scan results |

### POST /api/scan

```json
{
  "target": "/repos/user-repo",
  "tracked_only": true
}
```

- `target`: Path to repo (from `/api/repos`)
- `tracked_only`: If `true`, only scans `git ls-files` — skips `node_modules`, `.git`, etc.

Returns immediately with a `scan_id`. Poll `GET /api/scan/:id` for results.

### POST /api/repos/clone

```json
{
  "url": "https://github.com/user/repo",
  "token": "github_pat_..."  // optional, for private repos
}
```

---

## 5. Frontend

The web UI is a single-page application with:

- **Clone from GitHub** — paste a URL and optional PAT, server clones via `git clone --depth 1`
- **Scan Local Repo** — select from repos on disk, scan with tracked-only mode
- **Real-time results** — polls every 2s while scanning, shows infected files + signatures
- **Repos list** — view and delete cloned repos
- **Scan history** — last 50 scans, chronologically

### UI States

```
🛡️ VibeCheck — Malware Scanner for AI-Generated Code

┌──────────────────────┐  ┌──────────────────────┐
│ Clone from GitHub     │  │ Scan Local Repo      │
│ [url______________]   │  │ [repo-select ▼]      │
│ [pat···············]  │  │ ☑ Tracked files only │
│ [Clone & Scan]        │  │ [Scan]               │
│ ✅ Cloned as user-repo│  └──────────────────────┘
└──────────────────────┘

┌─────────────────────────────────────────────┐
│ Results                                      │
│ ✓ Clean — no threats detected               │
│ Scanned 847 files · 0 infected · 0 errors    │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Repos on Disk                   [Refresh]    │
│ 📁 user-repo                    Delete       │
│ 📁 another-repo                 Delete       │
└─────────────────────────────────────────────┘

┌─────────────────────────────────────────────┐
│ Scan History                    [Refresh]    │
│ user-repo      0 threats   Jun 10 14:32     │
│ another-repo   2 threats   Jun 10 14:28     │
└─────────────────────────────────────────────┘
```

---

## 6. Security Model

### Authentication

- **Guest tokens** — auto-provisioned on first API call, stored in `localStorage`, valid 4h
- **claw_auth SSO** — when deployed via SQS Marketplace, Caddy's forward_auth sets a JWT cookie that the app decodes
- **No passwords stored** — GitHub PATs are sent in the request body, not persisted

### Scan Isolation

- ClamAV runs as `clamav` user (not root) inside the container
- `clamscan` cannot write to scanned directories (mounted `:ro`)
- Temp file lists (`/tmp/vc-*.txt`) are cleaned up after each scan

### Network

- Outbound: only to GitHub (for `git clone`)
- Inbound: only port 3210 (Express server)
- No database, no persistent storage beyond the ClamAV signature volume

### Container Hardening

- Single-purpose image: `FROM node:20-alpine` + ClamAV + git
- ClamAV signatures pre-downloaded at build time (cached layer)
- `start_period: 90s` for freshclam first-run
- No root processes — Express runs as `node`

---

## 7. Marketplace Integration

VibeCheck is designed as a drop-in app for any Docker-compose-based app
marketplace. The integration requires:

### 7.1 Registry Structure

```
registry/vibecheck/
├── server.js       — Express API (160 lines)
├── package.json    — Dependencies (express, jsonwebtoken, cookie-parser)
├── Dockerfile      — Node 20 + ClamAV + git
├── docker-compose.yml — Local dev
└── public/
    └── index.html  — Web UI
```

### 7.2 Compose Template

The compose template needs:
- `clamav-db` named volume (persists signatures across restarts)
- `/opt/claw/git:/repos:ro` bind mount for persistent repo storage
- `start_period: 90s` (freshclam first-run takes 60–90s)
- Port 3210, `sqs.app_id=vibecheck` label

### 7.3 Env Vars

```
PORT=3210
SCAN_ROOT=/repos
JWT_SECRET=<random 32-byte hex>
CLAW_SESSION_SECRET=<shared marketplace secret>
NODE_ENV=production
```

### 7.4 Caddy Route

```caddy
vibecheck.{claw}.sqs.chat {
  @api path /api/*
  handle @api {
    reverse_proxy app:3210
  }
  handle {
    reverse_proxy app:3210
    @not_authed not header_regexp claw Cookie claw_auth=.+
    redir @not_authed https://hub.sqs.chat/go/{claw}?returnTo={scheme}://{host}{uri}
  }
}
```

---

## 8. CI/CD Integration

### GitHub Actions

```yaml
name: VibeCheck Malware Scan
on:
  pull_request:
    branches: [main]
jobs:
  vibecheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Update ClamAV signatures
        run: docker run --rm -v clamav-db:/var/lib/clamav \
          clamav/clamav:latest freshclam --quiet
      - name: Scan repo
        run: docker run --rm -v ${{ github.workspace }}:/scan:ro \
          -v clamav-db:/var/lib/clamav \
          clamav/clamav:latest \
          clamscan -r --infected --no-summary /scan
```

### Pre-commit Hook

```bash
#!/bin/bash
docker run --rm -v $(pwd):/scan:ro -v clamav-db:/var/lib/clamav \
  clamav/clamav:latest clamscan -r --infected --no-summary /scan
```

---

## 9. Development Guide

### Prerequisites

- Docker + Docker Compose
- Node.js 20+ (for local dev without Docker)

### Local Dev

```bash
# Clone
git clone https://github.com/rasrobo/sqs-vibe-check.git
cd sqs-vibe-check/registry/vibecheck

# Run with Docker
docker compose up --build

# Or run directly (without ClamAV, for API testing)
npm install
SCAN_ROOT=/tmp/repos node server.js
```

### Project Structure

```
sqs-vibe-check/
├── README.md                      # This file
├── PROMPT.md                      # Developer prompt for LLM sessions
├── HUB_INTEGRATION.md             # Marketplace wiring guide
├── LICENSE                        # MIT
├── CONTRIBUTING.md                # How to contribute
├── SECURITY.md                    # Security reporting
├── vibecheck-scan                 # Standalone CLI wrapper
├── cron.example                   # Cron/scheduled scanning
├── github-actions.example.yml     # CI/CD integration
└── registry/
    └── vibecheck/
        ├── server.js              # Express API
        ├── package.json           # Node deps
        ├── Dockerfile             # Container build
        ├── docker-compose.yml     # Local dev
        └── public/
            └── index.html         # Web UI
```

### Adding Features

The codebase is intentionally small (~160 lines server, ~200 lines HTML).
The architecture follows a "single file" philosophy — each component is
a single file that's easy to read and modify.

**To add a new API endpoint:**
Add a route handler in `server.js`. Auth is handled by `requireAuth` middleware.

**To add a new frontend feature:**
Edit `public/index.html`. The JavaScript uses `async function api()` for all
API calls and auto-provisions guest tokens.

---

## 10. Roadmap

### Phase 1 — Core (current)
- [x] ClamAV integration with clamscan
- [x] Web UI with repo clone + scan
- [x] GitHub PAT support for private repos
- [x] Tracked-only mode (git ls-files)
- [x] Marketplace integration (11-step wiring)
- [x] Guest auth + claw_auth SSO
- [x] Caddy/nginx route with API bypass
- [x] CLI wrapper (vibecheck-scan)

### Phase 2 — Depth
- [ ] YARA rule support (custom signature files)
- [ ] Schedule recurring scans (cron/systemd timer)
- [ ] Email/webhook notifications on threat detection
- [ ] Slack/Discord integration
- [ ] Scan results export (JSON/CSV/SARIF)

### Phase 3 — Scale
- [ ] PostgreSQL-backed scan history (replace in-memory)
- [ ] Multi-claw scanning (scan the same repo on every claw)
- [ ] GitHub webhook integration (auto-scan on push)
- [ ] GitLab/Bitbucket support
- [ ] Sbom generation (dependency listing alongside scan)

### Phase 4 — Ecosystem
- [ ] VibeCheck-as-a-Service (hosted scanning API)
- [ ] VS Code extension (scan before commit)
- [ ] Pre-commit hook installer
- [ ] Prometheus metrics for scan operations
- [ ] Terraform/Ansible module for automated deployment

---

## License

MIT — the underlying ClamAV engine is GPLv2 (Cisco Talos).
VibeCheck is not affiliated with or endorsed by Cisco Talos.

---

*"Before you ship what the LLM wrote — run a VibeCheck."*
