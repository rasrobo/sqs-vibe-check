# VibeCheck — GitHub-Native Architecture

## Auth Flow (Phase 1: OAuth + Phase 2: GitHub App)

```
Browser                          VibeCheck                     GitHub
  │                                 │                            │
  │  Click "Connect GitHub"         │                            │
  │────────────────────────────────▶│                            │
  │                                 │  GET /api/auth/github/login │
  │                                 │──────────────────────────▶  │
  │                                 │  302 redirect to GitHub    │
  │  Redirect to GitHub OAuth       │                            │
  │◀────────────────────────────────┤                            │
  │                                 │                            │
  │  Authorize on GitHub            │                            │
  │─────────────────────────────────────────────────────────────▶│
  │                                 │                            │
  │  Callback → /api/auth/github/cb│                            │
  │────────────────────────────────▶│                            │
  │                                 │  POST /api/auth/github/token│
  │                                 │──────────────────────────▶  │
  │                                 │  access_token + refresh    │
  │                                 │◀──────────────────────────  │
  │                                 │                            │
  │  Set session cookie             │                            │
  │◀────────────────────────────────┤                            │
  │                                 │                            │
  │  Install GitHub App prompt      │                            │
  │────────────────────────────────▶│                            │
  │                                 │  POST /api/github/app/install
  │                                 │──────────────────────────▶  │
  │                                 │  installation_id           │
  │                                 │◀──────────────────────────  │
  │  Repo list with scan toggles    │                            │
  │◀────────────────────────────────┤                            │
```

## Database Schema

Add a SQLite table (or file-based JSON for simplicity) in the container:

```sql
CREATE TABLE IF NOT EXISTS github_connections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id TEXT NOT NULL,                     -- from JWT sub
  github_user_id INTEGER,
  github_login TEXT,                         -- e.g., "octocat"
  access_token TEXT,                         -- encrypted at rest
  refresh_token TEXT,
  token_expires_at TEXT,                     -- ISO 8601
  github_app_installation_id INTEGER,        -- null until app installed
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS protected_repos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  connection_id INTEGER REFERENCES github_connections(id),
  repo_id INTEGER,                           -- GitHub repo ID
  repo_full_name TEXT,                       -- e.g., "user/repo"
  scan_on_push INTEGER DEFAULT 1,            -- boolean
  scan_on_pr INTEGER DEFAULT 1,              -- boolean
  block_deploy INTEGER DEFAULT 0,            -- boolean
  last_scan_result TEXT,                     -- 'clean', 'infected', 'pending'
  webhook_id INTEGER,                        -- GitHub webhook ID (for uninstall)
  created_at TEXT DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  repo_id INTEGER REFERENCES protected_repos(id),
  trigger TEXT,                              -- 'manual','push','pr','webhook'
  commit_sha TEXT,
  pr_number INTEGER,
  status TEXT,                               -- 'running','clean','infected','error'
  summary TEXT,
  infected_files TEXT,                        -- JSON array
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT DEFAULT (datetime('now'))
);
```

## API Endpoints

### Auth

| Method | Path | Description |
|---|---|---|
| GET | `/api/auth/github/login` | Redirect to GitHub OAuth authorize URL |
| GET | `/api/auth/github/callback` | Handle OAuth callback, exchange code for token |
| GET | `/api/auth/session` | Return current user info (existing) |
| POST | `/api/auth/guest` | Ephemeral guest token (existing) |

### GitHub App

| Method | Path | Description |
|---|---|---|
| POST | `/api/github/app/install` | Create GitHub App installation (returns install URL) |
| POST | `/api/github/webhook` | Receive push/PR webhook events from GitHub |
| GET | `/api/github/repos` | List user's GitHub repos (via OAuth token) |
| POST | `/api/github/repos/:id/protect` | Enable scan-on-push/PR for a repo |
| DELETE | `/api/github/repos/:id/protect` | Disable protection, remove webhook |

### Scans

| Method | Path | Description |
|---|---|---|
| POST | `/api/scan` | Scan a local repo (existing) |
| POST | `/api/scan/pr/:repoId/:prNumber` | Scan PR diff only |
| GET | `/api/scan/:id` | Poll scan result (existing) |
| GET | `/api/scans` | Scan history (existing) |

## Webhook Handler Flow

When GitHub sends a webhook event (`push` or `pull_request`):

```
GitHub ── POST /api/github/webhook ──▶ VibeCheck
  │                                      │
  │  X-Hub-Signature-256 verification    │
  │                                      │
  │  Lookup protected_repos by repo_id   │
  │                                      │
  │  Clone repo (using installation      │
  │  token, not PAT)                     │
  │                                      │
  │  Run clamscan (tracked-only on diff) │
  │                                      │
  │  Store result in scan_results        │
  │                                      │
  │  If infected:                        │
  │    POST commit status (failure)      │
  │    POST PR comment with details      │
  │                                      │
  │  If clean:                           │
  │    POST commit status (success)      │
```

## Frontend Screens

### Screen 1: Landing (unauthenticated)

```
🛡️ VibeCheck — Scan AI-generated code before it ships.

[Connect GitHub]  ← primary CTA

"Connect once. VibeCheck automatically scans every push
and pull request for malware, suspicious files, and known threats."
```

### Screen 2: Connected (repos list)

```
🛡️ VibeCheck

Signed in as octocat          [Disconnect]

Your Repositories

┌──────────────────────────────────────────────────────┐
│ ☑ user/repo-a          🔄 On push  🔄 On PR  🛡     │
│ ☑ org/repo-b           🔄 On push  🔄 On PR         │
│ ☐ user/private-repo    —                           │
│ ☐ user/new-project     —                           │
└──────────────────────────────────────────────────────┘

  [Add Repository]          [Scan All Now]

  Legend: 🛡 = protected  🔄 = auto-scan enabled
```

### Screen 3: Protection Settings

```
🛡️ user/repo-a — Protection Settings

  ☑ Scan on every push
  ☑ Scan pull requests
  ☐ Block deploy if infected

  [Save Settings]  [Scan Now]  [Remove Protection]

  Recent Scans
  ┌──────────────────────────────────────────────────┐
  │ main       ✓ Clean   2s ago   847 files scanned  │
  │ #42 PR     ✗ Found!  5m ago   ⚠ crypto-miner.js │
  │ #41 PR     ✓ Clean   1h ago   312 files scanned  │
  └──────────────────────────────────────────────────┘
```

## Git Clone with Installation Token

When cloning with a GitHub App installation token:

```javascript
// POST /api/github/app/token — get installation access token
const tokenRes = await fetch(
  `https://api.github.com/app/installations/${installationId}/access_tokens`,
  {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${jwt}`,
      Accept: 'application/vnd.github.v3+json',
    },
  }
);
const { token } = await tokenRes.json();
// token expires in 1 hour

// Clone using the installation token
execSync(`git clone https://x-access-token:${token}@github.com/${repo}.git`, ...);
```

## Environment Variables

```env
GITHUB_CLIENT_ID=          # OAuth App client ID
GITHUB_CLIENT_SECRET=      # OAuth App client secret
GITHUB_APP_ID=             # GitHub App ID
GITHUB_APP_PRIVATE_KEY=    # GitHub App private key (PEM)
GITHUB_APP_WEBHOOK_SECRET= # Webhook secret for HMAC verification
BASE_URL=https://vibecheck.example.com  # For OAuth callback redirect
```

## Implementation Order

### Week 1 — OAuth Login
1. Register GitHub OAuth App (callback: `/api/auth/github/callback`)
2. Add `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET` to env
3. Implement `/api/auth/github/login` and `/api/auth/github/callback`
4. Store access_token in `github_connections` table
5. Frontend: "Connect GitHub" button, user avatar, disconnect
6. Keep guest auth as fallback for unauthenticated access

### Week 2 — Repo Listing + Scanning
1. `/api/github/repos` (fetches from GitHub API using OAuth token)
2. Frontend: repo list with checkboxes
3. Clone + scan on repo select
4. Store results in `scan_results` table

### Week 3 — GitHub App + Webhooks
1. Register GitHub App (webhook: `/api/github/webhook`)
2. Install flow — generate install URL, capture `installation_id`
3. Webhook verification (HMAC-SHA256)
4. Push event → auto-clone → scan → commit status
5. PR event → scan diff → PR comment

### Week 4 — PR Checks + Protection Toggles
1. Frontend: enable/disable scan-on-push, scan-on-PR, block-deploy
2. PR check run via GitHub Checks API
3. Block deploy: commit status `failure` when infected
4. Scan summary in PR comment (markdown table)

## File Changes

```
registry/vibecheck/
├── server.js              ← +300 lines (OAuth routes, webhook handler, token mgmt)
├── package.json           ← +axios, jsonwebtoken already present
├── Dockerfile             ← no change needed
├── db.js                  ← NEW: SQLite helpers
├── github.js              ← NEW: GitHub API client (tokens, repos, webhooks, checks)
└── public/
    ├── index.html         ← rewritten onboarding + repo list + settings
    ├── dashboard.html     ← NEW: protected repos dashboard
    └── settings.html      ← NEW: per-repo protection toggles
```
