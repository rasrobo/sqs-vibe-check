# VibeCheck — Developer Prompt

Build a Dockerized Git repo malware scanner that:

1. Wraps ClamAV (clamscan) in a Node.js Express server
2. Provides a web UI for scanning repos
3. Supports "tracked only" mode (git ls-files) for vibe-coded repos
4. Uses JWT auth with claw_session / marketplace SSO support

## Architecture

```
Browser → vibecheck.host.com → Caddy/nginx → Express → clamscan
                                                      ↓
                                               /repos (mounted volume)
```

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Single container (clamscan, not clamd) | Simpler deployment, no daemon management |
| Named volume for ClamAV DB | Persists signatures across restarts (freshclam on boot) |
| `start_period: 90s` | freshclam takes 60-90s on first boot |
| Tracked-only mode | `git ls-files` filters to versioned files, not node_modules |
| In-memory scan history | No DB needed — history is ephemeral (resets on restart) |
| JWT SSO | Compatible with any marketplace that uses signed cookies |

## Marketplace Integration

To add VibeCheck to your app marketplace, follow the standard pattern:

1. Copy `registry/vibecheck/` to your provisioner's app registry
2. Register in your apps catalog (name, version, description, icon)
3. Add a compose renderer that matches the Dockerfile
4. Generate env vars (JWT_SECRET, CLAW_SESSION_SECRET)
5. Set up Caddy/nginx route with WebSocket + API bypass

## Files

| File | Purpose |
|---|---|
| `registry/vibecheck/server.js` | Express server with scan API |
| `registry/vibecheck/package.json` | Dependencies (express, jsonwebtoken) |
| `registry/vibecheck/Dockerfile` | Node + ClamAV + git in one image |
| `registry/vibecheck/docker-compose.yml` | Local dev compose |
| `registry/vibecheck/public/index.html` | Web UI |
| `vibecheck-scan` | Standalone CLI wrapper |
| `github-actions.example.yml` | CI/CD integration |
