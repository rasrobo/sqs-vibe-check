# VibeCheck — Marketplace Integration Guide

To add VibeCheck to your app marketplace, wire up these standard steps:

## 1. App Catalog Entry

Register VibeCheck in your apps catalog:

```
app_id:    vibecheck
name:      VibeCheck
version:   1.0.0
category:  security
icon:      🛡️
description: Malware scanner for AI-generated and vibe-coded repos. Powered by ClamAV.
```

## 2. Docker Compose Template

```yaml
name: vibecheck-{claw_id}
services:
  app:
    build: .
    restart: unless-stopped
    env_file: /opt/apps/vibecheck/app.env
    environment:
      - PORT=3210
      - SCAN_ROOT=/repos
    volumes:
      - clamav-db:/var/lib/clamav
      - /opt/git:/repos:ro
    labels:
      - app_id=vibecheck
    ports:
      - "127.0.0.1:0:3210"
    healthcheck:
      test: ["CMD","wget","-qO-","http://127.0.0.1:3210/health"]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 90s
volumes:
  clamav-db:
```

> `start_period: 90s` is critical — freshclam takes 60–90s on first boot.

## 3. Environment Variables

```
PORT=3210
SCAN_ROOT=/repos
JWT_SECRET=<random 32-byte hex>
CLAW_SESSION_SECRET=<shared marketplace secret>
NODE_ENV=production
```

## 4. Caddy / Reverse Proxy Route

```
vibecheck.{host}.com {
  @api path /api/*
  handle @api {
    reverse_proxy app:3210
  }
  handle {
    reverse_proxy app:3210
    @not_authed not header_regexp session Cookie session=.+
    redir @not_authed https://marketplace/login?returnTo={scheme}://{host}{uri}
  }
}
```

The `/api/*` paths bypass auth because the app uses its own Bearer token auth.
Static file serving (the web UI) goes through the auth gate.

## 5. Source Deploy

Tar the `registry/vibecheck/` directory, SCP to the host, extract, and run
`docker compose up -d --build`.
