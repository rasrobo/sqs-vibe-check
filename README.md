# 🛡️ VibeCheck

> Malware and virus scanning for AI-generated and vibe-coded repositories.
> Before you ship what the LLM wrote — run a VibeCheck.

VibeCheck is an open-source Dockerized malware scanner for Git repositories
and source trees, powered by **ClamAV** — the open-source antivirus engine
maintained by Cisco Talos. Run it standalone from the CLI, integrate into CI/CD,
or deploy as a one-click app in any marketplace.

> **Attribution:** The underlying AV engine is ClamAV, open-source GPLv2,
> developed by Cisco Talos → https://github.com/Cisco-Talos/clamav

## Quick Start

### Standalone (Docker)

```bash
# Scan a local directory
./vibecheck-scan /path/to/your/repo

# Or use the official ClamAV image directly
docker run --rm -v /path/to/repo:/scan:ro clamav/clamav:latest clamscan -r /scan
```

### Marketplace (any Docker host)

Deploy `registry/vibecheck/` as a compose stack:

```bash
cd registry/vibecheck
docker compose up -d
# UI at http://localhost:3210
```

### CI/CD

```yaml
# See github-actions.example.yml for full example
- name: Scan repo
  run: docker run --rm -v ${{ github.workspace }}:/scan:ro \
    clamav/clamav:latest clamscan -r --infected --no-summary /scan
```

## API

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/health` | GET | None | Health check |
| `/api/auth/session` | GET | Cookie | SSO via JWT cookie |
| `/api/auth/guest` | POST | None | Ephemeral guest token |
| `/api/repos` | GET | Bearer | List available repos |
| `/api/scans` | GET | Bearer | Scan history |
| `/api/scan` | POST | Bearer | Run a scan |
| `/api/scan/:id` | GET | Bearer | Scan status/results |

## License

MIT — the underlying ClamAV engine is GPLv2 (Cisco Talos).

---

Built by [Side Quest Studios](https://sidequeststudios.xyz)

If you find this project useful, consider [supporting development on Ko-fi](https://ko-fi.com/sidequeststudios).

*Keywords: malware scanner, ClamAV Docker, repo security, vibe coding, CI/CD security scanning, open-source antivirus*
