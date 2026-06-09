# Contributing to VibeCheck

## Reporting Issues

- Security vulnerabilities → see SECURITY.md
- Bugs → open a GitHub issue with reproduction steps
- Feature requests → open a discussion

## Pull Requests

1. Fork the repo
2. Create a feature branch
3. Test your changes locally (clone this repo and run docker compose)
4. Submit a PR with a clear description

## Code Standards

- Node.js 20+ (alpine)
- Express 4.x for the API
- ClamAV via clamscan (no clamd daemon needed)
- Follow the existing layout in `registry/vibecheck/`
