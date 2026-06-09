/**
 * VibeCheck — Malware scanner for AI-generated / vibe-coded repos
 * Powered by ClamAV (Cisco Talos, GPLv2)
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const { execFile, execSync } = require('child_process');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3210;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const CLAW_SESSION_SECRET = process.env.CLAW_SESSION_SECRET || '';
const SCAN_ROOT = process.env.SCAN_ROOT || '/repos';

app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

app.get('/api/auth/session', (req, res) => {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(/claw_auth=([^;]+)/);
  if (!match || !CLAW_SESSION_SECRET) return res.status(401).json({ error: 'no session' });
  try {
    const payload = jwt.verify(decodeURIComponent(match[1]), CLAW_SESSION_SECRET);
    const token = jwt.sign(
      { sub: payload.sub, email: payload.email, name: payload.name, claw_id: payload.claw_id },
      JWT_SECRET, { expiresIn: '8h' }
    );
    res.json({ token, email: payload.email, name: payload.name });
  } catch { res.status(401).json({ error: 'invalid session' }); }
});

app.post('/api/auth/guest', (_req, res) => {
  const id = 'guest_' + Math.random().toString(36).slice(2, 8).toUpperCase();
  const token = jwt.sign({ sub: id, name: 'Guest ' + id, guest: true }, JWT_SECRET, { expiresIn: '4h' });
  res.json({ token, name: 'Guest ' + id });
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'invalid token' }); }
}

app.get('/api/repos', requireAuth, (req, res) => {
  try {
    const entries = fs.readdirSync(SCAN_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => ({ name: d.name, path: path.join(SCAN_ROOT, d.name) }));
    res.json({ repos: entries });
  } catch { res.json({ repos: [] }); }
});

const scanHistory = [];

app.get('/api/scans', requireAuth, (_req, res) =>
  res.json({ scans: scanHistory.slice(-50).reverse() })
);

app.post('/api/scan', requireAuth, (req, res) => {
  const { target, tracked_only = false } = req.body;
  if (!target) return res.status(400).json({ error: 'target required' });

  const resolved = path.resolve(target);
  if (!resolved.startsWith(path.resolve(SCAN_ROOT)))
    return res.status(400).json({ error: 'target must be under SCAN_ROOT' });

  const scanId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const started = new Date().toISOString();
  const entry = {
    scan_id: scanId, target: resolved, tracked_only,
    status: 'running', started, finished: null, summary: null, infected: [], errors: []
  };
  scanHistory.push(entry);

  const args = ['--infected', '--no-summary', '--recursive'];
  let scanTarget = resolved;

  if (tracked_only) {
    try {
      const files = execSync(`git -C ${resolved} ls-files`, { timeout: 10000 })
        .toString().trim().split('\n').filter(Boolean)
        .map(f => path.join(resolved, f));
      if (!files.length) {
        entry.status = 'done'; entry.finished = new Date().toISOString();
        entry.summary = { scanned: 0, infected: 0, errors: 0 };
        return res.json({ scan_id: scanId, status: 'done', summary: entry.summary });
      }
      const listFile = `/tmp/vc-${scanId}.txt`;
      fs.writeFileSync(listFile, files.join('\n'));
      args.push('--file-list=' + listFile);
      scanTarget = null;
    } catch (e) { entry.errors.push('git ls-files failed: ' + e.message); }
  }

  if (scanTarget) args.push(scanTarget);

  const binary = fs.existsSync('/usr/bin/clamdscan') ? 'clamdscan' : 'clamscan';
  res.json({ scan_id: scanId, status: 'running', started });

  execFile(binary, args, { timeout: 300000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
    const infected = [];
    for (const line of (stdout || '').split('\n')) {
      if (line.includes('FOUND')) {
        const parts = line.split(': ');
        infected.push({ file: parts[0], signature: (parts[1] || '').replace(' FOUND', '') });
      }
    }
    entry.status = 'done';
    entry.finished = new Date().toISOString();
    entry.infected = infected;
    entry.summary = { scanned: (stdout || '').split('\n').length, infected: infected.length, errors: entry.errors.length };
    try { fs.unlinkSync(`/tmp/vc-${scanId}.txt`); } catch {}
  });
});

app.get('/api/scan/:id', requireAuth, (req, res) => {
  const entry = scanHistory.find(s => s.scan_id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'not found' });
  res.json(entry);
});

app.listen(PORT, () => console.log(`[vibecheck] port ${PORT} | SCAN_ROOT=${SCAN_ROOT}`));
