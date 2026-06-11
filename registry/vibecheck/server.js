/**
 * VibeCheck — Malware safety layer for AI-generated code
 * GitHub-native: OAuth login, App installation, webhook-driven scans, PR checks
 * Engine: ClamAV (Cisco Talos, GPLv2) + heuristic analysis for vibe-coded threats
 */
const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { execFile, execSync } = require('child_process');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3210;
const JWT_SECRET = process.env.JWT_SECRET || 'changeme';
const CLAW_SESSION_SECRET = process.env.CLAW_SESSION_SECRET || '';
const SCAN_ROOT = process.env.SCAN_ROOT || '/repos';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;

// GitHub OAuth (for user identity)
const GH_CLIENT_ID = process.env.GITHUB_CLIENT_ID || '';
const GH_CLIENT_SECRET = process.env.GITHUB_CLIENT_SECRET || '';

// GitHub App (for repo access, webhooks, checks)
const GH_APP_ID = process.env.GITHUB_APP_ID || '';
const GH_APP_PRIVATE_KEY = (process.env.GITHUB_APP_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const GH_WEBHOOK_SECRET = process.env.GITHUB_WEBHOOK_SECRET || '';

// ── Data store (file-based JSON for simplicity, one container) ────────────
const DB_PATH = path.join(__dirname, 'data.json');

function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); } catch { return { users: {}, installations: {}, repos: {}, scans: [] }; }
}
function saveDb(db) {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_PATH + '.tmp', JSON.stringify(db, null, 2));
  fs.renameSync(DB_PATH + '.tmp', DB_PATH);
}

// ── GitHub App JWT ─────────────────────────────────────────────────────────
function createAppJwt() {
  const now = Math.floor(Date.now() / 1000);
  const payload = { iss: GH_APP_ID, iat: now, exp: now + 600 };
  return jwt.sign(payload, GH_APP_PRIVATE_KEY, { algorithm: 'RS256' });
}

async function getInstallationToken(installationId) {
  const appJwt = createAppJwt();
  const url = `https://api.github.com/app/installations/${installationId}/access_tokens`;
  const res = await fetch(url, {
    method: 'POST',
    headers: { Authorization: `Bearer ${appJwt}`, Accept: 'application/vnd.github.v3+json' },
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.token;
}

// ── Webhook signature verification ─────────────────────────────────────────
function verifyWebhook(body, signature) {
  if (!GH_WEBHOOK_SECRET || !signature) return false;
  const sig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
  const hmac = crypto.createHmac('sha256', GH_WEBHOOK_SECRET).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(hmac));
}

// ── Express setup ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb', verify: (req, _, buf) => { req.rawBody = buf.toString(); } }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ status: 'ok', version: '2.0.0' }));

// ── Auth: Guest (existing) ─────────────────────────────────────────────────
app.post('/api/auth/guest', (_req, res) => {
  const id = 'guest_' + Math.random().toString(36).slice(2, 8).toUpperCase();
  const token = jwt.sign({ sub: id, name: 'Guest ' + id, guest: true }, JWT_SECRET, { expiresIn: '4h' });
  res.json({ token, name: 'Guest ' + id });
});

app.get('/api/auth/session', (req, res) => {
  const cookies = req.headers.cookie || '';
  const match = cookies.match(/claw_auth=([^;]+)/);
  if (!match || !CLAW_SESSION_SECRET) return res.status(401).json({ error: 'no session' });
  try {
    const payload = jwt.verify(decodeURIComponent(match[1]), CLAW_SESSION_SECRET);
    const token = jwt.sign(
      { sub: payload.sub, email: payload.email, name: payload.name },
      JWT_SECRET, { expiresIn: '8h' }
    );
    res.json({ token, email: payload.email, name: payload.name });
  } catch { res.status(401).json({ error: 'invalid session' }); }
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'invalid token' }); }
}

// ── GitHub OAuth (Phase 1: user identity) ──────────────────────────────────
app.get('/api/auth/github/login', (req, res) => {
  if (!GH_CLIENT_ID) return res.status(503).json({ error: 'GitHub OAuth not configured' });
  const state = crypto.randomBytes(16).toString('hex');
  const url = `https://github.com/login/oauth/authorize?client_id=${GH_CLIENT_ID}&state=${state}&scope=read:user%20repo`;
  res.cookie('oauth_state', state, { maxAge: 600000, httpOnly: true });
  res.redirect(url);
});

app.get('/api/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || state !== req.cookies?.oauth_state) {
    return res.status(400).type('html').send('<html><body><h1>OAuth failed</h1><p>State mismatch or missing code.</p><a href="/">Try again</a></body></html>');
  }
  res.clearCookie('oauth_state');
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ client_id: GH_CLIENT_ID, client_secret: GH_CLIENT_SECRET, code }),
    });
    const { access_token } = await tokenRes.json();
    if (!access_token) throw new Error('No access token in response');

    const userRes = await fetch('https://api.github.com/user', {
      headers: { Authorization: `Bearer ${access_token}` },
    });
    const ghUser = await userRes.json();

    const db = loadDb();
    const userId = 'gh_' + ghUser.id;
    db.users[userId] = {
      github_id: ghUser.id, login: ghUser.login, avatar_url: ghUser.avatar_url,
      access_token, created_at: new Date().toISOString(),
    };
    saveDb(db);

    const token = jwt.sign({ sub: userId, name: ghUser.login, avatar: ghUser.avatar_url }, JWT_SECRET, { expiresIn: '24h' });
    // Set as cookie for the frontend
    res.cookie('vibecheck_token', token, { maxAge: 86400000, httpOnly: false });
    res.redirect('/');
  } catch (e) {
    res.status(500).type('html').send(`<html><body><h1>OAuth error</h1><p>${e.message}</p><a href="/">Try again</a></body></html>`);
  }
});

// ── GitHub App installation (Phase 2: repo access + webhooks) ─────────────
app.get('/api/github/app/install', requireAuth, (req, res) => {
  if (!GH_APP_ID) return res.status(503).json({ error: 'GitHub App not configured' });
  const installUrl = `https://github.com/apps/${process.env.GITHUB_APP_SLUG || 'vibecheck'}/installations/new`;
  res.json({ url: installUrl });
});

app.post('/api/github/webhook', (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'];
  const delivery = req.headers['x-github-delivery'];

  if (!verifyWebhook(req.rawBody || '', signature)) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  const payload = req.body;
  console.log(`[webhook] ${event} ${delivery}`);

  try {
    if (event === 'push') handlePushEvent(payload).catch(e => console.error('[webhook:push]', e.message));
    else if (event === 'pull_request') handlePullRequestEvent(payload).catch(e => console.error('[webhook:pr]', e.message));
    else if (event === 'installation') handleInstallationEvent(payload);
    else if (event === 'installation_repositories') handleInstallationReposEvent(payload);
  } catch (e) { console.error('[webhook] error:', e.message); }

  res.status(202).json({ ok: true });
});

// ── Webhook handlers ───────────────────────────────────────────────────────
function handleInstallationEvent(payload) {
  const db = loadDb();
  const action = payload.action; // 'created' | 'deleted' | 'suspend' | 'unsuspend'
  if (action === 'created') {
    db.installations[payload.installation.id] = {
      account_login: payload.installation.account.login,
      account_type: payload.installation.account.type,
      created_at: new Date().toISOString(),
      repos: [],
    };
  } else if (action === 'deleted') {
    delete db.installations[payload.installation.id];
  }
  saveDb(db);
}

function handleInstallationReposEvent(payload) {
  const db = loadDb();
  const instId = payload.installation.id;
  if (!db.installations[instId]) return;
  if (payload.repositories_added) {
    for (const r of payload.repositories_added) {
      db.installations[instId].repos.push({ id: r.id, full_name: r.full_name });
      db.repos[r.full_name] = { installation_id: instId, scan_on_push: true, scan_on_pr: true, block_deploy: false };
    }
  }
  if (payload.repositories_removed) {
    for (const r of payload.repositories_removed) {
      db.installations[instId].repos = db.installations[instId].repos.filter(x => x.id !== r.id);
      delete db.repos[r.full_name];
    }
  }
  saveDb(db);
}

async function handlePushEvent(payload) {
  const repo = payload.repository.full_name;
  const ref = payload.ref;
  const commitSha = payload.after;
  const installationId = payload.installation?.id;
  if (!installationId || ref !== 'refs/heads/main') return;

  const db = loadDb();
  const settings = db.repos[repo];
  if (!settings || !settings.scan_on_push) return;

  try {
    const token = await getInstallationToken(installationId);
    const result = await scanRepo({ repo, token, commitSha, mode: 'push' });
    await updateCommitStatus({ repo, commitSha, token, conclusion: result.clean ? 'success' : 'failure',
      summary: `${result.scanned} files scanned, ${result.threats.length} threats found` });
  } catch (e) { console.error(`[push] ${repo}: ${e.message}`); }
}

async function handlePullRequestEvent(payload) {
  const repo = payload.repository.full_name;
  const prNumber = payload.number;
  const headSha = payload.pull_request.head.sha;
  const installationId = payload.installation?.id;
  if (!installationId) return;

  const db = loadDb();
  const settings = db.repos[repo];
  if (!settings || !settings.scan_on_pr) return;

  try {
    const token = await getInstallationToken(installationId);
    const result = await scanRepo({ repo, token, commitSha: headSha, mode: 'pr', prNumber });
    await createCheckRun({ repo, headSha, token, conclusion: result.clean ? 'success' : 'failure',
      summary: `${result.scanned} files scanned, ${result.threats.length} threats found`,
      annotations: result.threats.slice(0, 10).map(t => ({
        path: t.file, start_line: 1, end_line: 1, annotation_level: 'warning',
        message: `${t.signature} — detected by VibeCheck`,
      })),
    });
  } catch (e) { console.error(`[pr] ${repo}#${prNumber}: ${e.message}`); }
}

// ── GitHub API helpers ─────────────────────────────────────────────────────
async function updateCommitStatus({ repo, commitSha, token, conclusion, summary }) {
  await fetch(`https://api.github.com/repos/${repo}/statuses/${commitSha}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github.v3+json' },
    body: JSON.stringify({ state: conclusion === 'success' ? 'success' : 'failure',
      description: summary.slice(0, 140), context: 'VibeCheck' }),
  });
}

async function createCheckRun({ repo, headSha, token, conclusion, summary, annotations }) {
  const checkRes = await fetch(`https://api.github.com/repos/${repo}/check-runs`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github.v3+json' },
    body: JSON.stringify({
      name: 'VibeCheck', head_sha: headSha, status: 'completed', conclusion,
      output: { title: 'VibeCheck Malware Scan', summary, annotations: annotations || [] },
    }),
  });
  return checkRes.json();
}

// ── Scanner (ClamAV + heuristics) ──────────────────────────────────────────
async function scanRepo({ repo, token, commitSha, mode, prNumber }) {
  const safe = repo.replace(/[^a-zA-Z0-9_-]/g, '_');
  const dest = path.join(SCAN_ROOT, `webhook_${safe}_${commitSha?.slice(0, 7) || Date.now()}`);
  const cloneUrl = `https://x-access-token:${token}@github.com/${repo}.git`;

  const start = Date.now();

  // Clone
  execSync(`git clone --depth 1 ${cloneUrl} ${dest}`, { timeout: 120000, stdio: 'pipe' });

  // Run ClamAV
  const infected = [];
  try {
    const out = execSync(`clamscan --infected --no-summary --recursive ${dest}`, { timeout: 300000, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' });
    for (const line of out.split('\n')) {
      if (line.includes('FOUND')) {
        const parts = line.split(': ');
        infected.push({ file: parts[0].replace(dest, ''), signature: (parts[1] || '').replace(' FOUND', ''), type: 'clamav' });
      }
    }
  } catch (e) { /* clamscan returns non-zero on infection */ }

  // Run heuristics
  const heuristics = runHeuristics(dest);
  const threats = [...infected, ...heuristics];

  // Cleanup
  try { fs.rmSync(dest, { recursive: true, force: true }); } catch {}

  const elapsed = ((Date.now() - start) / 1000).toFixed(1);

  // Log scan result
  const db = loadDb();
  db.scans.unshift({
    id: crypto.randomUUID(), repo, commit_sha: commitSha, mode, pr_number: prNumber,
    status: threats.length ? 'infected' : 'clean', scanned: 0, threats,
    elapsed_seconds: parseFloat(elapsed), created_at: new Date().toISOString(),
  });
  if (db.scans.length > 200) db.scans.length = 200;
  saveDb(db);

  return { clean: threats.length === 0, scanned: infected.length + heuristics.length, threats };
}

// ── Heuristic analysis for vibe-coded threats ──────────────────────────────
function runHeuristics(root) {
  const threats = [];
  try {
    const files = execSync(`find ${root} -type f 2>/dev/null | head -2000`, { timeout: 10000, encoding: 'utf8' }).trim().split('\n').filter(Boolean);

    for (const file of files) {
      const rel = file.replace(root, '');
      const basename = path.basename(file);
      const ext = path.extname(file).toLowerCase();
      let content;
      try {
        content = fs.readFileSync(file, 'utf8').slice(0, 5000);
      } catch { continue; }

      // Suspicious file names
      if (/\.env(\.example)?$/i.test(basename) && content.includes('SECRET') || content.includes('PASSWORD') || content.includes('API_KEY')) {
        threats.push({ file: rel, signature: 'Suspicious: .env file with credentials exposed', type: 'heuristic' });
      }
      if (/^\.npmrc$/i.test(basename) && content.includes('//registry.npmjs.org/:_authToken')) {
        threats.push({ file: rel, signature: 'Suspicious: .npmrc with npm auth token', type: 'heuristic' });
      }
      if (/^\.aws|credentials|\.s3cfg/i.test(basename) && (content.includes('aws_access_key_id') || content.includes('secret_access_key'))) {
        threats.push({ file: rel, signature: 'Suspicious: AWS credentials file', type: 'heuristic' });
      }

      // Obfuscated shell scripts
      if (['.sh', '.bash'].includes(ext)) {
        if (content.includes('curl') && content.includes('bash') && content.match(/curl.*\|.*bash/i)) {
          if (!content.includes('# VibeCheck-allow: pipe')) {
            threats.push({ file: rel, signature: 'Heuristic: curl-to-bash — possible remote execution', type: 'heuristic' });
          }
        }
        if (content.includes('wget') && content.includes('chmod +x') && content.includes('./')) {
          threats.push({ file: rel, signature: 'Heuristic: wget-to-exec — possible binary download', type: 'heuristic' });
        }
        if (content.match(/eval\s*\(/i) && content.match(/base64|decode|\\x[0-9a-f]{2}/i)) {
          threats.push({ file: rel, signature: 'Heuristic: obfuscated eval in script', type: 'heuristic' });
        }
        if (/\/dev\/tcp\//.test(content)) {
          threats.push({ file: rel, signature: 'Heuristic: /dev/tcp reverse shell pattern', type: 'heuristic' });
        }
      }

      // Obfuscated JS
      if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
        if (content.length > 500 && (content.match(/\\x[0-9a-f]{2}/g) || []).length > 20) {
          threats.push({ file: rel, signature: 'Heuristic: heavily obfuscated JavaScript', type: 'heuristic' });
        }
        if (content.includes('eval(') && content.match(/atob|btoa|Buffer\.from/i)) {
          threats.push({ file: rel, signature: 'Heuristic: eval with base64 — possible payload', type: 'heuristic' });
        }
        if (content.includes('require("child_process")') && (content.includes('postinstall') || content.includes('preinstall'))) {
          threats.push({ file: rel, signature: 'Heuristic: install script using child_process', type: 'heuristic' });
        }
      }

      // Unexpected binaries
      if (!['.sh', '.bash', '.js', '.ts', '.py', '.rb', '.go', '.rs', '.c', '.cpp', '.h'].includes(ext) && !content.startsWith('#!')) {
        try {
          const firstBytes = fs.readFileSync(file).slice(0, 4);
          if (firstBytes[0] === 0x7f && firstBytes[1] === 0x45 && firstBytes[2] === 0x4c && firstBytes[3] === 0x46) {
            threats.push({ file: rel, signature: 'Heuristic: unexpected ELF binary in repo (possible crypto miner / malware)', type: 'heuristic' });
          }
        } catch {}
      }
    }
  } catch (e) { console.error('[heuristics] error:', e.message); }

  return threats;
}

// ── Existing endpoints (repo list, clone, scan, history) ──────────────────
app.get('/api/repos', requireAuth, (req, res) => {
  try {
    const entries = fs.readdirSync(SCAN_ROOT, { withFileTypes: true })
      .filter(d => d.isDirectory())
      .map(d => ({ name: d.name, path: path.join(SCAN_ROOT, d.name) }));
    res.json({ repos: entries });
  } catch { res.json({ repos: [] }); }
});

app.post('/api/repos/clone', requireAuth, (req, res) => {
  const { url, token } = req.body;
  if (!url) return res.status(400).json({ error: 'GitHub URL required' });
  if (!url.match(/^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/))
    return res.status(400).json({ error: 'Must be a valid GitHub URL' });

  const name = url.replace(/\.git$/, '').split('/').slice(-2).join('-');
  const dest = path.join(SCAN_ROOT, name);
  if (fs.existsSync(dest)) return res.status(409).json({ error: 'Repo already cloned', path: dest });

  let cloneUrl = url;
  if (token) cloneUrl = url.replace('https://', `https://${token}@`);
  try {
    execSync(`git clone --depth 1 ${cloneUrl} ${dest}`, { timeout: 120000, stdio: 'pipe' });
    res.json({ ok: true, name, path: dest });
  } catch (e) {
    res.status(500).json({ error: 'Clone failed: ' + (e.stderr?.toString() || e.message).slice(0, 300) });
  }
});

app.delete('/api/repos/:name', requireAuth, (req, res) => {
  const target = path.join(SCAN_ROOT, req.params.name);
  if (!target.startsWith(path.resolve(SCAN_ROOT))) return res.status(400).json({ error: 'invalid path' });
  try { fs.rmSync(target, { recursive: true, force: true }); res.json({ ok: true }); }
  catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/scan', requireAuth, (req, res) => {
  const { target, tracked_only = false } = req.body;
  if (!target) return res.status(400).json({ error: 'target required' });
  const resolved = path.resolve(target);
  if (!resolved.startsWith(path.resolve(SCAN_ROOT))) return res.status(400).json({ error: 'target must be under SCAN_ROOT' });

  const scanId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const started = new Date().toISOString();

  const entry = { scan_id: scanId, target: resolved, tracked_only, status: 'running', started, finished: null, summary: null, infected: [], errors: [] };
  const db = loadDb();
  db.scans.unshift(entry);
  if (db.scans.length > 200) db.scans.length = 200;
  saveDb(db);

  res.json({ scan_id: scanId, status: 'running', started });

  const args = ['--infected', '--no-summary', '--recursive'];
  let scanTarget = resolved;
  if (tracked_only) {
    try {
      const files = execSync(`git -C ${resolved} ls-files`, { timeout: 10000 })
        .toString().trim().split('\n').filter(Boolean).map(f => path.join(resolved, f));
      if (!files.length) { updateScan(scanId, 'done', { scanned: 0, infected: 0, errors: 0 }); return; }
      const listFile = `/tmp/vc-${scanId}.txt`;
      fs.writeFileSync(listFile, files.join('\n'));
      args.push('--file-list=' + listFile);
      scanTarget = null;
    } catch (e) { entry.errors.push('git ls-files failed: ' + e.message); }
  }
  if (scanTarget) args.push(scanTarget);

  const binary = fs.existsSync('/usr/bin/clamdscan') ? 'clamdscan' : 'clamscan';
  execFile(binary, args, { timeout: 300000, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
    const infected = [];
    for (const line of (stdout || '').split('\n')) {
      if (line.includes('FOUND')) {
        const parts = line.split(': ');
        infected.push({ file: parts[0], signature: (parts[1] || '').replace(' FOUND', ''), type: 'clamav' });
      }
    }
    updateScan(scanId, 'done', { scanned: (stdout || '').split('\n').length, infected: infected.length, errors: entry.errors.length }, infected);
    try { fs.unlinkSync(`/tmp/vc-${scanId}.txt`); } catch {}
  });
});

function updateScan(scanId, status, summary, infected) {
  const db = loadDb();
  const entry = db.scans.find(s => s.scan_id === scanId);
  if (entry) {
    entry.status = status;
    entry.finished = new Date().toISOString();
    entry.summary = summary;
    if (infected) entry.infected = infected;
    saveDb(db);
  }
}

app.get('/api/scan/:id', requireAuth, (req, res) => {
  const db = loadDb();
  const entry = db.scans.find(s => s.scan_id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'not found' });
  res.json(entry);
});

app.get('/api/scans', requireAuth, (req, res) => {
  const db = loadDb();
  res.json({ scans: db.scans.slice(0, 50) });
});

// ── GitHub connected user info ────────────────────────────────────────────
app.get('/api/user', requireAuth, (req, res) => {
  const db = loadDb();
  const user = db.users[req.user.sub];
  if (user) {
    const installs = Object.entries(db.installations).map(([id, inst]) => ({
      installation_id: parseInt(id), account_login: inst.account_login, repos: inst.repos,
    }));
    return res.json({ connected: true, login: user.login, avatar_url: user.avatar_url, installations: installs });
  }
  res.json({ connected: false });
});

app.get('/api/repos/protected', requireAuth, (req, res) => {
  const db = loadDb();
  const protectedRepos = Object.entries(db.repos).map(([name, settings]) => ({
    full_name: name, ...settings,
    last_scan: db.scans.filter(s => s.repo === name).sort((a, b) => b.created_at.localeCompare(a.created_at))[0] || null,
  }));
  res.json({ repos: protectedRepos });
});

app.patch('/api/repos/protected/:full_name', requireAuth, (req, res) => {
  const db = loadDb();
  const name = decodeURIComponent(req.params.full_name);
  if (!db.repos[name]) return res.status(404).json({ error: 'repo not found' });
  Object.assign(db.repos[name], req.body);
  saveDb(db);
  res.json({ ok: true, settings: db.repos[name] });
});

// ── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[vibecheck] port ${PORT} | SCAN_ROOT=${SCAN_ROOT}`);
  if (GH_APP_ID) console.log(`[vibecheck] GitHub App ${GH_APP_ID} loaded — webhook support enabled`);
  if (GH_CLIENT_ID) console.log(`[vibecheck] GitHub OAuth configured — login enabled`);
});
