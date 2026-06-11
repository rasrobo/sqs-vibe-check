/**
 * VibeCheck v2.1 — GitHub-native onboarding
 * 
 * Auth models:
 *   A. Guest (no login, ephemeral, for quick testing)
 *   B. Central VibeCheck App (we host the GitHub App; user just clicks Install)
 *   C. BYO App via Manifest flow (user creates their own app from the browser)
 *
 * No env file editing needed for any path.
 * The central app credentials come from env (set once by the operator).
 * BYO app credentials are stored in the database per-user.
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

// Central VibeCheck GitHub App credentials (set once by operator in env)
const CENTRAL_APP_ID = process.env.GH_APP_ID || '';
const CENTRAL_APP_KEY = (process.env.GH_APP_PRIVATE_KEY || '').replace(/\\n/g, '\n');
const CENTRAL_WEBHOOK_SECRET = process.env.GH_WEBHOOK_SECRET || '';
const CENTRAL_CLIENT_ID = process.env.GH_CLIENT_ID || '';
const CENTRAL_CLIENT_SECRET = process.env.GH_CLIENT_SECRET || '';
const CENTRAL_APP_SLUG = process.env.GH_APP_SLUG || 'vibecheck';

// ── Database ────────────────────────────────────────────────────────────────
const DB_PATH = path.join(__dirname, 'data.json');

function loadDb() {
  try { return JSON.parse(fs.readFileSync(DB_PATH, 'utf8')); }
  catch { return { users: {}, byoApps: {}, installations: {}, repos: {}, scans: [] }; }
}
function saveDb(db) {
  const dir = path.dirname(DB_PATH);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(DB_PATH + '.tmp', JSON.stringify(db, null, 2));
  fs.renameSync(DB_PATH + '.tmp', DB_PATH);
}

// ── GitHub App helpers ─────────────────────────────────────────────────────
function createAppJwt(appId, privateKey) {
  const now = Math.floor(Date.now() / 1000);
  return jwt.sign({ iss: appId, iat: now, exp: now + 600 }, privateKey, { algorithm: 'RS256' });
}

async function getInstallationToken(installationId, appId, privateKey) {
  const jwtToken = createAppJwt(appId, privateKey);
  const res = await fetch(`https://api.github.com/app/installations/${installationId}/access_tokens`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${jwtToken}`, Accept: 'application/vnd.github.v3+json' },
  });
  if (!res.ok) throw new Error(`GitHub API ${res.status}: ${await res.text()}`);
  const data = await res.json();
  return data.token;
}

function verifyWebhook(body, signature, secret) {
  if (!secret || !signature) return false;
  const sig = signature.startsWith('sha256=') ? signature.slice(7) : signature;
  const hmac = crypto.createHmac('sha256', secret).update(body).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(hmac));
}

// Resolve which app handles a given installation
function resolveApp(installationId, db) {
  // Check BYO apps first
  for (const [userId, app] of Object.entries(db.byoApps)) {
    if (app.installation_id === installationId) return { appId: app.app_id, privateKey: app.private_key, webhookSecret: app.webhook_secret, source: 'byo' };
  }
  // Fall back to central app
  if (CENTRAL_APP_ID) return { appId: CENTRAL_APP_ID, privateKey: CENTRAL_APP_KEY, webhookSecret: CENTRAL_WEBHOOK_SECRET, source: 'central' };
  return null;
}

// ── Express setup ──────────────────────────────────────────────────────────
app.use(express.json({ limit: '5mb', verify: (req, _, buf) => { req.rawBody = buf.toString(); } }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/health', (_req, res) => res.json({ status: 'ok', version: '2.1.0' }));

// ── Auth ──────────────────────────────────────────────────────────────────
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
    const token = jwt.sign({ sub: payload.sub, email: payload.email, name: payload.name }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, email: payload.email, name: payload.name });
  } catch { res.status(401).json({ error: 'invalid session' }); }
});

function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Bearer ')) return res.status(401).json({ error: 'unauthorized' });
  try { req.user = jwt.verify(auth.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'invalid token' }); }
}

// ── GitHub OAuth (for user identity — required for BYO App path too) ─────
app.get('/api/auth/github/login', (req, res) => {
  if (!CENTRAL_CLIENT_ID) return res.status(503).json({ error: 'GitHub OAuth not configured. Ask the operator to set GH_CLIENT_ID.' });
  const state = crypto.randomBytes(16).toString('hex');
  const url = `https://github.com/login/oauth/authorize?client_id=${CENTRAL_CLIENT_ID}&state=${state}&scope=read:user`;
  res.cookie('oauth_state', state, { maxAge: 600000, httpOnly: true });
  res.redirect(url);
});

app.get('/api/auth/github/callback', async (req, res) => {
  const { code, state } = req.query;
  if (!code || state !== req.cookies?.oauth_state) {
    return res.status(400).type('html').send('<html><body><h1>OAuth failed</h1><p>State mismatch.</p><a href="/">Try again</a></body></html>');
  }
  res.clearCookie('oauth_state');
  try {
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ client_id: CENTRAL_CLIENT_ID, client_secret: CENTRAL_CLIENT_SECRET, code }),
    });
    const { access_token } = await tokenRes.json();
    if (!access_token) throw new Error('No access token');

    const userRes = await fetch('https://api.github.com/user', { headers: { Authorization: `Bearer ${access_token}` } });
    const ghUser = await userRes.json();

    const db = loadDb();
    const userId = 'gh_' + ghUser.id;
    db.users[userId] = { github_id: ghUser.id, login: ghUser.login, avatar_url: ghUser.avatar_url, access_token, created_at: new Date().toISOString() };
    saveDb(db);

    const token = jwt.sign({ sub: userId, name: ghUser.login }, JWT_SECRET, { expiresIn: '24h' });
    res.cookie('vibecheck_token', token, { maxAge: 86400000, httpOnly: false });
    res.redirect('/');
  } catch (e) {
    res.status(500).type('html').send(`<html><body><h1>OAuth error</h1><p>${e.message}</p><a href="/">Try again</a></body></html>`);
  }
});

// ── User / Onboarding state ────────────────────────────────────────────────
app.get('/api/user', requireAuth, (req, res) => {
  const db = loadDb();
  const user = db.users[req.user.sub];
  if (!user) return res.json({ connected: false });

  // Determine onboarding state
  let state = 'connected';
  let activeApp = null;

  // Check BYO apps for this user
  const byoApp = db.byoApps[req.user.sub];
  if (byoApp) {
    activeApp = { source: 'byo', slug: byoApp.slug, app_id: byoApp.app_id };
    if (!byoApp.installation_id) state = 'app_not_installed';
    else state = 'installed';
  } else if (CENTRAL_APP_ID) {
    activeApp = { source: 'central', slug: CENTRAL_APP_SLUG };
    // Check if central app has any installations for this user
    const userInstalls = Object.entries(db.installations).filter(([_, inst]) => inst.owner_login === user.login);
    if (userInstalls.length === 0) state = 'app_not_installed';
    else state = 'installed';
  } else {
    state = 'no_app_configured';
  }

  // Count protected repos
  const protectedCount = Object.values(db.repos).filter(r => r.owner_login === user.login).length;

  res.json({
    connected: true, login: user.login, avatar_url: user.avatar_url,
    onboarding: { state, activeApp },
    stats: { protected_repos: protectedCount, total_scans: db.scans.filter(s => s.owner_login === user.login).length },
    has_byo: !!byoApp,
  });
});

// ── GitHub App install (central app) ──────────────────────────────────────
app.get('/api/github/install', requireAuth, (req, res) => {
  if (!CENTRAL_APP_ID) return res.status(503).json({ error: 'Central GitHub App not configured.' });
  const installUrl = `https://github.com/apps/${CENTRAL_APP_SLUG}/installations/new`;
  res.json({ url: installUrl, slug: CENTRAL_APP_SLUG, source: 'central' });
});

// ── BYO App via Manifest flow ─────────────────────────────────────────────
app.get('/api/github/byo/manifest', requireAuth, (req, res) => {
  const db = loadDb();
  const user = db.users[req.user.sub];
  if (!user) return res.status(401).json({ error: 'Connect GitHub first' });

  const webhookUrl = `${BASE_URL}/api/github/webhook`;
  const callbackUrl = `${BASE_URL}/api/github/byo/callback`;

  const manifest = {
    name: `vibecheck-${user.login}`,
    url: BASE_URL,
    hook_attributes: { url: webhookUrl },
    callback_urls: [callbackUrl],
    public: false,
    default_permissions: {
      contents: 'read',
      metadata: 'read',
      pull_requests: 'write',
      checks: 'write',
      statuses: 'write',
    },
    default_events: ['push', 'pull_request', 'installation', 'installation_repositories'],
    request_oauth_on_install: true,
  };

  // Store manifest in a temp key for callback verification
  const state = crypto.randomBytes(16).toString('hex');
  res.cookie('byo_state', state, { maxAge: 600000, httpOnly: true });

  const manifestEncoded = Buffer.from(JSON.stringify(manifest)).toString('base64');
  const registerUrl = `https://github.com/settings/apps/new?manifest=${manifestEncoded}&state=${state}`;
  res.json({ url: registerUrl });
});

app.get('/api/github/byo/callback', async (req, res) => {
  const { code, state, installation_id } = req.query;
  if (!code || state !== req.cookies?.byo_state) {
    return res.status(400).type('html').send('<html><body><h1>Manifest flow failed</h1><p>State mismatch.</p><a href="/">Try again</a></body></html>');
  }
  res.clearCookie('byo_state');

  try {
    // Exchange the code for app credentials
    const tokenRes = await fetch(`https://api.github.com/app-manifests/${code}/conversions`, {
      method: 'POST',
      headers: { Accept: 'application/vnd.github.v3+json' },
    });
    if (!tokenRes.ok) throw new Error(`Conversion failed: ${tokenRes.status}`);
    const app = await tokenRes.json();

    // app contains: id, slug, client_id, client_secret, private_key, webhook_secret, pem
    const db = loadDb();

    // Identify user from the JWT token in the cookie
    const vibeToken = req.cookies?.vibecheck_token || '';
    let userId = 'unknown';
    try { userId = jwt.verify(vibeToken, JWT_SECRET).sub; } catch {}

    db.byoApps[userId] = {
      app_id: app.id,
      slug: app.slug,
      client_id: app.client_id,
      client_secret: app.client_secret,
      private_key: app.pem,
      webhook_secret: app.webhook_secret,
      installation_id: parseInt(installation_id) || null,
      created_at: new Date().toISOString(),
    };
    saveDb(db);

    // Redirect to home with success
    res.redirect('/?byo=success');
  } catch (e) {
    res.status(500).type('html').send(`<html><body><h1>Manifest error</h1><p>${e.message}</p><a href="/">Try again</a></body></html>`);
  }
});

// ── Protected repos ───────────────────────────────────────────────────────
app.get('/api/repos/protected', requireAuth, (req, res) => {
  const db = loadDb();
  const user = db.users[req.user.sub];
  if (!user) return res.json({ repos: [] });

  // Get all installations visible to this user
  const userInstalls = Object.entries(db.installations)
    .filter(([_, inst]) => inst.owner_login === user.login)
    .map(([id, inst]) => ({ id: parseInt(id), ...inst }));

  const protectedRepos = Object.entries(db.repos)
    .filter(([_, r]) => r.owner_login === user.login)
    .map(([name, settings]) => ({
      full_name: name, ...settings,
      last_scan: db.scans.filter(s => s.repo === name).sort((a, b) => (b.created_at || '').localeCompare(a.created_at || ''))[0] || null,
    }));

  res.json({ installations: userInstalls, repos: protectedRepos });
});

app.patch('/api/repos/protected/:full_name', requireAuth, (req, res) => {
  const db = loadDb();
  const name = decodeURIComponent(req.params.full_name);
  if (!db.repos[name]) return res.status(404).json({ error: 'repo not found' });
  Object.assign(db.repos[name], req.body);
  saveDb(db);
  res.json({ ok: true, settings: db.repos[name] });
});

// ── Webhook (handles both central and BYO apps) ──────────────────────────
app.post('/api/github/webhook', (req, res) => {
  const signature = req.headers['x-hub-signature-256'];
  const event = req.headers['x-github-event'];
  const delivery = req.headers['x-github-delivery'];

  const db = loadDb();

  // Determine which app this webhook is for
  // Try each BYO app's webhook secret, then central
  let secret = CENTRAL_WEBHOOK_SECRET;
  let appSource = 'central';
  for (const [uid, byo] of Object.entries(db.byoApps)) {
    if (verifyWebhook(req.rawBody || '', signature, byo.webhook_secret)) {
      secret = byo.webhook_secret;
      appSource = 'byo';
      break;
    }
  }

  if (!verifyWebhook(req.rawBody || '', signature, secret)) {
    return res.status(401).json({ error: 'invalid signature' });
  }

  console.log(`[webhook] ${event} from ${appSource} app (${delivery})`);
  const payload = req.body;

  try {
    if (event === 'push') handlePushEvent(payload, db).catch(e => console.error('[push]', e.message));
    else if (event === 'pull_request') handlePullRequestEvent(payload, db).catch(e => console.error('[pr]', e.message));
    else if (event === 'installation') handleInstallationEvent(payload, db);
    else if (event === 'installation_repositories') handleInstallationReposEvent(payload, db);
  } catch (e) { console.error('[webhook]', e.message); }

  res.status(202).json({ ok: true });
});

// ── Webhook handlers ──────────────────────────────────────────────────────
function handleInstallationEvent(payload, db) {
  const action = payload.action;
  if (action === 'created') {
    const inst = payload.installation;
    db.installations[inst.id] = {
      owner_login: inst.account.login, owner_type: inst.account.type,
      app_slug: payload.app ? payload.app.slug : CENTRAL_APP_SLUG,
      created_at: new Date().toISOString(), repos: [],
    };
    console.log(`[webhook] App installed by ${inst.account.login}`);
  } else if (action === 'deleted') {
    // Clean up repos for this installation
    const instRepos = Object.entries(db.repos).filter(([_, r]) => r.installation_id === payload.installation.id);
    for (const [name] of instRepos) delete db.repos[name];
    delete db.installations[payload.installation.id];
    console.log(`[webhook] App uninstalled by ${payload.installation.account?.login}`);
  }
  saveDb(db);
}

function handleInstallationReposEvent(payload, db) {
  const instId = payload.installation.id;
  if (!db.installations[instId]) return;
  if (payload.repositories_added) {
    for (const r of payload.repositories_added) {
      if (!db.installations[instId].repos.find(x => x.id === r.id)) {
        db.installations[instId].repos.push({ id: r.id, full_name: r.full_name });
      }
      const owner = db.installations[instId].owner_login;
      db.repos[r.full_name] = {
        installation_id: instId, owner_login: owner,
        scan_on_push: true, scan_on_pr: true, block_deploy: false,
        added_at: new Date().toISOString(),
      };
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

async function handlePushEvent(payload, db) {
  const repo = payload.repository.full_name;
  const ref = payload.ref;
  const commitSha = payload.after;
  const installationId = payload.installation?.id;
  if (!installationId || ref !== 'refs/heads/main') return;

  const settings = db.repos[repo];
  if (!settings || !settings.scan_on_push) return;

  const app = resolveApp(installationId, db);
  if (!app) return;

  try {
    const token = await getInstallationToken(installationId, app.appId, app.privateKey);
    const result = await scanRepo({ repo, token, commitSha, mode: 'push' });
    await updateCommitStatus({ repo, commitSha, token, conclusion: result.clean ? 'success' : 'failure',
      description: `${result.scanned} files, ${result.threats.length} threats` });
  } catch (e) { console.error(`[push] ${repo}: ${e.message}`); }
}

async function handlePullRequestEvent(payload, db) {
  const repo = payload.repository.full_name;
  const headSha = payload.pull_request.head.sha;
  const prNumber = payload.number;
  const installationId = payload.installation?.id;
  if (!installationId) return;

  const settings = db.repos[repo];
  if (!settings || !settings.scan_on_pr) return;

  const app = resolveApp(installationId, db);
  if (!app) return;

  try {
    const token = await getInstallationToken(installationId, app.appId, app.privateKey);
    const result = await scanRepo({ repo, token, commitSha: headSha, mode: 'pr', prNumber });
    await createCheckRun({ repo, headSha, token, conclusion: result.clean ? 'success' : 'failure',
      summary: `${result.scanned} files, ${result.threats.length} threats`,
      annotations: result.threats.slice(0, 10).map(t => ({
        path: t.file, start_line: 1, end_line: 1, annotation_level: 'warning',
        message: `${t.signature} — VibeCheck`,
      })),
    });
  } catch (e) { console.error(`[pr] ${repo}#${prNumber}: ${e.message}`); }
}

// ── GitHub API helpers ────────────────────────────────────────────────────
async function updateCommitStatus({ repo, commitSha, token, conclusion, description }) {
  await fetch(`https://api.github.com/repos/${repo}/statuses/${commitSha}`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github.v3+json' },
    body: JSON.stringify({
      state: conclusion === 'success' ? 'success' : 'failure',
      description: description.slice(0, 140), context: 'VibeCheck',
    }),
  });
}

async function createCheckRun({ repo, headSha, token, conclusion, summary, annotations }) {
  await fetch(`https://api.github.com/repos/${repo}/check-runs`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}`, Accept: 'application/vnd.github.v3+json' },
    body: JSON.stringify({
      name: 'VibeCheck', head_sha: headSha, status: 'completed', conclusion,
      output: { title: 'VibeCheck Malware Scan', summary, annotations: annotations || [] },
    }),
  });
}

// ── Scanner ───────────────────────────────────────────────────────────────
async function scanRepo({ repo, token, commitSha, mode, prNumber, ownerLogin }) {
  const safe = repo.replace(/[^a-zA-Z0-9_-]/g, '_');
  const dest = path.join(SCAN_ROOT, `webhook_${safe}_${commitSha?.slice(0, 7) || Date.now()}`);
  const cloneUrl = `https://x-access-token:${token}@github.com/${repo}.git`;

  execSync(`git clone --depth 1 ${cloneUrl} ${dest}`, { timeout: 120000, stdio: 'pipe' });

  const threats = [];

  // ClamAV
  try {
    const out = execSync(`clamscan --infected --no-summary --recursive ${dest}`, { timeout: 300000, maxBuffer: 10 * 1024 * 1024, encoding: 'utf8' });
    for (const line of out.split('\n')) {
      if (line.includes('FOUND')) {
        const parts = line.split(': ');
        threats.push({ file: parts[0].replace(dest, ''), signature: (parts[1] || '').replace(' FOUND', ''), type: 'clamav' });
      }
    }
  } catch (e) {}

  // Heuristics
  threats.push(...runHeuristics(dest));

  try { fs.rmSync(dest, { recursive: true, force: true }); } catch {}

  // Save to history
  const db = loadDb();
  db.scans.unshift({
    id: crypto.randomUUID(), repo, commit_sha: commitSha, mode, pr_number: prNumber,
    owner_login: ownerLogin || '',
    status: threats.length ? 'infected' : 'clean',
    threats, created_at: new Date().toISOString(),
  });
  if (db.scans.length > 500) db.scans.length = 500;
  saveDb(db);

  return { clean: threats.length === 0, scanned: threats.length, threats };
}

function runHeuristics(root) {
  const threats = [];
  try {
    const files = execSync(`find ${root} -type f 2>/dev/null | head -2000`, { timeout: 10000, encoding: 'utf8' })
      .trim().split('\n').filter(Boolean);

    for (const file of files) {
      const rel = file.replace(root, '');
      const basename = path.basename(file);
      const ext = path.extname(file).toLowerCase();
      let content;
      try { content = fs.readFileSync(file, 'utf8').slice(0, 5000); } catch { continue; }

      if (/\.env/i.test(basename) && (content.includes('SECRET') || content.includes('PASSWORD') || content.includes('API_KEY')))
        threats.push({ file: rel, signature: '.env with credentials', type: 'heuristic' });
      if (/^\.npmrc$/i.test(basename) && content.includes('_authToken'))
        threats.push({ file: rel, signature: '.npmrc with npm auth token', type: 'heuristic' });
      if (/credentials|\.aws|\.s3cfg/i.test(basename) && (content.includes('aws_access_key_id') || content.includes('secret_access_key')))
        threats.push({ file: rel, signature: 'AWS credentials file', type: 'heuristic' });
      if (['.sh', '.bash'].includes(ext)) {
        if (content.includes('curl') && content.includes('bash') && /curl.*\|.*bash/i.test(content))
          threats.push({ file: rel, signature: 'curl-to-bash remote execution', type: 'heuristic' });
        if (content.match(/\/dev\/tcp\//))
          threats.push({ file: rel, signature: 'reverse shell pattern (/dev/tcp)', type: 'heuristic' });
        if (content.match(/eval\s*\(/i) && content.match(/base64|decode|\\x[0-9a-f]{2}/i))
          threats.push({ file: rel, signature: 'obfuscated eval in script', type: 'heuristic' });
      }
      if (['.js', '.jsx', '.ts', '.tsx'].includes(ext)) {
        if ((content.match(/\\x[0-9a-f]{2}/g) || []).length > 20)
          threats.push({ file: rel, signature: 'heavily obfuscated JavaScript', type: 'heuristic' });
        if (content.includes('require("child_process")') && (content.includes('postinstall') || content.includes('preinstall')))
          threats.push({ file: rel, signature: 'install script spawning child_process', type: 'heuristic' });
      }
      // ELF binary check
      if (!['.sh','.bash','.js','.ts','.py','.rb','.go','.rs','.c','.cpp','.h'].includes(ext) && !content.startsWith('#!')) {
        try {
          const buf = fs.readFileSync(file).slice(0, 4);
          if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46)
            threats.push({ file: rel, signature: 'unexpected ELF binary (possible miner/malware)', type: 'heuristic' });
        } catch {}
      }
    }
  } catch {}
  return threats;
}

// ── Legacy endpoints (manual clone + scan) ───────────────────────────────
app.get('/api/repos', requireAuth, (req, res) => {
  try {
    const entries = fs.readdirSync(SCAN_ROOT, { withFileTypes: true }).filter(d => d.isDirectory()).map(d => ({ name: d.name, path: path.join(SCAN_ROOT, d.name) }));
    res.json({ repos: entries });
  } catch { res.json({ repos: [] }); }
});

app.post('/api/repos/clone', requireAuth, (req, res) => {
  const { url, token } = req.body;
  if (!url || !url.match(/^https?:\/\/(www\.)?github\.com\/[\w.-]+\/[\w.-]+/))
    return res.status(400).json({ error: 'Valid GitHub URL required' });
  const name = url.replace(/\.git$/, '').split('/').slice(-2).join('-');
  const dest = path.join(SCAN_ROOT, name);
  if (fs.existsSync(dest)) return res.status(409).json({ error: 'Already cloned' });
  let cloneUrl = url;
  if (token) cloneUrl = url.replace('https://', `https://${token}@`);
  try {
    execSync(`git clone --depth 1 ${cloneUrl} ${dest}`, { timeout: 120000, stdio: 'pipe' });
    res.json({ ok: true, name, path: dest });
  } catch (e) { res.status(500).json({ error: (e.stderr?.toString() || e.message).slice(0, 300) }); }
});

app.delete('/api/repos/:name', requireAuth, (req, res) => {
  const target = path.join(SCAN_ROOT, req.params.name);
  if (!target.startsWith(path.resolve(SCAN_ROOT))) return res.status(400).json({ error: 'invalid path' });
  try { fs.rmSync(target, { recursive: true, force: true }); res.json({ ok: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/scan', requireAuth, (req, res) => {
  const { target, tracked_only } = req.body;
  if (!target) return res.status(400).json({ error: 'target required' });
  const resolved = path.resolve(target);
  if (!resolved.startsWith(path.resolve(SCAN_ROOT))) return res.status(400).json({ error: 'invalid path' });

  const scanId = Date.now().toString(36) + Math.random().toString(36).slice(2, 6);
  const started = new Date().toISOString();
  const entry = { scan_id: scanId, target: resolved, tracked_only: !!tracked_only, status: 'running', started, finished: null, infected: [], errors: [] };

  const db = loadDb();
  db.scans.unshift(entry);
  if (db.scans.length > 500) db.scans.length = 500;
  saveDb(db);
  res.json({ scan_id: scanId, status: 'running', started });

  const args = ['--infected', '--no-summary', '--recursive'];
  let scanTarget = resolved;
  if (tracked_only) {
    try {
      const files = execSync(`git -C ${resolved} ls-files`, { timeout: 10000 }).toString().trim().split('\n').filter(Boolean).map(f => path.join(resolved, f));
      if (!files.length) { updateScan(scanId, { scanned: 0, infected: 0 }); return; }
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
      if (line.includes('FOUND')) { const p = line.split(': '); infected.push({ file: p[0], signature: (p[1] || '').replace(' FOUND', ''), type: 'clamav' }); }
    }
    updateScan(scanId, { scanned: (stdout || '').split('\n').length, infected: infected.length, errors: entry.errors.length }, infected);
    try { fs.unlinkSync(`/tmp/vc-${scanId}.txt`); } catch {}
  });
});

function updateScan(scanId, summary, infected) {
  const db = loadDb();
  const entry = db.scans.find(s => s.scan_id === scanId);
  if (entry) { entry.status = 'done'; entry.finished = new Date().toISOString(); entry.summary = summary; if (infected) entry.infected = infected; saveDb(db); }
}

app.get('/api/scan/:id', requireAuth, (req, res) => {
  const db = loadDb();
  const entry = db.scans.find(s => s.scan_id === req.params.id);
  if (!entry) return res.status(404).json({ error: 'not found' });
  res.json(entry);
});

app.get('/api/scans', requireAuth, (req, res) => {
  const db = loadDb();
  res.json({ scans: db.scans.filter(s => !s.repo).slice(0, 50) });
});

// ── Start ─────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`[vibecheck] port ${PORT} | v2.1.0`);
  if (CENTRAL_APP_ID) console.log(`[vibecheck] Central GitHub App ${CENTRAL_APP_ID} ready`);
  else console.log('[vibecheck] No central GitHub App — users can BYO via Manifest flow');
});
