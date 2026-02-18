/**
 * DEAD DROP — Self-hosted secret sharing service
 * Ensign Wesley | Challenge #3
 *
 * Security model:
 *  - Client-side AES-GCM-256 encryption via Web Crypto API
 *  - Encryption key lives ONLY in URL fragment (never sent to server)
 *  - Server stores only opaque ciphertext + IV
 *  - Burn-after-read: secret deleted on first retrieval
 *  - Optional TTL: auto-delete after N hours
 *  - Rate limiting: max 10 creates per IP per 10 minutes
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const url = require('url');

// ── Config ────────────────────────────────────────────────────────────────────
const PORT = 3001;
const SECRETS_DIR = path.join(__dirname, 'secrets');
const MAX_SECRET_SIZE = 64 * 1024; // 64 KB
const RATE_LIMIT_MAX = 10;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000; // 10 minutes
const CLEANUP_INTERVAL_MS = 60 * 1000; // clean up expired secrets every minute
const DEFAULT_TTL_HOURS = 24;
const MAX_TTL_HOURS = 168; // 7 days
const MAX_LIVE_SECRETS = 1000; // global cap — prevents storage exhaustion DoS (TM-002)

// ── Rate limiting (in-memory) ─────────────────────────────────────────────────
const rateLimitMap = new Map(); // ip -> { count, windowStart }

function checkRateLimit(ip) {
  const now = Date.now();
  const entry = rateLimitMap.get(ip);

  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    rateLimitMap.set(ip, { count: 1, windowStart: now });
    return true;
  }

  if (entry.count >= RATE_LIMIT_MAX) return false;

  entry.count++;
  return true;
}

// Clean up old rate limit entries periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, entry] of rateLimitMap.entries()) {
    if (now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
      rateLimitMap.delete(ip);
    }
  }
}, RATE_LIMIT_WINDOW_MS);

// ── Secret storage ────────────────────────────────────────────────────────────
function secretPath(id) {
  // Validate id is a UUID to prevent path traversal
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
    return null;
  }
  return path.join(SECRETS_DIR, id + '.json');
}

function saveSecret(id, data) {
  const p = secretPath(id);
  if (!p) throw new Error('Invalid ID');
  fs.writeFileSync(p, JSON.stringify(data), { mode: 0o600 });
}

function loadAndDeleteSecret(id) {
  const p = secretPath(id);
  if (!p || !fs.existsSync(p)) return null;
  try {
    const raw = fs.readFileSync(p, 'utf8');
    fs.unlinkSync(p); // BURN — delete immediately on read
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

// ── TTL cleanup ───────────────────────────────────────────────────────────────
function cleanupExpired() {
  try {
    const files = fs.readdirSync(SECRETS_DIR);
    const now = Date.now();
    let cleaned = 0;

    for (const file of files) {
      if (!file.endsWith('.json')) continue;
      const p = path.join(SECRETS_DIR, file);
      try {
        const data = JSON.parse(fs.readFileSync(p, 'utf8'));
        const ttlMs = (data.ttl_hours || DEFAULT_TTL_HOURS) * 60 * 60 * 1000;
        if (now - data.created_at > ttlMs) {
          fs.unlinkSync(p);
          cleaned++;
        }
      } catch {
        // Corrupted file — nuke it
        try { fs.unlinkSync(p); } catch {}
      }
    }

    if (cleaned > 0) {
      console.log(`[cleanup] Deleted ${cleaned} expired secret(s)`);
    }
  } catch (err) {
    console.error('[cleanup] Error:', err.message);
  }
}

setInterval(cleanupExpired, CLEANUP_INTERVAL_MS);

// ── HTML Templates ────────────────────────────────────────────────────────────
const CSS = `
  :root {
    --bg: #0a0e12;
    --bg2: #111820;
    --bg3: #1a2332;
    --teal: #2dd4bf;
    --teal-dim: #1a8a7a;
    --text: #e2e8f0;
    --muted: #64748b;
    --red: #f87171;
    --border: #1e3a4a;
    --font: 'JetBrains Mono', 'Fira Code', 'Courier New', monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font);
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 2rem 1rem;
  }
  header {
    text-align: center;
    margin-bottom: 2.5rem;
  }
  header a {
    color: var(--muted);
    text-decoration: none;
    font-size: 0.75rem;
    letter-spacing: 0.1em;
  }
  header a:hover { color: var(--teal); }
  .logo {
    font-size: 1.8rem;
    font-weight: 700;
    color: var(--teal);
    letter-spacing: 0.15em;
    text-transform: uppercase;
  }
  .logo span { color: var(--muted); }
  .tagline {
    color: var(--muted);
    font-size: 0.75rem;
    letter-spacing: 0.12em;
    margin-top: 0.4rem;
  }
  .card {
    background: var(--bg2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 2rem;
    width: 100%;
    max-width: 640px;
  }
  label {
    display: block;
    color: var(--teal);
    font-size: 0.72rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 0.5rem;
  }
  textarea {
    width: 100%;
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.9rem;
    padding: 0.75rem;
    resize: vertical;
    min-height: 150px;
    outline: none;
    transition: border-color 0.2s;
  }
  textarea:focus { border-color: var(--teal-dim); }
  select {
    background: var(--bg3);
    border: 1px solid var(--border);
    border-radius: 4px;
    color: var(--text);
    font-family: var(--font);
    font-size: 0.85rem;
    padding: 0.6rem 0.75rem;
    outline: none;
    cursor: pointer;
    appearance: none;
    -webkit-appearance: none;
    background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'%3E%3Cpath d='M1 1l5 5 5-5' stroke='%232dd4bf' stroke-width='2' fill='none'/%3E%3C/svg%3E");
    background-repeat: no-repeat;
    background-position: right 0.75rem center;
    padding-right: 2rem;
  }
  select:focus { border-color: var(--teal-dim); }
  .field { margin-bottom: 1.5rem; }
  .row { display: flex; gap: 1rem; align-items: flex-end; }
  button {
    background: var(--teal);
    color: var(--bg);
    border: none;
    border-radius: 4px;
    font-family: var(--font);
    font-size: 0.85rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.7rem 1.5rem;
    cursor: pointer;
    transition: background 0.2s, transform 0.1s;
    white-space: nowrap;
  }
  button:hover { background: #3ae8d0; }
  button:active { transform: scale(0.98); }
  button:disabled { background: var(--muted); cursor: not-allowed; }
  button.secondary {
    background: transparent;
    border: 1px solid var(--teal-dim);
    color: var(--teal);
  }
  button.secondary:hover { background: var(--bg3); }
  .result {
    display: none;
    margin-top: 1.5rem;
    padding: 1.25rem;
    background: var(--bg3);
    border: 1px solid var(--teal-dim);
    border-radius: 6px;
  }
  .result.show { display: block; }
  .result-label {
    color: var(--teal);
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    text-transform: uppercase;
    margin-bottom: 0.6rem;
  }
  .result-url {
    color: var(--text);
    font-size: 0.82rem;
    word-break: break-all;
    margin-bottom: 1rem;
    padding: 0.5rem;
    background: var(--bg);
    border-radius: 3px;
  }
  .copy-row { display: flex; gap: 0.75rem; flex-wrap: wrap; }
  .status-msg {
    font-size: 0.75rem;
    color: var(--teal);
    margin-top: 0.5rem;
    min-height: 1.2em;
  }
  .error { color: var(--red); }
  .secret-box {
    padding: 1.5rem;
    background: var(--bg3);
    border: 1px solid var(--teal-dim);
    border-radius: 6px;
    margin-top: 1rem;
    white-space: pre-wrap;
    word-break: break-word;
    line-height: 1.6;
    font-size: 0.92rem;
  }
  .warning {
    color: var(--red);
    font-size: 0.78rem;
    letter-spacing: 0.08em;
    margin-top: 1rem;
    padding: 0.6rem 0.8rem;
    border: 1px solid rgba(248,113,113,0.3);
    border-radius: 4px;
    background: rgba(248,113,113,0.05);
  }
  .notice {
    color: var(--muted);
    font-size: 0.78rem;
    letter-spacing: 0.05em;
    margin-top: 1rem;
    text-align: center;
  }
  .badge {
    display: inline-block;
    font-size: 0.65rem;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    padding: 0.2rem 0.5rem;
    border-radius: 3px;
    background: rgba(45, 212, 191, 0.1);
    color: var(--teal);
    border: 1px solid rgba(45, 212, 191, 0.3);
    vertical-align: middle;
  }
  .spinner {
    display: inline-block;
    width: 14px;
    height: 14px;
    border: 2px solid var(--bg);
    border-top-color: transparent;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
    vertical-align: middle;
    margin-right: 0.4rem;
  }
  @keyframes spin { to { transform: rotate(360deg); } }
  footer {
    margin-top: 3rem;
    color: var(--muted);
    font-size: 0.7rem;
    letter-spacing: 0.08em;
    text-align: center;
  }
  footer a { color: var(--muted); text-decoration: none; }
  footer a:hover { color: var(--teal); }
`;

function htmlPage(title, bodyContent) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${title} — DEAD DROP</title>
  <style>${CSS}</style>
</head>
<body>
  <header>
    <div class="logo">☠ DEAD<span>//</span>DROP</div>
    <div class="tagline">burn after reading · end-to-end encrypted · one-time links</div>
    <div style="margin-top:0.8rem"><a href="/drop">← create new drop</a> &nbsp;·&nbsp; <a href="/">blog</a></div>
  </header>
  ${bodyContent}
  <footer>
    <p>
      <span class="badge">AES-GCM-256</span>&nbsp;
      <span class="badge">client-side enc</span>&nbsp;
      <span class="badge">zero-knowledge</span>
    </p>
    <p style="margin-top:0.8rem">
      key never leaves your browser · server stores only ciphertext ·
      <a href="https://wesley.thesisko.com">ensign wesley</a>
    </p>
  </footer>
</body>
</html>`;
}

const CREATE_PAGE = htmlPage('Create', `
<div class="card">
  <div class="field">
    <label>Secret Message</label>
    <textarea id="secret" placeholder="Eyes only. Type your message here..." autofocus></textarea>
  </div>
  <div class="row">
    <div class="field" style="flex:1">
      <label>Auto-destruct</label>
      <select id="ttl">
        <option value="1">1 hour</option>
        <option value="6">6 hours</option>
        <option value="24" selected>24 hours</option>
        <option value="72">3 days</option>
        <option value="168">7 days</option>
      </select>
    </div>
    <div class="field">
      <button id="createBtn" onclick="createDrop()">⚡ Encrypt &amp; Drop</button>
    </div>
  </div>
  <div id="statusMsg" class="status-msg"></div>
  <div id="result" class="result">
    <div class="result-label">🔐 Your one-time drop link</div>
    <div id="dropUrl" class="result-url"></div>
    <div class="copy-row">
      <button class="secondary" onclick="copyUrl()">📋 Copy Link</button>
      <button class="secondary" onclick="resetForm()">＋ New Drop</button>
    </div>
    <div class="notice">⚠ This link works once. Share it carefully. After viewing, it's gone forever.</div>
  </div>
</div>

<script>
// ── Crypto helpers ────────────────────────────────────────────────────────────
async function generateKey() {
  return await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true, ['encrypt', 'decrypt']
  );
}

async function exportKey(key) {
  const raw = await crypto.subtle.exportKey('raw', key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
}

async function encryptSecret(plaintext, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, encoded
  );
  const toB64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=/g, '');
  return { ciphertext: toB64u(ciphertext), iv: toB64u(iv) };
}

// ── Create flow ───────────────────────────────────────────────────────────────
async function createDrop() {
  const secret = document.getElementById('secret').value.trim();
  const ttl = parseInt(document.getElementById('ttl').value);
  const btn = document.getElementById('createBtn');
  const statusMsg = document.getElementById('statusMsg');

  if (!secret) {
    statusMsg.textContent = 'Nothing to drop.';
    statusMsg.className = 'status-msg error';
    return;
  }
  if (secret.length > 65536) {
    statusMsg.textContent = 'Too large. Max 64 KB.';
    statusMsg.className = 'status-msg error';
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span>Encrypting...';
  statusMsg.textContent = '';

  try {
    const key = await generateKey();
    const { ciphertext, iv } = await encryptSecret(secret, key);
    const keyB64 = await exportKey(key);

    const res = await fetch('/drop/api/create', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ ciphertext, iv, ttl_hours: ttl })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err.error || 'Server error');
    }

    const { id } = await res.json();
    const dropUrl = \`\${location.origin}/drop/s/\${id}#\${keyB64}\`;

    document.getElementById('dropUrl').textContent = dropUrl;
    document.getElementById('result').classList.add('show');
    document.getElementById('secret').value = '';
    btn.innerHTML = '✓ Dropped';
    statusMsg.textContent = 'Encrypted client-side. Server has zero knowledge of the plaintext.';
    statusMsg.className = 'status-msg';

  } catch (err) {
    btn.disabled = false;
    btn.innerHTML = '⚡ Encrypt &amp; Drop';
    statusMsg.textContent = 'Error: ' + err.message;
    statusMsg.className = 'status-msg error';
  }
}

function copyUrl() {
  const url = document.getElementById('dropUrl').textContent;
  navigator.clipboard.writeText(url).then(() => {
    const btn = event.target;
    btn.textContent = '✓ Copied!';
    setTimeout(() => btn.textContent = '📋 Copy Link', 2000);
  });
}

function resetForm() {
  document.getElementById('result').classList.remove('show');
  const btn = document.getElementById('createBtn');
  btn.disabled = false;
  btn.innerHTML = '⚡ Encrypt &amp; Drop';
  document.getElementById('statusMsg').textContent = '';
  document.getElementById('secret').focus();
}
</script>
`);

function viewPage(id) {
  return htmlPage('Open Drop', `
<div class="card">
  <div id="loading">
    <div style="color:var(--muted);font-size:0.85rem;text-align:center;padding:2rem 0">
      <span class="spinner" style="border-color:var(--teal);border-top-color:transparent"></span>
      Retrieving &amp; decrypting...
    </div>
  </div>
  <div id="content" style="display:none">
    <div style="color:var(--teal);font-size:0.75rem;letter-spacing:0.15em;text-transform:uppercase;margin-bottom:0.75rem">
      🔓 Decrypted Message
    </div>
    <div id="secretText" class="secret-box"></div>
    <div class="warning">
      ☠ This secret has been destroyed. It no longer exists on the server.
      Do not close this window — you cannot retrieve it again.
    </div>
  </div>
  <div id="error" style="display:none">
    <div style="color:var(--red);font-size:0.85rem;text-align:center;padding:2rem 0">
      <div style="font-size:2rem;margin-bottom:0.75rem">💀</div>
      <div id="errorMsg"></div>
    </div>
  </div>
</div>

<script>
async function importKey(b64u) {
  const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
  const raw = Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  return await crypto.subtle.importKey(
    'raw', raw, { name: 'AES-GCM' }, false, ['decrypt']
  );
}

async function decryptSecret(ciphertextB64u, ivB64u, key) {
  const fromB64u = (b64u) => {
    const b64 = b64u.replace(/-/g, '+').replace(/_/g, '/');
    const padded = b64 + '='.repeat((4 - b64.length % 4) % 4);
    return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
  };
  const plainBuf = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: fromB64u(ivB64u) },
    key,
    fromB64u(ciphertextB64u)
  );
  return new TextDecoder().decode(plainBuf);
}

async function openDrop() {
  const id = '${id}';
  const keyB64u = location.hash.slice(1);

  if (!keyB64u) {
    showError('Missing decryption key. Did you open the full link?');
    return;
  }

  try {
    const res = await fetch('/drop/api/secret/' + id);
    if (res.status === 404) {
      showError('This drop has expired or was already opened. The secret is gone.');
      return;
    }
    if (!res.ok) throw new Error('Server error ' + res.status);

    const { ciphertext, iv } = await res.json();
    const key = await importKey(keyB64u);
    const plaintext = await decryptSecret(ciphertext, iv, key);

    document.getElementById('loading').style.display = 'none';
    document.getElementById('secretText').textContent = plaintext;
    document.getElementById('content').style.display = 'block';

  } catch (err) {
    showError('Decryption failed: ' + err.message + '. The key may be wrong or the drop corrupted.');
  }
}

function showError(msg) {
  document.getElementById('loading').style.display = 'none';
  document.getElementById('errorMsg').textContent = msg;
  document.getElementById('error').style.display = 'block';
}

openDrop();
</script>
`);
}

// ── Request handling ──────────────────────────────────────────────────────────
function getClientIP(req) {
  // Use X-Real-IP set by nginx from $remote_addr (the actual connecting IP).
  // Do NOT use X-Forwarded-For: it can be spoofed by clients to bypass rate limiting (TM-001).
  // nginx config sets: proxy_set_header X-Real-IP $remote_addr;
  return req.headers['x-real-ip'] || req.socket.remoteAddress || 'unknown';
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (body.length > MAX_SECRET_SIZE) {
        reject(new Error('Payload too large'));
      }
    });
    req.on('end', () => resolve(body));
    req.on('error', reject);
  });
}

function jsonResponse(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function htmlResponse(res, status, html) {
  res.writeHead(status, { 'Content-Type': 'text/html; charset=utf-8' });
  res.end(html);
}

// ── Server ────────────────────────────────────────────────────────────────────
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname.replace(/\/+$/, '') || '/';
  const method = req.method.toUpperCase();

  // Security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'");

  try {
    // GET /drop → create form
    if (method === 'GET' && (pathname === '/drop' || pathname === '')) {
      return htmlResponse(res, 200, CREATE_PAGE);
    }

    // POST /drop/api/create → create secret
    if (method === 'POST' && pathname === '/drop/api/create') {
      const ip = getClientIP(req);
      if (!checkRateLimit(ip)) {
        return jsonResponse(res, 429, { error: 'Rate limit exceeded. Try again later.' });
      }

      // Global storage cap — reject if too many live secrets (TM-002 storage DoS)
      try {
        const liveCount = fs.readdirSync(SECRETS_DIR).filter(f => f.endsWith('.json')).length;
        if (liveCount >= MAX_LIVE_SECRETS) {
          console.warn(`[create] REJECTED: global cap reached (${liveCount} live secrets) ip=${ip}`);
          return jsonResponse(res, 503, { error: 'Service temporarily at capacity. Try again later.' });
        }
      } catch {
        // If we can't read the dir, fail open (don't block legitimate users)
      }

      let body;
      try {
        body = await readBody(req);
      } catch {
        return jsonResponse(res, 413, { error: 'Payload too large.' });
      }

      let payload;
      try {
        payload = JSON.parse(body);
      } catch {
        return jsonResponse(res, 400, { error: 'Invalid JSON.' });
      }

      const { ciphertext, iv, ttl_hours } = payload;

      if (!ciphertext || typeof ciphertext !== 'string' ||
          !iv || typeof iv !== 'string') {
        return jsonResponse(res, 400, { error: 'Missing required fields: ciphertext, iv' });
      }

      // Validate TTL
      const ttl = Math.min(
        Math.max(1, parseInt(ttl_hours) || DEFAULT_TTL_HOURS),
        MAX_TTL_HOURS
      );

      const id = crypto.randomUUID();
      saveSecret(id, {
        ciphertext,
        iv,
        ttl_hours: ttl,
        created_at: Date.now()
      });

      console.log(`[create] id=${id} ttl=${ttl}h ip=${ip}`);
      return jsonResponse(res, 200, { id });
    }

    // GET /drop/s/:id → view page (HTML)
    const viewMatch = pathname.match(/^\/drop\/s\/([^/]+)$/);
    if (method === 'GET' && viewMatch) {
      const id = viewMatch[1];
      // Validate UUID format before serving page
      if (!/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(id)) {
        return htmlResponse(res, 404, htmlPage('Not Found', '<div class="card"><div style="text-align:center;padding:2rem;color:var(--muted)">💀 Drop not found.</div></div>'));
      }
      return htmlResponse(res, 200, viewPage(id));
    }

    // GET /drop/api/secret/:id → retrieve + burn
    const apiMatch = pathname.match(/^\/drop\/api\/secret\/([^/]+)$/);
    if (method === 'GET' && apiMatch) {
      const id = apiMatch[1];
      const secret = loadAndDeleteSecret(id);

      if (!secret) {
        return jsonResponse(res, 404, { error: 'Not found or already read.' });
      }

      // Check TTL before serving
      const ttlMs = (secret.ttl_hours || DEFAULT_TTL_HOURS) * 60 * 60 * 1000;
      if (Date.now() - secret.created_at > ttlMs) {
        return jsonResponse(res, 404, { error: 'This drop has expired.' });
      }

      console.log(`[read] id=${id} — burned`);
      return jsonResponse(res, 200, {
        ciphertext: secret.ciphertext,
        iv: secret.iv
      });
    }

    // 404
    return jsonResponse(res, 404, { error: 'Not found.' });

  } catch (err) {
    console.error('[error]', err);
    return jsonResponse(res, 500, { error: 'Internal server error.' });
  }
});

// ── Startup ───────────────────────────────────────────────────────────────────
// Ensure secrets dir exists
if (!fs.existsSync(SECRETS_DIR)) {
  fs.mkdirSync(SECRETS_DIR, { recursive: true, mode: 0o700 });
}

server.listen(PORT, '127.0.0.1', () => {
  console.log(`[dead-drop] Listening on http://127.0.0.1:${PORT}`);
  console.log(`[dead-drop] Secrets dir: ${SECRETS_DIR}`);
  console.log(`[dead-drop] Rate limit: ${RATE_LIMIT_MAX} creates/${RATE_LIMIT_WINDOW_MS/60000}min per IP`);
});

process.on('SIGTERM', () => {
  console.log('[dead-drop] SIGTERM received, shutting down');
  server.close(() => process.exit(0));
});
