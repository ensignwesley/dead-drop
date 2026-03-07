# ☠ DEAD DROP

A self-hosted, zero-knowledge secret sharing service. Burn after reading.

**Live:** https://wesley.thesisko.com/drop

## Security Model

```
Client                          Server
──────                          ──────
Generate AES-GCM-256 key        
Encrypt secret with key         
POST { ciphertext, iv, ttl } ──→ Store opaque blob
Receive { id }          ←───────
Build URL: /drop/s/{id}#{key}   # Key is in hash — never sent to server
Share URL                       

Recipient opens URL             
Fragment (#key) read by JS      
GET /drop/api/secret/{id} ─────→ Return ciphertext + DELETE file
Decrypt client-side     ←───────
Display plaintext               # Server had zero knowledge
```

**Key properties:**
- 🔐 **End-to-end encrypted** — AES-GCM-256 via Web Crypto API
- 🔑 **Zero-knowledge server** — decryption key lives only in URL fragment (never transmitted)
- ☠ **Burn after reading** — secret file deleted immediately on first retrieval
- ⏱ **Auto-expire** — TTL 1h–7d, background cleanup every 60s
- 🚫 **Rate limited** — 10 creates per IP per 10 minutes
- 📁 **No database** — flat files with strict 0600 permissions
- 🛡️ **Security headers** — CSP, X-Frame-Options, nosniff, Referrer-Policy
- 🔒 **Path traversal protection** — UUID format validation before any file access

## Why These Choices

**Client-side encryption over server-side:** The server never needs to see the plaintext. If the server is compromised, secrets are still safe (the key is in the URL fragment, never logged, never transmitted). Threat model: assume server breach.

**Flat files over database:** Smaller attack surface. No SQL injection vectors. Files with 0600 permissions are readable only by the service user. Simpler to audit.

**Node built-ins only:** Zero npm dependencies = zero supply chain risk. `http`, `crypto`, `fs`, `path` — all built into Node.js core.

**UUID v4 for IDs:** Cryptographically random, 122 bits of entropy. Brute-force infeasible.

## Setup

```bash
# Clone and run
git clone https://github.com/ensignwesley/dead-drop
cd dead-drop
mkdir -p secrets
node server.js
```

### Nginx config

```nginx
location /drop {
    proxy_pass http://127.0.0.1:3001;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 10s;
    proxy_connect_timeout 5s;
    client_max_body_size 128k;
}
```

### systemd (user service)

```bash
cp dead-drop.service ~/.config/systemd/user/
systemctl --user enable --now dead-drop
```

## API

```
POST /drop/api/create
  Body: { ciphertext: string, iv: string, ttl_hours: number }
  Returns: { id: string }

GET /drop/api/secret/:id
  Returns: { ciphertext: string, iv: string }
  Side effect: deletes the secret (burn after read)
  404 if not found or already read

GET /drop/s/:id
  Returns: HTML viewer page (decrypts client-side using URL fragment as key)

GET /drop
  Returns: HTML create form

GET /drop/health
  Returns: { ok: true, service: "dead-drop", version: "1.1", active_drops: N, uptime_seconds: N, ts: <epoch_ms> }
  Lightweight health beacon for monitoring systems. Never burns a secret.
```

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Server compromise | Ciphertext only — key never stored or transmitted |
| MITM | HTTPS via Let's Encrypt |
| Replay attack | Burn-after-read; second request gets 404 |
| Brute force IDs | UUID v4 = 122-bit entropy; rate limiting |
| DoS via large payloads | 64KB max payload enforced |
| DoS via create spam | 10 creates/IP/10min rate limit |
| Path traversal | UUID regex validation before file access |
| Secret hoarding | TTL max 7 days; background cleanup |
| XSS | Strict CSP: `default-src 'self'` |
| Clickjacking | `X-Frame-Options: DENY` |

## Config

Edit top of `server.js`:

```js
const PORT = 3001;
const MAX_SECRET_SIZE = 64 * 1024;   // 64 KB
const RATE_LIMIT_MAX = 10;            // creates per window
const RATE_LIMIT_WINDOW_MS = 600000;  // 10 minutes
const MAX_TTL_HOURS = 168;            // 7 days
```

## Tech

- **Runtime:** Node.js v22 (zero npm dependencies)
- **Encryption:** AES-GCM-256 via Web Crypto API (client-side)
- **Storage:** Flat files, `secrets/` directory, mode 0600
- **Reverse proxy:** nginx with Let's Encrypt TLS
- **Process manager:** systemd user service (linger-enabled)

---

*Built by [Ensign Wesley](https://wesley.thesisko.com) — Ensign, junior ops officer.*
