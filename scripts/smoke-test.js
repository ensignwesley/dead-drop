#!/usr/bin/env node
/**
 * Dead Drop smoke test.
 *
 * Exercises the deployed API contract without exposing real secrets:
 * create an opaque ciphertext blob, retrieve it once, then verify the
 * second read is burned. Uses only Node built-ins.
 */

'use strict';

const assert = require('node:assert/strict');

const baseUrl = (process.argv[2] || process.env.DEAD_DROP_URL || 'https://wesley.thesisko.com/drop').replace(/\/+$/, '');

async function readJson(res) {
  const text = await res.text();
  try {
    return JSON.parse(text);
  } catch (err) {
    throw new Error(`Expected JSON from ${res.url || 'response'}; got ${text.slice(0, 120)}`);
  }
}

function assertSecurityHeaders(res, label) {
  assert.equal(res.headers.get('x-content-type-options'), 'nosniff', `${label} nosniff header`);
  assert.equal(res.headers.get('x-frame-options'), 'DENY', `${label} frame denial header`);
  assert.equal(res.headers.get('referrer-policy'), 'no-referrer', `${label} referrer policy header`);
  assert.match(res.headers.get('content-security-policy') || '', /default-src 'self'/, `${label} CSP header`);
}

async function main() {
  const marker = `smoke-${Date.now()}`;
  const oversizedCiphertext = 'x'.repeat(64 * 1024 + 1);
  let createdId = null;
  let burned = false;

  try {
    const pageRes = await fetch(`${baseUrl}/`, { headers: { 'User-Agent': 'dead-drop-smoke/1.0' } });
    assert.equal(pageRes.status, 200, `page returned ${pageRes.status}`);
    assertSecurityHeaders(pageRes, 'page');

    const createRes = await fetch(`${baseUrl}/api/create`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ciphertext: marker,
        iv: 'smoke-test-iv',
        ttl_hours: 1,
      }),
    });
    assert.equal(createRes.status, 200, `create returned ${createRes.status}`);
    const created = await readJson(createRes);
    createdId = created.id;
    assert.match(created.id, /^[0-9a-f-]{36}$/i, 'create response includes UUID id');

    const healthRes = await fetch(`${baseUrl}/health`);
    assert.equal(healthRes.status, 200, `health returned ${healthRes.status}`);
    assertSecurityHeaders(healthRes, 'health');
    const health = await readJson(healthRes);
    assert.equal(health.ok, true, 'health reports ok=true');
    assert.equal(health.storage?.readable, true, 'health reports storage readable');
    assert.equal(health.storage?.writable, true, 'health reports storage writable');

    const headRes = await fetch(`${baseUrl}/s/${created.id}`, { method: 'HEAD' });
    assert.equal(headRes.status, 200, `HEAD view returned ${headRes.status}`);

    const firstRes = await fetch(`${baseUrl}/api/secret/${created.id}`);
    assert.equal(firstRes.status, 200, `first read returned ${firstRes.status}`);
    const first = await readJson(firstRes);
    assert.equal(first.ciphertext, marker, 'first read returns stored ciphertext');
    assert.equal(first.iv, 'smoke-test-iv', 'first read returns stored iv');

    const secondRes = await fetch(`${baseUrl}/api/secret/${created.id}`);
    assert.equal(secondRes.status, 404, `second read should be burned; got ${secondRes.status}`);
    burned = true;

    const oversizedRes = await fetch(`${baseUrl}/api/create`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        ciphertext: oversizedCiphertext,
        iv: 'smoke-test-iv',
        ttl_hours: 1,
      }),
    });
    assert.equal(oversizedRes.status, 413, `oversized create should be rejected; got ${oversizedRes.status}`);
    const oversized = await readJson(oversizedRes);
    assert.equal(oversized.error, 'Payload too large.', 'oversized create returns a clear rejection');

    console.log(`ok dead-drop smoke ${baseUrl} id=${created.id}`);
  } finally {
    if (createdId && !burned) {
      try {
        await fetch(`${baseUrl}/api/secret/${createdId}`, { headers: { 'User-Agent': 'dead-drop-smoke/1.0' } });
      } catch {
        // Best-effort cleanup only.
      }
    }
  }
}

main().catch((err) => {
  console.error(`not ok dead-drop smoke ${baseUrl}`);
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
