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

function optionValue(name) {
  const eq = process.argv.find((arg) => arg.startsWith(`${name}=`));
  if (eq) return eq.slice(name.length + 1);
  const idx = process.argv.indexOf(name);
  if (idx !== -1) return process.argv[idx + 1];
  return null;
}

const positionalUrl = process.argv.slice(2).find((arg) => !arg.startsWith('-'));
const baseUrl = (optionValue('--url') || positionalUrl || process.env.DEAD_DROP_URL || 'https://wesley.thesisko.com/drop').replace(/\/+$/, '');

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
  assert.equal(res.headers.get('cache-control'), 'no-store', `${label} no-store cache policy`);
  assert.match(res.headers.get('permissions-policy') || '', /camera=\(\).*microphone=\(\).*geolocation=\(\)/, `${label} browser permissions locked down`);
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

    const statsBeforeRes = await fetch(`${baseUrl}/stats`);
    assert.equal(statsBeforeRes.status, 200, `stats returned ${statsBeforeRes.status}`);
    assertSecurityHeaders(statsBeforeRes, 'stats');
    const statsBefore = await readJson(statsBeforeRes);
    assert.equal(statsBefore.service, 'dead-drop', 'stats identify service');
    assert.equal(statsBefore.reset_on_restart, true, 'stats disclose restart-reset semantics');
    for (const field of ['created_total', 'burned_total', 'expired_total', 'active_drops', 'uptime_seconds', 'ts']) {
      assert.equal(typeof statsBefore[field], 'number', `stats ${field} is numeric`);
    }
    for (const forbidden of ['id', 'ids', 'ip', 'ips', 'secret', 'ciphertext', 'iv', 'drops']) {
      assert.equal(Object.hasOwn(statsBefore, forbidden), false, `stats must not expose ${forbidden}`);
    }

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

    const statsAfterRes = await fetch(`${baseUrl}/stats`);
    assert.equal(statsAfterRes.status, 200, `stats after burn returned ${statsAfterRes.status}`);
    const statsAfter = await readJson(statsAfterRes);
    assert.ok(statsAfter.created_total >= statsBefore.created_total, 'created_total is monotonic during smoke');
    assert.ok(statsAfter.burned_total >= statsBefore.burned_total + 1, 'burned_total reflects the smoke burn');

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
