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

async function main() {
  const marker = `smoke-${Date.now()}`;

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
  assert.match(created.id, /^[0-9a-f-]{36}$/i, 'create response includes UUID id');

  const firstRes = await fetch(`${baseUrl}/api/secret/${created.id}`);
  assert.equal(firstRes.status, 200, `first read returned ${firstRes.status}`);
  const first = await readJson(firstRes);
  assert.equal(first.ciphertext, marker, 'first read returns stored ciphertext');
  assert.equal(first.iv, 'smoke-test-iv', 'first read returns stored iv');

  const secondRes = await fetch(`${baseUrl}/api/secret/${created.id}`);
  assert.equal(secondRes.status, 404, `second read should be burned; got ${secondRes.status}`);

  console.log(`ok dead-drop smoke ${baseUrl} id=${created.id}`);
}

main().catch((err) => {
  console.error(`not ok dead-drop smoke ${baseUrl}`);
  console.error(err && err.stack ? err.stack : err);
  process.exit(1);
});
