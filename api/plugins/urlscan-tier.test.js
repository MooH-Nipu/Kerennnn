'use strict';
/**
 * URLScan tier selection: the fast path must be used only when public evidence
 * is still inside the shared cache TTL, and must never turn a search miss into
 * a false CLEAN. Both branches are exercised against stubbed HTTP, so no key or
 * network is needed.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const httpPath = require.resolve('../_http');

// Stub the shared HTTP helper for one test, then restore the real module.
// Clears the URLScan module from cache too, so a plugin instance created here
// always binds to the stubbed exports rather than a previous test's.
function withStubs(stubs, fn) {
  const pluginPath = require.resolve('./urlscan');
  const hadPlugin = Boolean(require.cache[pluginPath]);
  delete require.cache[pluginPath];
  require(httpPath); // ensure the cache entry exists before replacing it
  const original = require.cache[httpPath].exports;
  require.cache[httpPath].exports = { ...original, ...stubs };
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      require.cache[httpPath].exports = original;
      delete require.cache[pluginPath];
      if (!hadPlugin) return;
    });
}

function freshRow(domain, ageMs) {
  return {
    task: { uuid: 'uuid-1', time: new Date(Date.now() - ageMs).toISOString(), domain },
    stats: {},
    page: { title: 'Example Domain', status: '200' },
    result: 'https://urlscan.io/result/uuid-1/',
    screenshot: 'https://urlscan.io/screenshots/uuid-1.png',
  };
}

function body(malicious) {
  return {
    task: { uuid: 'uuid-1' },
    page: { title: 'Example Domain', status: '200' },
    verdicts: { overall: { hasVerdicts: true, malicious, score: malicious ? 100 : 0, tags: [] } },
    result: 'https://urlscan.io/result/uuid-1/',
  };
}

// The plugin reads process.env at call time, so one key covers every case.
process.env.URLSCAN_API_KEY = 'x'.repeat(36);

test('a fresh public scan is served without submitting a new one', () =>
  withStubs({
    httpGet: async (url) => {
      if (url.includes('/search/')) return { status: 200, data: { results: [freshRow('example.com', 60_000)] } };
      if (url.includes('/result/')) return { status: 200, data: body(false) };
      throw new Error(`unexpected GET ${url}`);
    },
    httpPost: async () => { throw new Error('must not submit'); },
  }, async () => {
    const { URLScanPlugin } = require('./urlscan');
    const r = await new URLScanPlugin().check('example.com');
    assert.equal(r.source, 'URLScan.io');
    assert.equal(r.verdict, 'clean');
    assert.equal(r.meta.Title, 'Example Domain');
  }));

test('a stale public scan falls through to an active submit', () => {
  let posted = 0;
  return withStubs({
    httpGet: async (url) => {
      if (url.includes('/search/')) return { status: 200, data: { results: [freshRow('example.com', 30 * 86_400_000)] } };
      return { status: 200, data: body(true) };
    },
    httpPost: async () => { posted++; return { status: 200, data: { uuid: 'uuid-2' } }; },
  }, async () => {
    const { URLScanPlugin } = require('./urlscan');
    const r = await new URLScanPlugin().check('example.com');
    assert.equal(posted, 1, 'stale evidence must not short-circuit a live scan');
    assert.equal(r.verdict, 'malicious');
  });
});

test('a search miss falls through to an active submit', () => {
  let posted = 0;
  return withStubs({
    httpGet: async (url) => {
      if (url.includes('/search/')) return { status: 200, data: { results: [] } };
      return { status: 200, data: body(false) };
    },
    httpPost: async () => { posted++; return { status: 200, data: { uuid: 'uuid-3' } }; },
  }, async () => {
    const { URLScanPlugin } = require('./urlscan');
    await new URLScanPlugin().check('never-scanned.example');
    assert.equal(posted, 1);
  });
});

test('refresh opts out of the historical path entirely', () => {
  let searched = 0;
  let posted = 0;
  return withStubs({
    httpGet: async (url) => {
      if (url.includes('/search/')) searched++;
      return { status: 200, data: body(false) };
    },
    httpPost: async () => { posted++; return { status: 200, data: { uuid: 'uuid-4' } }; },
  }, async () => {
    const { URLScanPlugin } = require('./urlscan');
    await new URLScanPlugin().check('example.com', 'domain', { refresh: true });
    assert.equal(searched, 0);
    assert.equal(posted, 1);
  });
});

test('the search predicate is exact-domain, not page-domain', () => {
  let seen = '';
  return withStubs({
    httpGet: async (url) => {
      if (url.includes('/search/')) { seen = decodeURIComponent(url); return { status: 200, data: { results: [] } }; }
      return { status: 200, data: body(false) };
    },
    httpPost: async () => ({ status: 200, data: { uuid: 'uuid-5' } }),
  }, async () => {
    const { URLScanPlugin } = require('./urlscan');
    await new URLScanPlugin().check('example.com');
    // page.domain:example.com matches unrelated domains (verified against the
    // live API: it returned sosnina.icu); task.domain:"…" is exact.
    assert.match(seen, /task\.domain:"example\.com"/);
    assert.doesNotMatch(seen, /page\.domain/);
  });
});
