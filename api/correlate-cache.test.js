'use strict';
/**
 * Correlation cache short-circuit. Asserts the branch the old code was missing:
 * a repeat scan of a domain or hash reads vt_ioc_cache instead of silently
 * re-running every provider. Stubbed Supabase, no network, no keys.
 */
const test = require('node:test');
const assert = require('node:assert/strict');

const supabasePath = require.resolve('./_supabase');
const httpPath = require.resolve('./_http');
const authPath = require.resolve('./_auth');
const budgetPath = require.resolve('./_scan-budget');

function payload(confidence, ageMs = 60_000) {
  return {
    ioc: 'example.com',
    type: 'domain',
    confidence,
    // Freshness now keys off the payload's own observation time.
    correlatedAt: new Date(Date.now() - ageMs).toISOString(),
    sources: [{ source: 'VirusTotal', verdict: 'clean' }],
    scoring: { version: 4 },
  };
}

// Records every table/column touched so the assertion is about the query, not
// about a return value both implementations could produce.
function stubDb({ row }) {
  const seen = { tables: [], columns: [], filters: [] };
  const supabase = {
    from(table) {
      seen.tables.push(table);
      const chain = {
        select(cols) { seen.columns.push(cols); return chain; },
        eq(col, val) { seen.filters.push([col, val]); return chain; },
        maybeSingle: async () => ({ data: row, error: null }),
        update() { return { eq: async () => ({ error: null }) }; },
        is() { return chain; },
        range() { return chain; },
        order() { return chain; },
      };
      return chain;
    },
  };
  return { supabase, seen };
}

function withStubs({ supabase }, fn) {
  const originals = [supabasePath, httpPath, authPath, budgetPath].map(p => [p, require.cache[p]]);
  const put = (p, exports) => { require(p); require.cache[p].exports = exports; };
  put(supabasePath, { getSupabase: () => supabase });
  put(httpPath, { httpGet: async () => { throw new Error('no upstream call expected'); }, httpPost: async () => { throw new Error('no upstream call expected'); }, httpGetText: async () => ({ status: 200, text: '' }), withTimeout: (p) => p });
  put(authPath, { requireAuth: () => true, readJsonBody: async () => ({}) });
  put(budgetPath, { consumeScanBudget: () => true });
  const handlerPath = require.resolve('./correlate');
  const hadHandler = require.cache[handlerPath];
  delete require.cache[handlerPath];
  return Promise.resolve()
    .then(() => fn(require('./correlate')))
    .finally(() => {
      for (const [p, entry] of originals) {
        if (entry) require.cache[p] = entry; else delete require.cache[p];
      }
      if (hadHandler) require.cache[handlerPath] = hadHandler; else delete require.cache[handlerPath];
    });
}

function response() {
  return {
    headers: {}, statusCode: null, body: null,
    setHeader(n, v) { this.headers[n] = v; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this; },
    end() { return this; },
  };
}

const freshRow = (type, confidence) => ({
  corr_payload: payload(confidence),
  vt_verdict: 'clean',
  // Clean evidence is fresh for 1h under the shared TTL policy.
  last_scanned_at: new Date(Date.now() - 60_000).toISOString(),
  first_scanned_at: new Date(Date.now() - 60_000).toISOString(),
  ioc_type: type,
});

test('repeat domain scan is served from vt_ioc_cache with no upstream call', () =>
  withStubs(stubDb({ row: freshRow('domain', 26) }), async (handler) => {
    const res = response();
    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res);
    assert.equal(res.statusCode, 200);
    assert.equal(res.body.confidence, 26);
  }));

test('the domain branch queries vt_ioc_cache keyed by ioc_type and ioc', async () => {
  const db = stubDb({ row: freshRow('domain', 26) });
  await withStubs(db, async (handler) => {
    await handler({ method: 'GET', query: { ioc: 'example.com' } }, response());
  });
  assert.deepEqual(db.seen.tables, ['vt_ioc_cache']);
  assert.deepEqual(db.seen.filters, [['ioc_type', 'domain'], ['ioc', 'example.com']]);
});

test('repeat IP scan still reads vt_ip_cache', async () => {
  const db = stubDb({ row: { ...freshRow('ip', 70), ip: '192.0.2.55' } });
  await withStubs(db, async (handler) => {
    await handler({ method: 'GET', query: { ioc: '192.0.2.55' } }, response());
  });
  assert.deepEqual(db.seen.tables, ['vt_ip_cache']);
});

test('stale evidence is not served from cache', () =>
  withStubs(stubDb({ row: { ...freshRow('domain', 26), corr_payload: payload(26, 5 * 3_600_000) } }), async (handler) => {
    const res = response();
    // Providers are stubbed to throw, so a cache miss surfaces as a 500 rather
    // than a 200 — which is exactly the proof that it did NOT short-circuit.
    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res).catch(() => {});
    assert.notEqual(res.body?.confidence, 26);
  }));

test('a payload with no correlatedAt is treated as stale', () =>
  withStubs(stubDb({ row: { ...freshRow('domain', 26), corr_payload: { ...payload(26), correlatedAt: undefined } } }), async (handler) => {
    const res = response();
    await handler({ method: 'GET', query: { ioc: 'example.com' } }, res).catch(() => {});
    assert.notEqual(res.body?.confidence, 26);
  }));

test('refresh=1 skips the cache even when a fresh row exists', () =>
  withStubs(stubDb({ row: freshRow('domain', 26) }), async (handler) => {
    const res = response();
    await handler({ method: 'GET', query: { ioc: 'example.com', refresh: '1' } }, res).catch(() => {});
    // Same reasoning as above: bypassing the cache must not return the row.
    assert.notEqual(res.body?.confidence, 26);
  }));
