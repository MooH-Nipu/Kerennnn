const test = require('node:test');
const assert = require('node:assert/strict');
const { generateApiKey } = require('./_apikeys');
const { fakeReq, fakeRes } = require('./_testkit');

const key = generateApiKey().key;
const cachedRow = {
  ip: '8.8.8.8',
  vt_verdict: 'malicious',
  vt_stats: { malicious: 9 },
  vt_payload: { last_analysis_stats: { malicious: 9, suspicious: 2, undetected: 60 }, country: 'NL' },
  corr_confidence: 78,
  corr_payload: { confidence: 78, sources: [{ source: 'VirusTotal', verdict: 'malicious', score: 78 }], riskFactors: [] },
  last_scanned_at: new Date().toISOString(),
};

function install(row, { scopes = ['ioc:read'], allowed_types = ['ip'] } = {}) {
  const sbPath = require.resolve('./_supabase');
  require.cache[sbPath] = { id: sbPath, filename: sbPath, loaded: true, exports: { getSupabase: () => ({
    from(table) {
      const data = table === 'api_keys'
        ? { id: 'k1', user_id: 'u1', username: 'apang', key_prefix: 'krn_00000000', scopes, allowed_types, enabled: true, revoked_at: null }
        : (table === 'app_users' ? { id: 'u1', username: 'apang', role: 'l2', team_access: ['PAC'] } : row);
      const b = {
        select: () => b, eq: () => b, is: () => b, update: () => b,
        maybeSingle: async () => ({ data, error: null }),
        then: (ok, no) => Promise.resolve({ data: null, error: null }).then(ok, no),
      };
      return b;
    },
  }) } };
  delete require.cache[require.resolve('./v1/verdict')];
  return require('./v1/verdict');
}

function req() {
  return fakeReq({ query: { ioc: '8.8.8.8' }, headers: { authorization: `Bearer ${key}` } });
}

test('returns the cached verdict without spending quota', async () => {
  const handler = install(cachedRow);
  const res = fakeRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.verdict, 'HIGH RISK');
  assert.equal(res.body.vt.verdict, 'MALICIOUS');
  assert.equal(res.body.fresh, true);
  assert.equal(res.body.sources.length, 1);
});

test('404 when the IOC was never cached', async () => {
  const handler = install(null);
  const res = fakeRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 404);
  assert.equal(res.body.error.code, 'NOT_CACHED');
});

test('403 when the key has no ioc:read scope', async () => {
  const handler = install(cachedRow, { scopes: ['ioc:scan'] });
  const res = fakeRes();
  await handler(req(), res);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error.code, 'SCOPE_NOT_ALLOWED');
});

test('400 for an unrecognized IOC', async () => {
  const handler = install(cachedRow);
  const res = fakeRes();
  await handler(fakeReq({ query: { ioc: 'not-an-ioc' }, headers: { authorization: `Bearer ${key}` } }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error.code, 'INVALID_IOC');
});
