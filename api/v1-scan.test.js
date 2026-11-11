const test = require('node:test');
const assert = require('node:assert/strict');

// The handler resolves deps at require time; stub the two upstream handlers so
// this test never touches VirusTotal or Supabase.
const vtPath = require.resolve('./vt');
const corrPath = require.resolve('./correlate');
require.cache[vtPath] = {
  id: vtPath, filename: vtPath, loaded: true,
  exports: async (_req, res) => res.status(200).json({ data: { attributes: { last_analysis_stats: { malicious: 9, undetected: 62 } } } }),
};
require.cache[corrPath] = {
  id: corrPath, filename: corrPath, loaded: true,
  exports: async (_req, res) => res.status(200).json({ confidence: 78, sources: [{ source: 'VirusTotal', verdict: 'malicious', score: 78 }], riskFactors: [] }),
};

const sbPath = require.resolve('./_supabase');
require.cache[sbPath] = {
  id: sbPath, filename: sbPath, loaded: true,
  exports: { getSupabase: () => ({
    from(table) {
      const row = table === 'api_keys'
        ? { id: 'k1', user_id: 'u1', username: 'apang', key_prefix: 'krn_00000000', scopes: ['ioc:scan'], allowed_types: ['ip'], enabled: true, revoked_at: null }
        : { id: 'u1', username: 'apang', role: 'l2', team_access: ['PAC'] };
      const b = {
        select: () => b, eq: () => b, is: () => b, update: () => b,
        maybeSingle: async () => ({ data: row, error: null }),
        then: (ok, no) => Promise.resolve({ data: null, error: null }).then(ok, no),
      };
      return b;
    },
  }) },
};

const handler = require('./v1/scan');
const { generateApiKey } = require('./_apikeys');
const { fakeReq, fakeRes } = require('./_testkit');

const key = generateApiKey().key;

test('POST /api/v1/scan returns merged verdicts for an authorized key', async () => {
  const res = fakeRes();
  const req = fakeReq({ method: 'POST', headers: { authorization: `Bearer ${key}` }, body: { iocs: ['8.8.8.8'] } });
  await handler(req, res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.ok, true);
  assert.equal(res.body.count, 1);
  assert.equal(res.body.results[0].verdict, 'HIGH RISK');
  assert.equal(res.body.results[0].sources[0].source, 'VirusTotal');
  assert.equal(res.body.key.prefix, 'krn_00000000');
});

test('rejects a request without a key', async () => {
  const res = fakeRes();
  await handler(fakeReq({ method: 'POST', body: { iocs: ['8.8.8.8'] } }), res);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error.code, 'MISSING_API_KEY');
});

test('rejects an empty or oversized batch', async () => {
  for (const body of [{}, { iocs: [] }]) {
    const res = fakeRes();
    await handler(fakeReq({ method: 'POST', headers: { authorization: `Bearer ${key}` }, body }), res);
    assert.equal(res.statusCode, 400);
    assert.equal(res.body.error.code, 'NO_IOCS');
  }
  const res = fakeRes();
  await handler(fakeReq({
    method: 'POST',
    headers: { authorization: `Bearer ${key}` },
    body: { iocs: Array.from({ length: 26 }, () => '8.8.8.8') },
  }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error.code, 'BATCH_TOO_LARGE');
});

test('rejects non-POST methods', async () => {
  const res = fakeRes();
  await handler(fakeReq({ method: 'GET' }), res);
  assert.equal(res.statusCode, 405);
  assert.equal(res.body.error.code, 'METHOD_NOT_ALLOWED');
});
