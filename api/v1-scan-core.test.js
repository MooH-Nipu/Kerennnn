const test = require('node:test');
const assert = require('node:assert/strict');
const { scanBatch, MAX_BATCH } = require('./_v1-scan-core');

const vtOk = () => ({ status: 200, body: {
  data: { attributes: { last_analysis_stats: { malicious: 9, suspicious: 2, undetected: 60 }, country: 'NL' } },
  _meta: { cache: { fromCache: true } },
}, headers: {} });

const corrOk = (ioc) => ({ status: 200, body: {
  ioc, type: 'ip', confidence: 78,
  sources: [
    { source: 'VirusTotal', verdict: 'malicious', score: 78, weight: 1 },
    { source: 'AbuseIPDB', verdict: 'suspicious', score: 55, weight: 0.8 },
    { source: 'OTX', skipped: true },
  ],
  riskFactors: [{ code: 'RECENT_ABUSE', severity: 'high' }],
}, headers: {} });

const invoke = async (handler) => (handler === 'vt' ? vtOk() : corrOk('8.8.8.8'));

test('merges VT stats with every correlation source verdict', async () => {
  const out = await scanBatch({
    rawIocs: ['8.8.8.8'],
    allowedTypes: ['ip', 'domain', 'hash'],
    auth: { userId: 'u1' },
    invoke,
    vtHandler: 'vt',
    correlateHandler: 'corr',
  });
  assert.equal(out.results.length, 1);
  const r = out.results[0];
  assert.equal(r.ioc, '8.8.8.8');
  assert.equal(r.verdict, 'HIGH RISK');
  assert.equal(r.confidence, 78);
  assert.equal(r.vt.verdict, 'MALICIOUS');
  assert.equal(r.vt.total, 71);
  assert.equal(r.cached, true);
  assert.deepEqual(r.sources.map(s => s.source), ['VirusTotal', 'AbuseIPDB']);
  assert.equal(r.sources[1].verdict, 'suspicious');
});

test('dedupes, normalizes and reports rejected types', async () => {
  const out = await scanBatch({
    rawIocs: ['8.8.8.8', ' 8.8.8.8 ', 'hxxp://evil.test/x', 'not-an-ioc', '1.1.1.1'],
    allowedTypes: ['ip'],
    auth: { userId: 'u1' },
    invoke,
    vtHandler: 'vt',
    correlateHandler: 'corr',
  });
  assert.deepEqual(out.results.map(r => r.ioc), ['8.8.8.8', '1.1.1.1']);
  assert.deepEqual(out.errors, [
    { ioc: 'evil.test', error: 'TYPE_NOT_ALLOWED' },
    { ioc: 'not-an-ioc', error: 'UNRECOGNIZED_IOC' },
  ]);
});

test('upstream failures surface as errors but do not lose the result row', async () => {
  const out = await scanBatch({
    rawIocs: ['8.8.8.8'],
    allowedTypes: ['ip'],
    auth: { userId: 'u1' },
    invoke: async (handler) => handler === 'vt'
      ? { status: 500, body: { error: 'vt down' }, headers: {} }
      : corrOk('8.8.8.8'),
    vtHandler: 'vt',
    correlateHandler: 'corr',
  });
  assert.equal(out.errors.length, 1);
  assert.equal(out.errors[0].error, 'vt down');
  assert.equal(out.results[0].confidence, 78);
  assert.equal(out.results[0].vt.verdict, 'UNKNOWN');
});

test('batch cap is at most 25', () => {
  assert.ok(MAX_BATCH <= 25);
});
