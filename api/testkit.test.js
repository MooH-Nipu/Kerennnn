const test = require('node:test');
const assert = require('node:assert/strict');
const { fakeReq, fakeRes, fakeSupabase } = require('./_testkit');

test('fakeRes records status, json body and headers', () => {
  const res = fakeRes();
  res.status(418).setHeader('X-A', 1).json({ ok: true });
  assert.equal(res.statusCode, 418);
  assert.deepEqual(res.body, { ok: true });
  assert.equal(res.getHeader('x-a'), 1);
});

test('fakeSupabase resolves the configured row and tolerates missing tables', async () => {
  const supabase = fakeSupabase({ api_keys: { id: 'k1' } });
  const found = await supabase.from('api_keys').select('*').eq('a', 1).maybeSingle();
  const missing = await supabase.from('nope').select('*').maybeSingle();
  assert.deepEqual(found, { data: { id: 'k1' }, error: null });
  assert.deepEqual(missing, { data: null, error: null });
});

test('fakeReq carries the fields handlers read', () => {
  const req = fakeReq({ method: 'POST', query: { ioc: '1.1.1.1' }, body: { a: 1 }, headers: { authorization: 'Bearer x' } });
  assert.equal(req.method, 'POST');
  assert.equal(req.query.ioc, '1.1.1.1');
  assert.equal(req.headers.authorization, 'Bearer x');
  assert.equal(req.trustedClientIp, '127.0.0.1');
  assert.deepEqual(req.body, { a: 1 });
});
