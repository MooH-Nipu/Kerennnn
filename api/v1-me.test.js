const test = require('node:test');
const assert = require('node:assert/strict');
const { generateApiKey } = require('./_apikeys');
const { fakeReq, fakeRes } = require('./_testkit');

const key = generateApiKey().key;
const sbPath = require.resolve('./_supabase');
require.cache[sbPath] = { id: sbPath, filename: sbPath, loaded: true, exports: { getSupabase: () => ({
  from(table) {
    const data = table === 'api_keys'
      ? { id: 'k1', user_id: 'u1', username: 'apang', key_prefix: 'krn_00000000', scopes: ['ioc:scan'], allowed_types: ['ip'], enabled: true, revoked_at: null }
      : { id: 'u1', username: 'apang', role: 'l2', team_access: ['PAC'] };
    const b = {
      select: () => b, eq: () => b, is: () => b, update: () => b,
      maybeSingle: async () => ({ data, error: null }),
      then: (ok, no) => Promise.resolve({ data: null, error: null }).then(ok, no),
    };
    return b;
  },
}) } };
const handler = require('./v1/me');

test('reports the key identity and its ACL', async () => {
  const res = fakeRes();
  await handler(fakeReq({ headers: { authorization: `Bearer ${key}` } }), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.user.username, 'apang');
  assert.deepEqual(res.body.key.scopes, ['ioc:scan']);
  assert.deepEqual(res.body.key.allowedTypes, ['ip']);
  assert.match(res.body.endpoints.scan, /POST \/api\/v1\/scan/);
});

test('rejects a request without a key', async () => {
  const res = fakeRes();
  await handler(fakeReq({}), res);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error.code, 'MISSING_API_KEY');
});
