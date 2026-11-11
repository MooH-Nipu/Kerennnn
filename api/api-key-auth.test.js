const test = require('node:test');
const assert = require('node:assert/strict');
const { requireApiKey, generateApiKey } = require('./_apikeys');
const { fakeReq, fakeRes, fakeSupabase } = require('./_testkit');

const key = generateApiKey();
const keyRow = {
  id: 'k1', user_id: 'u1', username: 'apang', key_prefix: key.prefix,
  scopes: ['ioc:scan'], allowed_types: ['ip'], enabled: true, revoked_at: null,
};
const userRow = { id: 'u1', username: 'apang', role: 'l2', team_access: ['PAC'] };

function req() {
  return fakeReq({ headers: { authorization: `Bearer ${key.key}` } });
}

test('valid key injects req.auth and req.apiKey', async () => {
  const r = req(); const res = fakeRes();
  const ok = await requireApiKey(r, res, fakeSupabase({ api_keys: keyRow, app_users: userRow }), 'ioc:scan');
  assert.equal(ok, true);
  assert.equal(res.statusCode, 200);
  assert.equal(r.auth.userId, 'u1');
  assert.equal(r.auth.role, 'l2');
  assert.deepEqual(r.auth.teamAccess, ['PAC']);
  assert.equal(r.authCurrent, true);
  assert.equal(r.apiKey.prefix, key.prefix);
  assert.deepEqual(r.apiKey.allowedTypes, ['ip']);
  assert.equal(res.getHeader('x-api-key-prefix'), key.prefix);
});

test('missing header is 401 MISSING_API_KEY', async () => {
  const res = fakeRes();
  const ok = await requireApiKey(fakeReq(), res, fakeSupabase({}), 'ioc:scan');
  assert.equal(ok, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error.code, 'MISSING_API_KEY');
});

test('unknown or disabled key is 401 INVALID_API_KEY', async () => {
  for (const row of [null, { ...keyRow, enabled: false }]) {
    const res = fakeRes();
    const ok = await requireApiKey(req(), res, fakeSupabase({ api_keys: row }), 'ioc:scan');
    assert.equal(ok, false);
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error.code, 'INVALID_API_KEY');
  }
});

test('missing scope is 403 SCOPE_NOT_ALLOWED', async () => {
  const res = fakeRes();
  const ok = await requireApiKey(req(), res, fakeSupabase({ api_keys: keyRow, app_users: userRow }), 'ioc:read');
  assert.equal(ok, false);
  assert.equal(res.statusCode, 403);
  assert.equal(res.body.error.code, 'SCOPE_NOT_ALLOWED');
});

test('deleted owner is 401 KEY_OWNER_MISSING', async () => {
  const res = fakeRes();
  const ok = await requireApiKey(req(), res, fakeSupabase({ api_keys: keyRow, app_users: null }), 'ioc:scan');
  assert.equal(ok, false);
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error.code, 'KEY_OWNER_MISSING');
});
