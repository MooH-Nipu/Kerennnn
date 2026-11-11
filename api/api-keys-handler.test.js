const test = require('node:test');
const assert = require('node:assert/strict');
const { fakeReq, fakeRes } = require('./_testkit');

const K1 = {
  id: '11111111-1111-4111-8111-111111111111', label: 'n8n', key_prefix: 'krn_aaaaaaaa',
  scopes: ['ioc:scan'], allowed_types: ['ip'], enabled: true, last_used_at: null, created_at: '2026-11-12T00:00:00Z',
};
const K2 = {
  id: '22222222-2222-4222-8222-222222222222', label: 'laptop cli', key_prefix: 'krn_bbbbbbbb',
  scopes: ['ioc:scan', 'ioc:read'], allowed_types: ['ip', 'domain'], enabled: true, last_used_at: null, created_at: '2026-11-11T00:00:00Z',
};

/** Installs a fake supabase; `live` is what SELECT/UPDATE see. */
function install({ live = [], insertRow = K1, updateRow = K1 } = {}) {
  const calls = { inserts: [], updates: [], filters: [] };
  const sbPath = require.resolve('./_supabase');
  require.cache[sbPath] = { id: sbPath, filename: sbPath, loaded: true, exports: { getSupabase: () => ({
    from() {
      let mode = 'select';
      const b = {};
      b.select = () => b;
      b.order = () => b;
      b.is = () => b;
      b.eq = (col, val) => { calls.filters.push([col, val]); return b; };
      b.update = (patch) => { calls.updates.push(patch); mode = 'update'; return b; };
      b.insert = (row) => { calls.inserts.push(row); mode = 'insert'; return b; };
      b.maybeSingle = async () => ({ data: mode === 'insert' ? insertRow : (mode === 'update' ? updateRow : (live[0] || null)), error: null });
      b.then = (ok, no) => Promise.resolve({ data: mode === 'select' ? live : [], error: null }).then(ok, no);
      return b;
    },
  }) } };
  delete require.cache[require.resolve('./api-keys')];
  return { handler: require('./api-keys'), calls };
}

function req(method, { body, query } = {}) {
  return { ...fakeReq({ method, body, query }), auth: { userId: 'u1', username: 'apang', role: 'l2', teamAccess: ['PAC'] }, authCurrent: true };
}

test('GET lists every live key for the user, never a secret', async () => {
  const { handler } = install({ live: [K1, K2] });
  const res = fakeRes();
  await handler(req('GET'), res);
  assert.equal(res.statusCode, 200);
  assert.equal(res.body.keys.length, 2);
  assert.deepEqual(res.body.keys.map(k => k.label), ['n8n', 'laptop cli']);
  assert.equal(JSON.stringify(res.body).includes('secret'), false);
});

test('POST adds a second key alongside existing ones', async () => {
  const { handler, calls } = install({ live: [K1] });
  const res = fakeRes();
  await handler(req('POST', { body: { label: 'siem probe', scopes: ['ioc:read'], allowedTypes: ['domain'] } }), res);
  assert.equal(res.statusCode, 201);
  assert.match(res.body.secret, /^krn_[0-9a-f]{8}_/);
  const keyInserts = calls.inserts.filter(row => row.key_hash);
  assert.equal(keyInserts.length, 1, 'exactly one api_keys row (audit rows are separate)');
  const inserted = keyInserts[0];
  assert.equal(inserted.label, 'siem probe');
  assert.deepEqual(inserted.scopes, ['ioc:read']);
  assert.deepEqual(inserted.allowed_types, ['domain']);
  assert.equal(inserted.key_hash.length, 64);
  assert.equal(JSON.stringify(inserted).includes(res.body.secret), false, 'secret must never be persisted');
});

test('POST refuses once the per-user cap is reached', async () => {
  const { handler } = install({ live: Array.from({ length: 10 }, (_, i) => ({ ...K1, id: `${i}` })) });
  const res = fakeRes();
  await handler(req('POST', { body: {} }), res);
  assert.equal(res.statusCode, 409);
  assert.equal(res.body.error.code, 'KEY_LIMIT_REACHED');
});

test('PATCH targets one key and scopes the query by user_id', async () => {
  const { handler, calls } = install({ live: [K1], updateRow: { ...K1, scopes: ['ioc:read'] } });
  const res = fakeRes();
  await handler(req('PATCH', { body: { id: K1.id, scopes: ['ioc:read'] } }), res);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(res.body.key.scopes, ['ioc:read']);
  assert.deepEqual(calls.filters, [['id', K1.id], ['user_id', 'u1']], 'ownership must be part of the WHERE clause');
});

test('PATCH without an id is rejected', async () => {
  const { handler } = install({ live: [K1] });
  const res = fakeRes();
  await handler(req('PATCH', { body: { enabled: false } }), res);
  assert.equal(res.statusCode, 400);
  assert.equal(res.body.error.code, 'MISSING_KEY_ID');
});

test('DELETE revokes one key by id, scoped by user_id', async () => {
  const { handler, calls } = install({ live: [K1], updateRow: K1 });
  const res = fakeRes();
  await handler(req('DELETE', { query: { id: K2.id } }), res);
  assert.equal(res.statusCode, 200);
  assert.equal(calls.updates[0].enabled, false);
  assert.ok(calls.updates[0].revoked_at, 'revocation must be timestamped');
  assert.deepEqual(calls.filters, [['id', K2.id], ['user_id', 'u1']]);
});

test('PATCH/DELETE on a foreign key is a 404, not a 403 leak', async () => {
  for (const [method, extra] of [
    ['PATCH', { body: { id: K1.id, enabled: false } }],
    ['DELETE', { query: { id: K1.id } }],
  ]) {
    const { handler } = install({ live: [K1], updateRow: null });
    const res = fakeRes();
    await handler(req(method, extra), res);
    assert.equal(res.statusCode, 404, method);
    assert.equal(res.body.error.code, 'KEY_NOT_FOUND', method);
  }
});
