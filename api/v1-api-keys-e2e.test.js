/**
 * End-to-end wiring test for the public API: real requireApiKey + real
 * api/v1/scan + real api/api-keys handlers, backed by an in-memory Supabase
 * stand-in that stores rows the way PostgREST would.
 *
 * Proves the multi-key contract without a database:
 *   two keys coexist -> each authenticates -> scopes are per key ->
 *   revoking one leaves the other working.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { fakeReq, fakeRes } = require('./_testkit');

/** Tiny PostgREST-ish store supporting the query shapes these handlers use. */
function memorySupabase() {
  const tables = { api_keys: [], app_users: [{ id: 'u1', username: 'apang', role: 'l2', team_access: ['PAC'] }] };
  
  function builder(table) {
    const rows = tables[table] || (tables[table] = []);
    const filters = [];
    let mode = 'select';
    let payload = null;

    const matches = (row) => filters.every(([col, val]) => row[col] === val);
    const api = {
      select: () => api,
      order: () => api,
      eq: (col, val) => { filters.push([col, val]); return api; },
      is: (col, val) => { filters.push([col, val === null ? null : val]); return api; },
      update: (patch) => { mode = 'update'; payload = patch; return api; },
      insert: (row) => { mode = 'insert'; payload = row; return api; },
      maybeSingle: async () => {
        if (mode === 'insert') {
          const row = { id: randomUUID(), created_at: new Date().toISOString(), enabled: true, revoked_at: null, last_used_at: null, ...payload };
          rows.push(row);
          return { data: row, error: null };
        }
        if (mode === 'update') {
          const hit = rows.find(matches);
          if (!hit) return { data: null, error: null };
          Object.assign(hit, payload);
          return { data: { ...hit }, error: null };
        }
        const hit = rows.find(matches);
        return { data: hit ? { ...hit } : null, error: null };
      },
      then: (ok, no) => {
        if (mode === 'insert') {
          const row = { id: randomUUID(), created_at: new Date().toISOString(), enabled: true, revoked_at: null, last_used_at: null, ...payload };
          rows.push(row);
          return Promise.resolve({ data: [row], error: null }).then(ok, no);
        }
        if (mode === 'update') {
          const hit = rows.find(matches);
          if (hit) Object.assign(hit, payload);
          return Promise.resolve({ data: hit ? [hit] : [], error: null }).then(ok, no);
        }
        return Promise.resolve({ data: rows.filter(matches), error: null }).then(ok, no);
      },
    };
    return api;
  }

  return { from: builder, tables };
}

const sbPath = require.resolve('./_supabase');
const store = memorySupabase();
require.cache[sbPath] = { id: sbPath, filename: sbPath, loaded: true, exports: { getSupabase: () => store } };

const vtPath = require.resolve('./vt');
const corrPath = require.resolve('./correlate');
require.cache[vtPath] = {
  id: vtPath, filename: vtPath, loaded: true,
  exports: async (_req, res) => res.status(200).json({ data: { attributes: { last_analysis_stats: { malicious: 9, undetected: 62 }, country: 'NL' } } }),
};
require.cache[corrPath] = {
  id: corrPath, filename: corrPath, loaded: true,
  exports: async (_req, res) => res.status(200).json({ confidence: 78, sources: [{ source: 'VirusTotal', verdict: 'malicious', score: 78 }], riskFactors: [] }),
};

const keysHandler = require('./api-keys');
const scanHandler = require('./v1/scan');
const meHandler = require('./v1/me');

function sessionReq(method, props = {}) {
  return { ...fakeReq({ method, ...props }), auth: { userId: 'u1', username: 'apang', role: 'l2', teamAccess: ['PAC'] }, authCurrent: true };
}

async function createKey(body) {
  const res = fakeRes();
  await keysHandler(sessionReq('POST', { body }), res);
  assert.equal(res.statusCode, 201, JSON.stringify(res.body));
  return { secret: res.body.secret, id: res.body.key.id };
}

test('two keys coexist, authenticate separately, and revoke independently', async () => {
  const a = await createKey({ label: 'n8n prod', scopes: ['ioc:scan', 'ioc:read'], allowedTypes: ['ip'] });
  const b = await createKey({ label: 'siem probe', scopes: ['ioc:read'], allowedTypes: ['ip'] });

  const listRes = fakeRes();
  await keysHandler(sessionReq('GET'), listRes);
  assert.deepEqual(listRes.body.keys.map(k => k.label).sort(), ['n8n prod', 'siem probe']);

  const scanA = fakeRes();
  await scanHandler(fakeReq({ method: 'POST', headers: { authorization: `Bearer ${a.secret}` }, body: { iocs: ['8.8.8.8'] } }), scanA);
  assert.equal(scanA.statusCode, 200);
  assert.equal(scanA.body.results[0].verdict, 'HIGH RISK');

  const scanB = fakeRes();
  await scanHandler(fakeReq({ method: 'POST', headers: { authorization: `Bearer ${b.secret}` }, body: { iocs: ['8.8.8.8'] } }), scanB);
  assert.equal(scanB.statusCode, 403);
  assert.equal(scanB.body.error.code, 'SCOPE_NOT_ALLOWED');

  const revoke = fakeRes();
  await keysHandler(sessionReq('DELETE', { query: { id: a.id } }), revoke);
  assert.equal(revoke.statusCode, 200);

  const deadA = fakeRes();
  await meHandler(fakeReq({ headers: { authorization: `Bearer ${a.secret}` } }), deadA);
  assert.equal(deadA.statusCode, 401);
  assert.equal(deadA.body.error.code, 'INVALID_API_KEY');

  const liveB = fakeRes();
  await meHandler(fakeReq({ headers: { authorization: `Bearer ${b.secret}` } }), liveB);
  assert.equal(liveB.statusCode, 200);
  assert.equal(liveB.body.key.scopes.length, 1);
});

test('editing one key ACL does not touch the other', async () => {
  const c = await createKey({ label: 'c', scopes: ['ioc:read'], allowedTypes: ['ip'] });
  const d = await createKey({ label: 'd', scopes: ['ioc:read'], allowedTypes: ['ip'] });

  const patch = fakeRes();
  await keysHandler(sessionReq('PATCH', { body: { id: c.id, scopes: ['ioc:scan', 'ioc:read'] } }), patch);
  assert.equal(patch.statusCode, 200);
  assert.deepEqual(patch.body.key.scopes, ['ioc:scan', 'ioc:read']);

  const scanC = fakeRes();
  await scanHandler(fakeReq({ method: 'POST', headers: { authorization: `Bearer ${c.secret}` }, body: { iocs: ['8.8.8.8'] } }), scanC);
  assert.equal(scanC.statusCode, 200);

  const scanD = fakeRes();
  await scanHandler(fakeReq({ method: 'POST', headers: { authorization: `Bearer ${d.secret}` }, body: { iocs: ['8.8.8.8'] } }), scanD);
  assert.equal(scanD.statusCode, 403);
});
