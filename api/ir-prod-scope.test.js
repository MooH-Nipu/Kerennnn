'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const auth = require('./_auth');
const client = require('./_supabase');
const originalAuth = auth.requireCurrentRole;
const originalDb = client.getSupabase;
const originalEnv = process.env.KERENNNN_DEPLOY_ENV;
const ID = '00000000-0000-4000-8000-000000000002';
const MARKED = '00000000-0000-4000-8000-000000000003';
const rows = [{ id: ID, title: 'production', description: 'prod body', created_by: 'alice' }, { id: MARKED, title: 'development', description: 'dev body', created_by: 'alice' }];
let scopeFailure = false;
let calls = [];
auth.requireCurrentRole = async req => { req.auth = { role: 'admin', username: 'alice', userId: ID }; return true; };
function query(table) {
  const record = { table, select: '', filters: [], action: 'read' };
  calls.push(record);
  const q = {
    select(value) { record.select = value; return q; },
    eq(field, value) { record.filters.push([field, value]); return q; },
    is(field, value) { record.filters.push([field, value]); return q; },
    order() { return q; }, range() { return q; }, or() { return q; },
    insert() { record.action = 'insert'; return q; },
    update() { record.action = 'update'; return q; },
    delete() { record.action = 'delete'; return q; },
    maybeSingle() {
      const id = record.filters.find(([field]) => field === 'id' || field === 'case_id')?.[1];
      const row = table === 'ir_case_dev_scope' ? id === MARKED ? { case_id: MARKED } : null : rows.find(r => r.id === id);
      const scoped = record.select.includes('!inner') ? row?.id === MARKED : record.filters.some(([field]) => field === 'ir_case_dev_scope') ? row?.id !== MARKED : true;
      return Promise.resolve(table === 'ir_case_dev_scope' && scopeFailure ? { data: null, error: { message: 'scope unavailable' } } : { data: scoped ? row ?? null : null });
    },
    then(resolve) {
      const scoped = record.select.includes('!inner') ? rows.filter(r => r.id === MARKED) : record.filters.some(([field]) => field === 'ir_case_dev_scope') ? rows.filter(r => r.id !== MARKED) : rows;
      return Promise.resolve({ data: scoped, count: scoped.length }).then(resolve);
    },
  };
  return q;
}
client.getSupabase = () => ({ from: query, rpc: name => { calls.push({ rpc: name }); return Promise.resolve({ data: null }); } });
const list = require('./ir-cases');
const detail = require('./ir-cases/detail');
function response() { return { setHeader() {}, status(n) { this.code = n; return this; }, json(v) { this.data = v; return this; } }; }
async function run(handler, method, id = ID) {
  calls = [];
  const res = response();
  await handler({ method, query: { id }, body: { id, title: 'updated' } }, res);
  return res;
}
test('production list and detail exclude marked development rows; dev list and detail exclude production rows', async () => {
  for (const [env, expectedId, blockedId, join] of [['prod', ID, MARKED, '!left'], ['dev', MARKED, ID, '!inner']]) {
    process.env.KERENNNN_DEPLOY_ENV = env;
    const listing = await run(list, 'GET');
    assert.equal(listing.code, 200);
    assert.equal(listing.data.deployEnv, env);
    assert.deepEqual(listing.data.cases.map(r => r.id), [expectedId]);
    assert.equal(listing.data.total, 1);
    assert.match(calls.find(c => c.table === 'ir_cases').select, new RegExp(`ir_case_dev_scope${join}`));
    const allowed = await run(detail, 'GET', expectedId);
    assert.equal(allowed.code, 200);
    assert.equal(allowed.data.case.id, expectedId);
    assert.equal(allowed.data.case.ir_case_dev_scope, undefined);
    const denied = await run(detail, 'GET', blockedId);
    assert.equal(denied.code, 404);
  }
});
test('prod PATCH and DELETE reject marked cases; preserve legacy production write paths', async () => {
  process.env.KERENNNN_DEPLOY_ENV = 'prod';
  for (const method of ['PATCH', 'DELETE']) {
    const denied = await run(list, method, MARKED);
    assert.equal(denied.code, 404);
    assert.equal(calls.filter(c => ['update', 'delete'].includes(c.action)).length, 0);
    const allowed = await run(list, method, ID);
    assert.equal(allowed.code, 200);
    assert.equal(calls.find(c => c.table === 'ir_cases').action, method === 'PATCH' ? 'update' : 'delete');
  }
});
test('scope lookup error blocks production PATCH and DELETE without mutations', async () => {
  process.env.KERENNNN_DEPLOY_ENV = 'prod';
  scopeFailure = true;
  try {
    for (const method of ['PATCH', 'DELETE']) {
      const res = await run(list, method, ID);
      assert.equal(res.code, 500);
      assert.equal(calls.filter(c => ['update', 'delete'].includes(c.action)).length, 0);
    }
  } finally { scopeFailure = false; }
});
test('unknown deployment identity fails closed before case reads or mutations', async () => {
  for (const env of [undefined, 'production', '']) {
    if (env === undefined) delete process.env.KERENNNN_DEPLOY_ENV;
    else process.env.KERENNNN_DEPLOY_ENV = env;
    for (const method of ['GET', 'POST', 'PATCH', 'DELETE']) {
      const res = await run(list, method);
      assert.equal(res.code, 503);
      assert.equal(calls.length, 0);
    }
    const res = await run(detail, 'GET');
    assert.equal(res.code, 503);
    assert.equal(calls.length, 0);
  }
});
test('IR UI selects detail flow by server identity; prod compose pins identity', () => {
  const ui = fs.readFileSync(require.resolve('../src/pages/IrManagerTab.tsx'), 'utf8');
  assert.match(ui, /if \(deployEnv === 'dev'\) await loadWorkspace\(id\)/);
  assert.match(ui, /else if \(deployEnv === 'prod'\) \{\s*const res = await api\.irCases\.detail\(id\)/);
  assert.match(ui, /const canDelete = deployEnv === 'prod' && role !== 'l1'/);
  const compose = fs.readFileSync(require.resolve('../docker-compose.yml'), 'utf8');
  assert.match(compose, /- KERENNNN_DEPLOY_ENV=prod/);
});
test.after(() => {
  auth.requireCurrentRole = originalAuth;
  client.getSupabase = originalDb;
  if (originalEnv === undefined) delete process.env.KERENNNN_DEPLOY_ENV;
  else process.env.KERENNNN_DEPLOY_ENV = originalEnv;
  delete require.cache[require.resolve('./ir-cases')];
  delete require.cache[require.resolve('./ir-cases/detail')];
});
