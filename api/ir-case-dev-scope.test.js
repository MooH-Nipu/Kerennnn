'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const auth = require('./_auth');
const client = require('./_supabase');
const originalAuth = auth.requireCurrentRole;
const originalDb = client.getSupabase;
const originalEnv = process.env.KERENNNN_DEPLOY_ENV;
const ID = '00000000-0000-4000-8000-000000000002';
const USER = '00000000-0000-4000-8000-000000000001';
let marked = false;
let operations = [];
process.env.KERENNNN_DEPLOY_ENV = 'dev';
auth.requireCurrentRole = async req => { req.auth = { role: 'admin', username: 'alice', userId: USER }; return true; };
function query(table) {
  const opts = { table, select: '', filters: [], action: 'read' };
  operations.push(opts);
  const q = {
    select(s) { opts.select = s; return q; },
    eq(field, value) { opts.filters.push([field, value]); return q; },
    or() { return q; }, order() { return q; }, range() { return q; },
    update() { opts.action = 'update'; return q; },
    insert() { opts.action = 'insert'; return q; },
    maybeSingle() { return Promise.resolve({ data: marked || !opts.select.includes('!inner') ? { id: ID, title: 'synthetic', created_by: 'alice' } : null }); },
    then(resolve) { return Promise.resolve({ data: marked || !opts.select.includes('!inner') ? [{ id: ID, title: 'synthetic', created_by: 'alice' }] : [], count: marked ? 1 : 0 }).then(resolve); },
  };
  return q;
}
client.getSupabase = () => ({ from: query, rpc: (name, args) => { operations.push({ name, args }); return Promise.resolve({ data: name === 'ir_create_dev_cases' ? [{ id: ID }] : marked ? { id: ID } : null }); } });
const list = require('./ir-cases');
const detail = require('./ir-cases/detail');
function response() { return { setHeader() {}, status(n) { this.code = n; return this; }, json(v) { this.data = v; return this; } }; }
test('admin dev list inner-joins marker; zero unmarked cases', async () => {
  marked = false; operations = [];
  const res = response();
  await list({ method: 'GET', query: {} }, res);
  assert.equal(res.code, 200);
  assert.deepEqual(res.data, { ok: true, deployEnv: 'dev', cases: [], total: 0 });
  assert.match(operations[0].select, /ir_case_dev_scope!inner/);
});
test('admin dev detail returns same 404 for unmarked and absent case', async () => {
  marked = false; operations = [];
  const res = response();
  await detail({ method: 'GET', query: { id: ID } }, res);
  assert.equal(res.code, 404);
  assert.deepEqual(res.data, { error: 'Case not found.' });
  assert.match(operations[0].select, /ir_case_dev_scope!inner/);
});
test('admin dev PATCH calls guarded RPC; unmarked case not updated', async () => {
  marked = false; operations = [];
  const res = response();
  await list({ method: 'PATCH', body: { id: ID, title: 'new' } }, res);
  assert.equal(res.code, 404);
  assert.equal(operations.length, 1);
  assert.equal(operations[0].name, 'ir_update_dev_case');
  assert.equal(operations[0].args.p_case_id, ID);
});
test('dev POST uses transactional creation RPC, never direct insert', async () => {
  operations = [];
  const res = response();
  await list({ method: 'POST', body: { title: 'synthetic' } }, res);
  assert.equal(res.code, 201);
  assert.deepEqual(operations.map(o => o.name), ['ir_create_dev_cases']);
  assert.equal(operations[0].args.p_creator_id, USER);
});
test.after(() => {
  auth.requireCurrentRole = originalAuth;
  client.getSupabase = originalDb;
  if (originalEnv === undefined) delete process.env.KERENNNN_DEPLOY_ENV;
  else process.env.KERENNNN_DEPLOY_ENV = originalEnv;
  delete require.cache[require.resolve('./ir-cases')];
  delete require.cache[require.resolve('./ir-cases/detail')];
});
