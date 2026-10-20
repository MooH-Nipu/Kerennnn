'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const auth = require('./_auth');
const supabase = require('./_supabase');
const originalAuth = auth.requireCurrentRole;
const originalDb = supabase.getSupabase;
const originalEnv = process.env.KERENNNN_DEPLOY_ENV;
process.env.KERENNNN_DEPLOY_ENV = 'dev';
auth.requireCurrentRole = async req => { req.auth = { userId: '00000000-0000-4000-8000-000000000001', username: 'alice', role: role }; return true; };
const ID = '00000000-0000-4000-8000-000000000002';
let owner = 'bob';
let marked = true;
let role = 'l1';
let calls = [];
function query(table) {
  calls.push({ table });
  const q = { select: () => q, eq: () => q, order: () => q, range: () => Promise.resolve({ data: [] }), maybeSingle: () => Promise.resolve({ data: table === 'ir_case_dev_scope' ? (marked ? { case_id: ID } : null) : { id: ID, title: 'private', description: 'secret', status: 'open', created_by: owner } }), insert: value => { calls.push({ table, value }); return { select: () => ({ single: () => Promise.resolve({ data: value }) }) }; } };
  return q;
}
supabase.getSupabase = () => ({ from: table => query(table), rpc: (name, args) => { calls.push({ name, args }); return Promise.resolve({}); } });
const handler = require('./ir-cases/workspace');
function response() { return { setHeader() {}, status(code) { this.code = code; return this; }, json(data) { this.data = data; return this; } }; }
test('cross-owner denied before private reads and writes', async () => {
  marked = true; owner = 'bob'; role = 'l1'; calls = [];
  const res = response();
  await handler({ method: 'POST', body: { id: ID, kind: 'note', body: 'x' } }, res);
  assert.equal(res.code, 404);
  assert.deepEqual(calls.map(c => c.table), ['ir_case_dev_scope', 'ir_cases']);
  assert.equal(res.data.case, undefined);
});
test('unmarked case denied to admin for GET, POST and PATCH without case read or mutation', async () => {
  marked = false; role = 'admin'; calls = [];
  for (const [method, payload] of [['GET', { query: { id: ID } }], ['POST', { body: { id: ID, kind: 'note', body: 'x' } }], ['PATCH', { body: { id: ID, status: 'closed' } }]]) {
    const res = response();
    await handler({ method, ...payload }, res);
    assert.equal(res.code, 404);
    assert.deepEqual(res.data, { error: 'Case not found.' });
  }
  assert.deepEqual(calls.map(c => c.table), ['ir_case_dev_scope', 'ir_case_dev_scope', 'ir_case_dev_scope']);
});
test('normalization and bounded page validation', () => {
  assert.equal(handler.normalizeIoc('ip', '999.1.2.3'), null);
  assert.equal(handler.normalizeIoc('domain', 'Example.COM'), 'example.com');
  assert.equal(handler.normalizeIoc('hash', 'a'.repeat(64)), 'a'.repeat(64));
  assert.equal(handler.normalizeIoc('url', 'javascript:alert(1)'), null);
  assert.equal(handler.normalizeIoc('url', 'https://x.test/' + 'a'.repeat(2040)), null);
  assert.equal(handler.pagination({ limit: '51' }), null);
  assert.equal(handler.pagination({ offset: '-1' }), null);
  assert.equal(handler.canAccess({ role: 'l1', username: 'alice' }, { created_by: 'bob' }), false);
});
test('owner note attribution and status actor cannot be supplied by client', async () => {
  marked = true; owner = 'alice'; role = 'l1'; calls = [];
  const note = response();
  await handler({ method: 'POST', body: { id: ID, kind: 'note', body: 'evidence', author_id: 'fake' } }, note);
  assert.equal(note.code, 400);
  await handler({ method: 'POST', body: { id: ID, kind: 'note', body: 'evidence' } }, note);
  assert.equal(note.code, 201);
  assert.equal(calls.find(c => c.value)?.value.author_id, '00000000-0000-4000-8000-000000000001');
  const status = response();
  await handler({ method: 'PATCH', body: { id: ID, status: 'closed', actor_id: 'fake' } }, status);
  assert.equal(status.code, 400);
  await handler({ method: 'PATCH', body: { id: ID, status: 'closed' } }, status);
  assert.equal(status.code, 200);
  const rpc = calls.find(c => c.name);
  assert.equal(rpc.name, 'ir_workspace_set_dev_status');
  assert.equal(rpc.args.p_actor_id, '00000000-0000-4000-8000-000000000001');
});
test.after(() => {
  auth.requireCurrentRole = originalAuth;
  supabase.getSupabase = originalDb;
  if (originalEnv === undefined) delete process.env.KERENNNN_DEPLOY_ENV;
  else process.env.KERENNNN_DEPLOY_ENV = originalEnv;
});
