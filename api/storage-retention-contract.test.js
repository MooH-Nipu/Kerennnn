const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

function loadHistoryParser() {
  const hook = source('src/hooks/useScanHistory.ts');
  const match = hook.match(/export function parseLocalHistory[\s\S]*?\n}/);
  assert.ok(match, 'parseLocalHistory export missing');
  const js = ts.transpileModule(match[0], {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  vm.runInNewContext(js, { module, exports: module.exports, MAX: 20 });
  return module.exports.parseLocalHistory;
}

test('scan history keeps the latest 20 rows per user', () => {
  const handler = source('api/scan-history.js');
  const api = source('src/lib/api.ts');
  const hook = source('src/hooks/useScanHistory.ts');
  assert.match(handler, /const MAX_ROWS = 20;/);
  assert.match(handler, /const MAX_LIMIT = MAX_ROWS;/);
  assert.equal((handler.match(/\.order\('created_at', \{ ascending: false \}\)\n\s*\.order\('id', \{ ascending: false \}\)/g) ?? []).length, 2);
  assert.match(api, /history:\s*\{[\s\S]*list:\s*\(limit = 20\)/);
  assert.match(hook, /const MAX = 20;/);
});

test('legacy local history is capped on read and malformed payloads are rejected', () => {
  const parseLocalHistory = loadHistoryParser();
  const rows = Array.from({ length: 50 }, (_, id) => ({ id }));
  assert.equal(parseLocalHistory(JSON.stringify(rows)).length, 20);
  assert.deepEqual(Array.from(parseLocalHistory('{bad json')), []);
  assert.deepEqual(Array.from(parseLocalHistory(JSON.stringify({ not: 'an array' }))), []);
});

test('database retention is daily, idempotent, and preserves audit tables', () => {
  const sql = source('supabase/storage_retention.sql');
  assert.match(sql, /create extension if not exists pg_cron/);
  assert.match(sql, /create or replace function public\.prune_storage_retention\(\)/);
  assert.match(sql, /row_number\(\) over \(partition by user_id order by created_at desc, id desc\)/);
  assert.match(sql, /delete from public\.scan_history[\s\S]*where rn > 20/);
  assert.match(sql, /delete from public\.api_usage[\s\S]*created_at < now\(\) - interval '90 days'/);
  assert.match(sql, /delete from public\.login_attempts[\s\S]*attempted_at < now\(\) - interval '7 days'/);
  assert.match(sql, /cron\.schedule\([\s\S]*kerennnn-storage-retention[\s\S]*0 3 \* \* \*/);
  assert.match(sql, /for existing_job in[\s\S]*where jobname = 'kerennnn-storage-retention'[\s\S]*cron\.unschedule\(existing_job\.jobid\)/);
  assert.doesNotMatch(sql, /delete from public\.(audit_log|team_filter_audit|charlie_client_filter_audit)/);
});
