const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');
const {
  normalizeClientCode,
  resolveCharlieClient,
  fetchAllCharlieClientFilterRows,
} = require('./team-filter');

describe('Charlie client boundary', () => {
  test('normalizes valid client codes and rejects malformed values', () => {
    assert.equal(normalizeClientCode(' client-01 '), 'CLIENT-01');
    assert.equal(normalizeClientCode('ACME_ID'), 'ACME_ID');
    assert.throws(() => normalizeClientCode(''), /2-32/);
    assert.throws(() => normalizeClientCode('a'), /2-32/);
    assert.throws(() => normalizeClientCode('has space'), /2-32/);
    assert.throws(() => normalizeClientCode('x'.repeat(33)), /2-32/);
    assert.throws(() => normalizeClientCode(42), /client context/i);
  });

  test('resolves only active registry clients', async () => {
    const calls = [];
    const query = {
      select(columns) { calls.push(['select', columns]); return this; },
      eq(column, value) { calls.push(['eq', column, value]); return this; },
      maybeSingle() { return Promise.resolve({ data: { id: 7, code: 'ACME', label: 'Acme' }, error: null }); },
    };
    const supabase = { from(table) { calls.push(['from', table]); return query; } };

    const result = await resolveCharlieClient(supabase, 'ACME');

    assert.deepEqual(result.client, { id: 7, code: 'ACME', label: 'Acme' });
    assert.equal(result.error, null);
    assert.deepEqual(calls, [
      ['from', 'charlie_filter_clients'],
      ['select', 'id,code,label'],
      ['eq', 'code', 'ACME'],
      ['eq', 'active', true],
    ]);
  });

  test('pages rows inside one client only', async () => {
    const sourceRows = Array.from({ length: 1001 }, (_, i) => ({ ip: `10.0.${Math.floor(i / 256)}.${i % 256}` }));
    const calls = [];
    const supabase = {
      from(table) {
        calls.push(['from', table]);
        return {
          select() { return this; },
          eq(column, value) { calls.push(['eq', column, value]); return this; },
          order() { return this; },
          range(from, to) { calls.push(['range', from, to]); return Promise.resolve({ data: sourceRows.slice(from, to + 1), error: null }); },
        };
      },
    };

    const result = await fetchAllCharlieClientFilterRows(supabase, 7);

    assert.equal(result.error, null);
    assert.equal(result.items.length, 1001);
    assert.ok(calls.some(call => call[0] === 'from' && call[1] === 'charlie_client_filter_ips'));
    assert.ok(calls.every(call => call[0] !== 'eq' || (call[1] === 'client_id' && call[2] === 7)));
    assert.deepEqual(calls.filter(call => call[0] === 'range').at(-1), ['range', 1000, 1999]);
  });
});

describe('Charlie multi-client rollout contract', () => {
  test('migration is parallel and does not alter live production filter objects', () => {
    const migration = source('supabase/charlie_multi_client_filter.sql');
    assert.match(migration, /create table if not exists public\.charlie_filter_clients/);
    assert.match(migration, /create table if not exists public\.charlie_client_filter_ips/);
    assert.match(migration, /create or replace function public\.mutate_charlie_client_filter/);
    assert.match(migration, /insert into public\.charlie_filter_clients[\s\S]*'GENERAL'/);
    assert.match(migration, /'GENERAL', 'General \/ legacy list'/);
    assert.doesNotMatch(migration, /insert into public\.charlie_client_filter_ips[\s\S]*from public\.team_filter_ips/i);
    assert.doesNotMatch(migration, /alter table public\.team_filter_ips/i);
    assert.doesNotMatch(migration, /create or replace function public\.mutate_team_filter\s*\(/i);
    assert.doesNotMatch(migration, /drop (table|function)/i);
  });

  test('immutable Charlie audit keeps snapshots without cascading foreign keys', () => {
    const migration = source('supabase/charlie_multi_client_filter.sql');
    const auditTable = migration.match(/create table if not exists public\.charlie_client_filter_audit \([\s\S]*?\n\);/)?.[0] ?? '';
    assert.match(auditTable, /actor_id uuid/);
    assert.match(auditTable, /client_id bigint/);
    assert.doesNotMatch(auditTable, /references public\.app_users/);
    assert.doesNotMatch(auditTable, /references public\.charlie_filter_clients/);
    assert.match(migration, /drop constraint if exists charlie_client_filter_audit_actor_id_fkey/);
    assert.match(migration, /drop constraint if exists charlie_client_filter_audit_client_id_fkey/);
  });

  test('rollback removes only dedicated Charlie objects', () => {
    const rollback = source('supabase/charlie_multi_client_filter_rollback.sql');
    assert.match(rollback, /drop table if exists public\.charlie_client_filter_audit/);
    assert.match(rollback, /drop table if exists public\.charlie_client_filter_ips/);
    assert.match(rollback, /drop table if exists public\.charlie_filter_clients/);
    assert.doesNotMatch(rollback, /drop table if exists public\.team_filter_ips/i);
    assert.doesNotMatch(rollback, /drop function if exists public\.mutate_team_filter\s*\(/i);
  });

  test('legacy PAC and unscoped Team Filter requests keep old path', () => {
    const endpoint = source('api/team-filter.js');
    assert.match(endpoint, /if \(team === 'CHARLIE' && clientCode/);
    assert.match(endpoint, /\.rpc\('mutate_charlie_client_filter'/);
    assert.match(endpoint, /\.rpc\('mutate_team_filter'/);
    assert.match(endpoint, /X-Team-Context, X-Client-Context/);
  });

  test('same Team Filter UI exposes easy Charlie client switching', () => {
    const filter = source('src/pages/PacFilterTab.tsx');
    const hook = source('src/hooks/useMergerDb.ts');
    const api = source('src/lib/api.ts');
    assert.match(filter, /aria-label="Charlie client filter"/);
    assert.match(filter, /team === 'CHARLIE'/);
    assert.match(filter, /charlieClients/);
    assert.match(filter, /<span>Code<\/span>[\s\S]*aria-label="New Charlie client code"/);
    assert.match(filter, /<span>Name<\/span>[\s\S]*aria-label="New Charlie client label"/);
    assert.match(hook, /clientCode\?: string/);
    assert.match(hook, /const cacheKey = `\$\{identity\}:\$\{team\}:\$\{clientCode \?\? 'LEGACY'\}`/);
    assert.match(api, /X-Client-Context/);
    assert.match(api, /charlieClients:/);
  });
});
