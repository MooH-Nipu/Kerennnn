const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('legacy PAC API uses canonical team_filter_ips storage', () => {
  const endpoint = source('api/scan-merger.js');
  assert.match(endpoint, /\.from\('team_filter_ips'\)/);
  assert.match(endpoint, /\.eq\('team', 'PAC'\)/);
  assert.doesNotMatch(endpoint, /\.from\('merger_scanned_ips'\)/);
});

test('team mutation no longer mirrors PAC rows into legacy storage', () => {
  const migration = source('supabase/team_filter.sql');
  assert.doesNotMatch(migration, /sync_legacy_pac_filter/);
  assert.doesNotMatch(migration, /merger_scanned_ips_team_bridge/);
  assert.doesNotMatch(migration, /insert into public\.merger_scanned_ips/);
  assert.doesNotMatch(migration, /delete from public\.merger_scanned_ips/);
});

test('storage migration removes only archived redundant tables and indexes', () => {
  const migration = source('supabase/team_filter_storage_optimization.sql');
  assert.match(migration, /drop table if exists public\.merger_scanned_ips_backup_juli/);
  assert.match(migration, /drop table if exists public\.merger_scanned_ips_backup_aug/);
  assert.match(migration, /drop table if exists public\.merger_scanned_ips/);
  assert.match(migration, /drop index if exists public\.ip_scan_events_user_created_idx/);
  assert.match(migration, /drop index if exists public\.team_filter_ips_team_updated_idx/);
  assert.doesNotMatch(migration, /drop table public\.team_filter_ips/);
  assert.doesNotMatch(migration, /drop index public\.api_usage_service_idx/);
});
