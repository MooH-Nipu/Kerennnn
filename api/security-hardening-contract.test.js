const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('security migration makes audit rows immutable and privileged mutations transactional', () => {
  const sql = source('supabase/security_hardening.sql');
  assert.match(sql, /create or replace function public\.reject_audit_mutation/);
  assert.match(sql, /before update or delete on public\.team_filter_audit/);
  assert.match(sql, /before update or delete on public\.audit_log/);
  assert.match(sql, /revoke update, delete on public\.team_filter_audit from service_role/);
  assert.match(sql, /drop constraint if exists team_filter_audit_actor_id_fkey/);
  assert.doesNotMatch(sql, /foreign key \(actor_id\)/);
  assert.match(sql, /create or replace function public\.record_team_filter_event/);
  assert.match(sql, /select role, username into actor_role, actor_username\s+from public\.app_users/);
  assert.match(sql, /create or replace function public\.mutate_app_user/);
  assert.match(sql, /insert into public\.audit_log/);
  assert.match(sql, /grant execute on function public\.mutate_app_user/);
});

test('admin user mutations use one audited database transaction', () => {
  const users = source('api/admin/users.js');
  assert.match(users, /supabase\.rpc\('mutate_app_user'/);
  assert.doesNotMatch(users, /\.from\('app_users'\)\s*\.insert/);
  assert.doesNotMatch(users, /\.from\('app_users'\)\s*\.update/);
  assert.doesNotMatch(users, /\.from\('app_users'\)\.delete/);
  assert.doesNotMatch(users, /writeAudit/);
});

test('Team Filter records denied and failed events outside mutation rollback', () => {
  const filter = source('api/team-filter.js');
  assert.match(filter, /recordTeamFilterEvent/);
  assert.match(filter, /status: 'denied'/);
  assert.match(filter, /status: 'error'/);
  assert.match(filter, /supabase\.rpc\('record_team_filter_event'/);
});

test('README documents ordered migrations, verification, backup, and rollback', () => {
  const readme = source('README.md');
  const appUsers = readme.indexOf('supabase/app_users.sql');
  const auditLog = readme.indexOf('supabase/audit_log.sql');
  const teamFilter = readme.indexOf('supabase/team_filter.sql');
  const hardening = readme.indexOf('supabase/security_hardening.sql');
  assert.ok(appUsers >= 0 && appUsers < auditLog && auditLog < teamFilter && teamFilter < hardening);
  assert.match(readme, /Backup before migration/);
  assert.match(readme, /Rollback/);
  assert.match(readme, /team_filter_audit_immutable/);
});
