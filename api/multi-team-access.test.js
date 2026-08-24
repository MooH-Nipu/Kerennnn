'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('admin team membership input is normalized and rejects unknown teams', () => {
  const { sanitizeTeamAccess } = require('./admin/users');
  assert.deepEqual(sanitizeTeamAccess(['charlie', 'PAC', 'pac']), ['PAC', 'CHARLIE']);
  assert.deepEqual(sanitizeTeamAccess([]), []);
  assert.equal(sanitizeTeamAccess(undefined, true), null);
  assert.throws(() => sanitizeTeamAccess('PAC'), /array/i);
  assert.throws(() => sanitizeTeamAccess(['PAC', 'BLUE']), /PAC or CHARLIE/);
  const users = source('api/admin/users.js');
  assert.doesNotMatch(users, /const VALID_ROLES/);
  assert.equal((users.match(/!ASSIGNABLE_ROLES\.includes\(role\)/g) || []).length, 2);
});

test('multi-team migration is additive and updates every DB authorization boundary', () => {
  const migration = source('supabase/multi_team_access.sql');
  assert.match(migration, /add column if not exists team_access text\[\]/);
  assert.match(migration, /role = 'pac'[\s\S]*array\['PAC'\]/);
  assert.match(migration, /role = 'charlie'[\s\S]*array\['CHARLIE'\]/);
  assert.match(migration, /role in \('admin', 'soc_lead', 'l2'\)[\s\S]*array\['PAC', 'CHARLIE'\]/);
  assert.match(migration, /create or replace function public\.mutate_app_user_v2/);
  assert.match(migration, /p_team_access text\[\]/);
  assert.match(migration, /p_team = any\(actor_team_access\)/);
  assert.match(migration, /'CHARLIE' = any\(actor_team_access\)/);
  assert.doesNotMatch(migration, /actor_role = 'pac'|actor_role = 'charlie'|actor_role in \('admin', 'soc_lead', 'l2'\) or/);
  assert.equal((migration.match(/if actor_role is null then raise exception 'current account not found'/g) || []).length, 2);
  assert.match(migration, /revoke all on function public\.mutate_app_user_v2/);
  assert.match(migration, /grant execute on function public\.mutate_app_user_v2[^;]+to service_role/);
});

test('live identity and auth responses carry database team memberships', () => {
  const auth = source('api/_auth.js');
  const login = source('api/auth/login.js');
  const me = source('api/auth/me.js');
  assert.equal((auth.match(/\.select\('id,username,role,team_access'\)/g) || []).length, 2);
  assert.match(login, /password_hash, role, team_access/);
  assert.match(login, /teamAccess: user\.team_access/);
  assert.match(login, /getRoleContext\(user\.role, user\.team_access\)/);
  assert.match(me, /teamAccess: req\.auth\.teamAccess/);
  assert.match(me, /getRoleContext\(req\.auth\.role, req\.auth\.teamAccess\)/);
  const adminUi = source('src/pages/AdminUsersTab.tsx');
  assert.match(adminUi, /const ASSIGNABLE_ROLES: Role\[\] = \['admin', 'soc_lead', 'l1', 'l2'\]/);
  assert.match(adminUi, /function TeamAccessSelect/);
  assert.match(adminUi, /<details ref=\{rootRef\} className="team-access-select"/);
  assert.match(adminUi, /aria-pressed=\{selected\}/);
  assert.match(adminUi, /type="button"/);
  assert.doesNotMatch(adminUi, /type="checkbox"/);
  assert.match(adminUi, /const \{ user: savedUser \} = await api\.admin\.updateUser/);
  assert.match(adminUi, /u\.id === user\.id \? savedUser : u/);
});

test('utility tabs are global while Team Filter follows membership', () => {
  const permissions = source('src/lib/permissions.ts');
  const prefs = source('src/hooks/useTabPrefs.ts');
  for (const tab of ['formatter', 'json', 'merger', 'daily-eod', 'cve', 'attack']) {
    assert.match(permissions, new RegExp(`'${tab}':\\s+null`));
  }
  assert.match(permissions, /if \(tab === 'pac-filter'\) return allowedTeams\.length > 0/);
  assert.match(prefs, /L1_NAV_LAYOUT[\s\S]*'daily-eod'[\s\S]*'formatter', 'merger', 'json', 'cve', 'attack'/);
  const eod = source('api/kibana-combined-report.js');
  assert.match(eod, /if \(!requireAuth\(req, res\)\) return/);
  assert.doesNotMatch(eod, /authEnabled\(\) &&/);
});

test('Charlie client listing and Team Filter authorize current memberships, not scalar role alone', () => {
  const clients = source('api/charlie-clients.js');
  const filter = source('api/team-filter.js');
  assert.match(clients, /getRoleContext\(req\.auth\.role, req\.auth\.teamAccess\)/);
  assert.match(clients, /allowedTeams\.includes\('CHARLIE'\)/);
  assert.match(filter, /requireCurrentRole\(req, res, supabase, VALID_ROLES\)/);
});
