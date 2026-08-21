const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('team-aware filter UI carries server-issued access and explicit context', () => {
  const auth = source('src/context/AuthContext.tsx');
  const settings = source('src/pages/SettingsTab.tsx');
  const api = source('src/lib/api.ts');
  const app = source('src/App.tsx');

  assert.match(auth, /allowedTeams:\s*Team\[\]/);
  assert.match(auth, /activeTeam:\s*Team \| null/);
  assert.match(auth, /setActiveTeam/);
  assert.match(settings, /Team context/);
  assert.match(settings, /const canChooseTeam = canSwitchTeam && \['admin', 'l2', 'soc_lead'\]\.includes\(role\)/);
  assert.match(settings, /canChooseTeam \? \(/);
  assert.match(settings, /className="settings-team-context"/);
  assert.match(settings, /Team context: \{activeTeam\}/);
  assert.doesNotMatch(settings, /disabled=\{!canSwitchTeam\}/);
  assert.match(api, /X-Team-Context/);
  assert.match(app, /<PacFilterTab[\s\S]*team=\{activeTeam\}/);
});

test('admin has end-to-end Team Filter access', () => {
  const permissions = source('src/lib/permissions.ts');
  const tenancy = source('api/_tenancy.js');
  const endpoint = source('api/team-filter.js');
  const migration = source('supabase/team_filter.sql');
  assert.match(permissions, /TEAM_FILTER_ROLES: Role\[\] = \['admin', 'soc_lead', 'pac', 'charlie', 'l2'\]/);
  assert.match(tenancy, /admin:\s*\{ assignedTeam: null, allowedTeams: \['PAC', 'CHARLIE'\], canSwitchTeam: true \}/);
  assert.match(endpoint, /\['admin', 'pac', 'charlie', 'soc_lead', 'l2'\]/);
  assert.match(migration, /actor_role in \('admin', 'soc_lead', 'l2'\)/);
});

test('L1 navigation defaults to focused investigation workflow', () => {
  const permissions = source('src/lib/permissions.ts');
  const prefs = source('src/hooks/useTabPrefs.ts');
  assert.match(permissions, /const ANALYST_ROLES/);
  assert.doesNotMatch(permissions, /'formatter':\s+null/);
  assert.match(prefs, /L1_NAV_LAYOUT/);
  assert.match(source('src/App.tsx'), /role !== 'l1' && !tabPrefs\.tutorialDismissed/);
});

test('team migration skips malformed legacy IP text before inet cast', () => {
  const migration = source('supabase/team_filter.sql');
  assert.match(migration, /begin;/);
  assert.match(migration, /commit;/);
  assert.doesNotMatch(migration, /pg_input_is_valid/);
  assert.match(migration, /valid_legacy_ips as materialized/);
  assert.match(migration, /ip ~ '\^/);
  assert.match(migration, /select 'PAC', ip::inet/);
});

test('team mutations are transactional and legacy PAC remains bridged during cutover', () => {
  const migration = source('supabase/team_filter.sql');
  const endpoint = source('api/team-filter.js');
  assert.match(migration, /create or replace function public\.mutate_team_filter/);
  assert.match(migration, /insert into public\.team_filter_audit/);
  assert.match(migration, /sync_legacy_pac_filter/);
  assert.match(endpoint, /\.rpc\('mutate_team_filter'/);
  assert.doesNotMatch(endpoint, /\.from\('team_filter_ips'\)\.upsert/);
});

test('large team filter preview stays compact while copy retains full query', () => {
  const outputBox = source('src/components/shared/OutputBox.tsx');
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(outputBox, /displayValue\?: string/);
  assert.match(outputBox, /text=\{value\}/);
  assert.match(outputBox, /value=\{displayValue \?\? value\}/);
  assert.match(filter, /displayValue=\{siemQueryPreview\}/);
  assert.match(filter, /copyLabel="COPY ALL"/);
});

test('Team Filter status dismissal clears both success and error state', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(hook, /clearStatus/);
  assert.match(filter, /onDismiss=\{clearStatus\}/);
});

test('SOC Lead can select every server-issued team context', () => {
  const settings = source('src/pages/SettingsTab.tsx');
  assert.match(settings, /const canChooseTeam = canSwitchTeam && \['admin', 'l2', 'soc_lead'\]\.includes\(role\)/);
});

test('Team Filter session cache is isolated by authenticated identity', () => {
  const app = source('src/App.tsx');
  const hook = source('src/hooks/useMergerDb.ts');
  assert.match(app, /identity=\{workspaceIdentity!\}/);
  assert.match(hook, /export function useMergerDb\(team: Team, identity: string\)/);
  assert.match(hook, /const cacheKey = `\$\{identity\}:\$\{team\}`/);
});

test('Team Filter refresh is a prominent header icon action', () => {
  const filter = source('src/pages/PacFilterTab.tsx');
  const css = source('src/styles/ui-improvements.css');
  assert.match(filter, /className="pac-refresh-btn"/);
  assert.match(filter, /aria-label="Refresh Team Filter data"/);
  assert.match(filter, /className=\{`pac-refresh-icon\$\{loading \? ' is-loading' : ''\}`\}/);
  assert.doesNotMatch(filter, /↻ Refresh/);
  assert.match(css, /\.pac-refresh-btn\s*\{[^}]*width:\s*36px;[^}]*height:\s*36px;/s);
  assert.match(css, /\.pac-refresh-icon\.is-loading\s*\{[^}]*animation:\s*loading-spinner-spin/s);
});
