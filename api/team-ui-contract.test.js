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
  assert.match(settings, /const canChooseTeam = canSwitchTeam/);
  assert.match(settings, /canChooseTeam \? \(/);
  assert.match(settings, /className="settings-team-context"/);
  assert.match(settings, /Team context: \{activeTeam\}/);
  assert.doesNotMatch(settings, /disabled=\{!canSwitchTeam\}/);
  assert.match(api, /X-Team-Context/);
  assert.match(app, /<PacFilterTab[\s\S]*team=\{activeTeam\}/);
});

test('Team Filter access requires explicit membership independently from authority role', () => {
  const permissions = source('src/lib/permissions.ts');
  const tenancy = source('api/_tenancy.js');
  const endpoint = source('api/team-filter.js');
  const migration = source('supabase/multi_team_access.sql');
  assert.match(permissions, /if \(tab === 'pac-filter'\) return allowedTeams\.length > 0/);
  assert.match(tenancy, /allowedTeams = \['PAC', 'CHARLIE'\]\.filter\(team => explicit\.includes\(team\)\)/);
  assert.doesNotMatch(tenancy, /const TEAM_CONTEXT|legacy\?\.allowedTeams/);
  assert.match(endpoint, /requireCurrentRole\(req, res, supabase, VALID_ROLES\)/);
  assert.match(migration, /p_team = any\(actor_team_access\)/);
  assert.doesNotMatch(migration, /actor_role in \('admin', 'soc_lead', 'l2'\) or/);
});

test('L1 navigation includes global utilities without admin tools', () => {
  const permissions = source('src/lib/permissions.ts');
  const prefs = source('src/hooks/useTabPrefs.ts');
  assert.match(permissions, /const ANALYST_ROLES/);
  assert.match(permissions, /'formatter':\s+null/);
  assert.match(permissions, /'daily-eod':\s+null/);
  const l1Layout = prefs.match(/L1_NAV_LAYOUT[\s\S]*?\n\];/)?.[0] || '';
  assert.match(l1Layout, /'formatter', 'merger', 'json', 'cve', 'attack'/);
  assert.doesNotMatch(l1Layout, /dashboard|admin-users|admin-logs/);
  assert.match(source('src/App.tsx'), /role !== 'l1' && !tabPrefs\.tutorialDismissed/);
});

test('team filter schema uses one canonical storage table', () => {
  const migration = source('supabase/team_filter.sql');
  assert.match(migration, /begin;/);
  assert.match(migration, /commit;/);
  assert.match(migration, /create table if not exists public\.team_filter_ips/);
  assert.doesNotMatch(migration, /merger_scanned_ips/);
});

test('team mutations remain transactional without legacy PAC mirroring', () => {
  const migration = source('supabase/team_filter.sql');
  const endpoint = source('api/team-filter.js');
  assert.match(migration, /create or replace function public\.mutate_team_filter/);
  assert.match(migration, /insert into public\.team_filter_audit/);
  assert.doesNotMatch(migration, /sync_legacy_pac_filter/);
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
  assert.match(settings, /const canChooseTeam = canSwitchTeam/);
});

test('Team Filter session cache is isolated by authenticated identity', () => {
  const app = source('src/App.tsx');
  const hook = source('src/hooks/useMergerDb.ts');
  assert.match(app, /identity=\{workspaceIdentity!\}/);
  assert.match(hook, /export function useMergerDb\(team: Team, identity: string, clientCode\?: string\)/);
  assert.match(hook, /const cacheKey = `\$\{identity\}:\$\{team\}:\$\{clientCode \?\? 'LEGACY'\}`/);
});

test('Team Filter ignores stale responses after rapid client switching', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  assert.match(hook, /const activeCacheKey = useRef\(cacheKey\)/);
  assert.match(hook, /activeCacheKey\.current = cacheKey/);
  assert.match(hook, /if \(activeCacheKey\.current === requestCacheKey\) \{[\s\S]*setItems\(loaded\)/);
  assert.match(hook, /if \(activeCacheKey\.current === requestCacheKey\) setError/);
});

test('deleted client cache rejects late responses and concurrent filter actions', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(hook, /const sessionGeneration: Record<string, number> = \{\}/);
  assert.match(hook, /sessionGeneration\[cacheKey\] = \(sessionGeneration\[cacheKey\] \?\? 0\) \+ 1/);
  assert.match(hook, /const requestGeneration = sessionGeneration\[cacheKey\] \?\? 0/);
  assert.match(hook, /if \(\(sessionGeneration\[cacheKey\] \?\? 0\) !== requestGeneration\) return null/);
  assert.match(hook, /const hasActiveOperation = useCallback\(\(\) => activeOperations\.current > 0, \[\]\)/);
  assert.match(filter, /if \(deleteClientInFlight\.current\) return/);
  assert.match(filter, /if \(deleteClientInFlight\.current \|\| !toDelete\.length\) return/);
  assert.match(filter, /if \(hasActiveOperation\(\)\) return/);
  assert.match(filter, /onClick=\{handleRefresh\}/);
});

test('Charlie client creation is locked during active filter work', () => {
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(filter, /const createInFlight = useRef\(false\)/);
  assert.match(filter, /if \(createInFlight\.current\) return/);
  assert.match(filter, /createInFlight\.current = true/);
  assert.match(filter, /createInFlight\.current = false/);
  assert.match(filter, /disabled=\{[^}]*loading[^}]*posting[^}]*clientLoading[^}]*clientCreating[^}]*\}/);
});

test('Team Filter submit reports success only after DB reload succeeds', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  assert.match(hook, /const loaded = await refresh\(\)/);
  assert.match(hook, /if \(loaded\) \{/);
  assert.match(hook, /return done === toPost\.length && loaded !== null/);
  assert.doesNotMatch(hook, /sessionItems\[cacheKey\]\.length/);
});

test('Team Filter delete clears input only after DB-confirmed delete and reload', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(hook, /const deleteInFlight = useRef\(false\)/);
  assert.match(hook, /if \(deleteInFlight\.current\) return false/);
  assert.match(hook, /const deleteIps = useCallback\(async \(ips: string\[\]\): Promise<boolean>/);
  assert.match(hook, /return deleted === ips\.length/);
  assert.match(hook, /catch \(err\) \{[\s\S]*if \(deleted > 0\) await refresh\(\);[\s\S]*return false/);
  assert.match(filter, /const deleted = await deleteIps\(toDelete\);[\s\S]*if \(deleted\) setDeleteInput\(''\)/);
  assert.doesNotMatch(filter, /await deleteIps\(toDelete\);\s*setDeleteInput\(''\)/);
});

test('Team Filter submit is synchronously locked against rapid repeat clicks', () => {
  const hook = source('src/hooks/useMergerDb.ts');
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(hook, /const submitInFlight = useRef\(false\)/);
  assert.match(hook, /if \(submitInFlight\.current\) return false/);
  assert.match(hook, /submitInFlight\.current = true;[\s\S]*setPosting\(true\)/);
  assert.match(hook, /finally \{[\s\S]*submitInFlight\.current = false/);
  assert.match(filter, /const submitted = await submitIps\(input\);[\s\S]*if \(submitted\) setInput\(''\)/);
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
