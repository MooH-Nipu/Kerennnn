const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('frontend routing uses native same-origin paths without vulnerable router dependency', () => {
  const packageJson = JSON.parse(source('package.json'));
  const app = source('src/App.tsx');
  const result = source('src/pages/ResultPage.tsx');
  assert.equal(packageJson.devDependencies['react-router-dom'], undefined);
  assert.doesNotMatch(app, /react-router-dom/);
  assert.doesNotMatch(result, /react-router-dom/);
  assert.match(app, /window\.location\.pathname/);
  assert.match(app, /safeDecodePathSegment/);
});

test('unused PDF libraries are absent from dependency graph', () => {
  const packageJson = JSON.parse(source('package.json'));
  assert.equal(packageJson.devDependencies.jspdf, undefined);
  assert.equal(packageJson.devDependencies['jspdf-autotable'], undefined);
});

test('production container runs non-root with constrained privileges', () => {
  const dockerfile = source('Dockerfile');
  const compose = source('docker-compose.yml');
  assert.match(dockerfile, /USER node/);
  assert.match(compose, /read_only: true/);
  assert.match(compose, /no-new-privileges:true/);
  assert.match(compose, /cap_drop:\s*\n\s*- ALL/);
  assert.match(compose, /pids_limit: 256/);
  assert.match(compose, /COOKIE_SECURE=\$\{COOKIE_SECURE:-true\}/);
});

test('shared route registry exposes Team Filter to Express', () => {
  const routes = source('api/_routes.js');
  const server = source('server.js');
  assert.match(routes, /'\/api\/v1\/team-filter',\s*require\('\.\/team-filter\.js'\)/);
  assert.doesNotMatch(routes, /require\(entry\[1\]\)/);
  assert.match(server, /require\('\.\/api\/_routes'\)/);
});

test('legacy PAC endpoint uses canonical team storage without a synchronization bridge', () => {
  const endpoint = source('api/scan-merger.js');
  const migration = source('supabase/team_filter.sql');
  assert.match(endpoint, /\.from\('team_filter_ips'\)/);
  assert.match(endpoint, /\.eq\('team', 'PAC'\)/);
  assert.doesNotMatch(migration, /sync_legacy_pac_filter/);
});
