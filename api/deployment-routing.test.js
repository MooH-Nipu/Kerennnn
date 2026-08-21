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

test('Vercel routes every API path through current-account revalidation', () => {
  const vercel = JSON.parse(source('vercel.json'));
  assert.equal(vercel.rewrites, undefined);
  const apiRouteIndex = vercel.routes.findIndex(row => row.src === '/api/(.*)');
  const filesystemIndex = vercel.routes.findIndex(row => row.handle === 'filesystem');
  assert.ok(apiRouteIndex >= 0 && apiRouteIndex < filesystemIndex);
  assert.equal(vercel.routes[apiRouteIndex].dest, '/api/index?path=$1');

  const router = source('api/index.js');
  assert.match(router, /revalidateRequestIdentity/);
  assert.match(router, /getApiRoute/);
  assert.match(router, /ERR_ROUTE_NOT_FOUND/);
});

test('shared route registry exposes Team Filter to Express and Vercel', () => {
  const routes = source('api/_routes.js');
  const server = source('server.js');
  assert.match(routes, /'\/api\/v1\/team-filter',\s*require\('\.\/team-filter\.js'\)/);
  assert.doesNotMatch(routes, /require\(entry\[1\]\)/);
  assert.match(server, /require\('\.\/api\/_routes'\)/);
});

test('Vercel router dispatches public health and rejects unknown routes', async () => {
  const router = require('./index');
  const invoke = async pathValue => {
    const out = { statusCode: 200, body: null };
    const res = {
      status(code) { out.statusCode = code; return this; },
      json(body) { out.body = body; return this; },
      setHeader() {},
      end() { return this; },
    };
    await router({ method: 'GET', query: { path: pathValue }, headers: {}, socket: {} }, res);
    return out;
  };
  assert.deepEqual(await invoke('health'), { statusCode: 200, body: { ok: true } });
  assert.deepEqual(await invoke('nope'), { statusCode: 404, body: { error_code: 'ERR_ROUTE_NOT_FOUND', message: 'API route not found.' } });
});

test('legacy PAC update bridge removes OLD IP before inserting NEW IP', () => {
  const migration = source('supabase/team_filter.sql');
  assert.match(migration, /if tg_op = 'UPDATE' and old\.ip is distinct from new\.ip then/);
  assert.match(migration, /delete from public\.team_filter_ips where team = 'PAC' and ip = old\.ip::inet/);
});
