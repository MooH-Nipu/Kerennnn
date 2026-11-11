const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { shouldRevalidateRoute, API_KEY_ROUTES } = require('./_auth');

const source = file => fs.readFileSync(path.join(__dirname, '..', file), 'utf8');

test('api-key routes skip cookie revalidation, session routes do not', () => {
  for (const route of API_KEY_ROUTES) assert.equal(shouldRevalidateRoute(route), false, route);
  assert.equal(shouldRevalidateRoute('/api/vt'), true);
  assert.equal(shouldRevalidateRoute('/api/api-keys'), true, 'key management still needs a session');
  assert.equal(shouldRevalidateRoute('/api/health'), false);
});

test('the exemption list matches the registered key-authenticated routes', () => {
  const routes = source('api/_routes.js');
  for (const route of API_KEY_ROUTES) {
    assert.ok(routes.includes(`'${route}'`), `${route} must be registered`);
  }
  assert.ok(routes.includes("'/api/api-keys'"), '/api/api-keys must be registered');
});

test('the shared route registry still only holds literal require() entries', () => {
  const routes = source('api/_routes.js');
  assert.doesNotMatch(routes, /require\(entry\[1\]\)/);
});

test('unknown /api paths return a JSON 404 instead of the SPA shell', () => {
  const server = source('server.js');
  assert.match(server, /app\.use\('\/api', \(_req, res\) => \{\s*res\.status\(404\)\.json/);
  const guard = server.indexOf("app.use('/api', (_req, res)");
  const staticMount = server.indexOf('express.static(dist');
  const fallback = server.indexOf("app.get('*'");
  assert.ok(guard > 0, 'API 404 guard must exist');
  assert.ok(guard < staticMount, 'guard must run before static assets');
  assert.ok(guard < fallback, 'guard must run before the SPA fallback');
});
