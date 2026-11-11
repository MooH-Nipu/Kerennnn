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
