const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('permanent browser QA separates mutable dev from read-only production', () => {
  const pkg = JSON.parse(source('package.json'));
  const config = source('playwright.config.ts');
  const runner = source('scripts/run-e2e.js');
  const dev = source('tests/e2e/dev.spec.ts');
  const responsive = source('tests/e2e/responsive.spec.ts');
  const prod = source('tests/e2e/prod.spec.ts');
  const helpers = source('tests/e2e/helpers.ts');

  assert.equal(pkg.scripts['test:e2e:dev'], 'node scripts/run-e2e.js dev');
  assert.equal(pkg.scripts['test:e2e:prod'], 'node scripts/run-e2e.js prod');
  assert.match(pkg.scripts['release:check'], /npm run test:e2e:dev/);
  assert.match(config, /name: 'dev-desktop'/);
  assert.match(config, /name: 'dev-narrow'/);
  assert.match(config, /name: 'prod-desktop'/);
  assert.match(config, /name: 'prod-narrow'/);
  assert.match(config, /video: 'retain-on-failure'/);

  assert.match(runner, /finally/);
  assert.match(runner, /E2E_AUTO_/);
  assert.match(runner, /login_attempts\?username=eq\./);
  assert.match(runner, /scan_history\?user_id=eq\./);
  assert.match(runner, /E2E_SESSION_TOKEN/);
  assert.match(dev, /GENERAL \/ Legacy List/);
  assert.match(dev, /x-client-context/);
  assert.match(responsive, /expectNoHorizontalOverflow/);
  assert.match(helpers, /scrollWidth/);
  assert.match(helpers, /stubTeamFilterReads/);
  assert.match(helpers, /route\.fulfill/);
  assert.match(prod, /read-only production smoke/);
  assert.match(prod, /READ_ONLY_PAGE_API_PATHS/);
  assert.match(prod, /blockedReads/);
  assert.match(prod, /route\.abort\(\)/);
  assert.doesNotMatch(prod, /request\.(post|put|patch|delete)\(|method:\s*['"](POST|PUT|PATCH|DELETE)/i);
});

test('CI at least validates browser suite discovery without production credentials', () => {
  const workflow = source('.github/workflows/ci.yml');
  assert.match(workflow, /playwright test --list/);
});
