const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');

function source(file) {
  return fs.readFileSync(path.join(root, file), 'utf8');
}

test('settings lives in header beside profile, not sidebar navigation', () => {
  const header = source('src/components/layout/AppHeader.tsx');
  const nav = source('src/components/layout/TabNav.tsx');

  assert.match(header, /className=\{`settings-btn/);
  assert.match(header, /onClick=\{onOpenSettings\}/);
  assert.doesNotMatch(nav, /tabs: \['settings'\]/);
});

test('navigation tutorial requires explicit permanent dismissal', () => {
  const settings = source('src/pages/SettingsTab.tsx');

  assert.match(settings, /Navigation builder crash course/);
  assert.match(settings, /Do not show me again/);
  assert.match(settings, /dismissNavTutorial/);
  assert.match(settings, /tutorialDismissed/);
  assert.match(settings, /prefs\.dismissTutorial\(\)/);
  assert.doesNotMatch(settings, /prefs\.save\(\{ \.\.\.draft, tutorialDismissed: true \}\)/);
});

test('preference saves do not restore default tab and hidden active tabs fall back', () => {
  const app = source('src/App.tsx');
  const restoreEffect = app.match(/\/\/ Restore once when auth identity changes[\s\S]*?\}, \[([^\]]+)\]\);/)?.[1] || '';

  assert.equal(restoreEffect.replace(/\s/g, ''), 'authed,role');
  assert.match(app, /const tabs = allowedTabs\(role, hiddenTabs\);/);
  assert.doesNotMatch(app, /allowedTabs\(role, hiddenTabs, activeTab\)/);
});

test('admin usage remains reachable through personalized navigation', () => {
  const nav = source('src/components/layout/TabNav.tsx');
  const prefs = source('src/hooks/useTabPrefs.ts');
  const api = source('api/user-prefs.js');

  assert.match(nav, /id: 'admin-usage'/);
  assert.match(prefs, /tabs: \['dashboard', 'admin-usage', 'admin-users', 'admin-logs'\]/);
  assert.match(api, /'admin-usage'/);
});

test('navigation builder has keyboard-operable alternatives to drag and visible focus', () => {
  const settings = source('src/pages/SettingsTab.tsx');
  const css = source('src/styles/ui-improvements.css');

  assert.match(settings, /aria-label=\{`Move \$\{tab\.label\} up`\}/);
  assert.match(settings, /aria-label=\{`Hide \$\{tab\.label\}`\}/);
  assert.match(settings, /aria-label=\{`Move \$\{tab\.label\} to group`\}/);
  assert.match(settings, /aria-label=\{`Move \$\{group\.label\} group up`\}/);
  assert.match(css, /\.nav-tab-name:focus-visible/);
});

test('new navigation feature points users to settings', () => {
  const app = source('src/App.tsx');
  const shell = source('src/components/layout/AppShell.tsx');
  const header = source('src/components/layout/AppHeader.tsx');
  const css = source('src/styles/ui-improvements.css');

  assert.match(app, /showSettingsFeature=\{!tabPrefs\.tutorialDismissed\}/);
  assert.match(shell, /showSettingsFeature/);
  assert.match(header, /Customize your navigation/);
  assert.match(header, /settings-feature-bubble/);
  assert.match(css, /\.settings-feature-bubble::after/);
});

test('sidebar hover affordances reserve stable space and share one motion timing', () => {
  const css = source('src/styles/ui-improvements.css');

  assert.match(css, /--nav-motion-duration:\s*180ms/);
  assert.match(css, /transform:\s*translateX\(7px\) scale\(1\.025\)/);
  assert.match(css, /\.tab-nav--sidebar \.tab-btn__shortcut[\s\S]*visibility:\s*hidden/);
  assert.match(css, /\.tab-nav--sidebar \.tab-btn:hover \.tab-btn__shortcut[\s\S]*visibility:\s*visible/);
});
