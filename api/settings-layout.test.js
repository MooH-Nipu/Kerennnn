const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('team context lives in Workspace settings, not global header', () => {
  const header = source('src/components/layout/AppHeader.tsx');
  const settings = source('src/pages/SettingsTab.tsx');
  assert.doesNotMatch(header, /team-context|setActiveTeam|allowedTeams/);
  assert.match(settings, /useAuthActions/);
  assert.match(settings, /settings-workspace/);
  assert.match(settings, /setActiveTeam/);
  assert.match(settings, /Team context/);
});

test('settings workflows are separated instead of stacked', () => {
  const settings = source('src/pages/SettingsTab.tsx');
  assert.match(settings, /type SettingsSection = 'workspace' \| 'navigation' \| 'alerts'/);
  assert.match(settings, /className="settings-section-nav"/);
  assert.match(settings, /activeSection === 'workspace'/);
  assert.match(settings, /activeSection === 'navigation'/);
  assert.match(settings, /activeSection === 'alerts'/);
  assert.match(settings, /aria-current=\{activeSection === section\.id \? 'page' : undefined\}/);
});

test('webhook loading is scoped to Alerts and navigation guide is compact', () => {
  const settings = source('src/pages/SettingsTab.tsx');
  assert.doesNotMatch(settings, /if \(loading\) return/);
  assert.match(settings, /loadingWebhook/);
  assert.match(settings, /<details className="nav-guide"/);
  assert.match(settings, /className="settings-toolbar"/);
});

test('alert form dismissal and validation metadata cannot accidentally submit', () => {
  const settings = source('src/pages/SettingsTab.tsx');
  const status = source('src/components/shared/StatusMessage.tsx');
  assert.match(status, /<button type="button"/);
  assert.match(settings, /aria-describedby="webhook-url-help"/);
  assert.match(settings, /id="webhook-url-help"/);
});
