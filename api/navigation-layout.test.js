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

  assert.match(settings, /How navigation editing works/);
  assert.match(settings, /Do not show again/);
  assert.match(settings, /dismissNavTutorial/);
  assert.match(settings, /tutorialDismissed/);
  assert.match(settings, /prefs\.dismissTutorial\(\)/);
  assert.doesNotMatch(settings, /prefs\.save\(\{ \.\.\.draft, tutorialDismissed: true \}\)/);
});

test('preference saves do not restore default tab and hidden active tabs fall back', () => {
  const app = source('src/App.tsx');
  const restoreEffect = app.match(/\/\/ Reset keep-alive state before the next identity may mount old tab children[\s\S]*?\}, \[([^\]]+)\]\);/)?.[1] || '';

  assert.equal(restoreEffect.replace(/\s/g, ''), 'workspaceIdentity');
  assert.match(app, /const tabs = allowedTabs\(role, hiddenTabs\);/);
  assert.match(app, /allowedTabs\(role!, hiddenTabs, activeTab\)/);
});

test('saved tab order drives sidebar and shortcut order', () => {
  const nav = source('src/components/layout/TabNav.tsx');

  assert.match(nav, /section\.tabs\.map\(id => tabsById\.get\(id\)\)\.filter/);
  assert.doesNotMatch(nav, /tabs\.filter\(tab => section\.tabs\.includes\(tab\.id\)\)/);
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
  assert.match(settings, /Available \(hidden\)/);
  assert.match(settings, /aria-label=\{`Move \$\{tab\.label\} to group`\}/);
  assert.match(settings, /aria-label=\{`Move \$\{group\.label\} group up`\}/);
  assert.match(css, /\.nav-tab-name:focus-visible/);
});

test('new navigation feature points users to settings', () => {
  const app = source('src/App.tsx');
  const shell = source('src/components/layout/AppShell.tsx');
  const header = source('src/components/layout/AppHeader.tsx');
  const css = source('src/styles/ui-improvements.css');

  assert.match(app, /showSettingsFeature=\{role !== 'l1' && !tabPrefs\.tutorialDismissed\}/);
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

test('mobile navigation becomes a horizontal strip instead of crushing page content', () => {
  const css = source('src/styles/ui-improvements.css');

  assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.app-shell--sidebar \.app-shell__body\s*\{[\s\S]*flex-direction:\s*column/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*\.tab-nav--sidebar\s*\{[\s\S]*width:\s*100%[\s\S]*flex-direction:\s*row/);
});

test('header and notification actions declare safe button semantics', () => {
  const header = source('src/components/layout/AppHeader.tsx');
  const toast = source('src/components/shared/SessionExpiredToast.tsx');

  assert.match(header, /type="button" className="logout-btn"/);
  assert.equal((toast.match(/type="button"/g) || []).length, 2);
});

test('app shell neutralizes legacy page geometry', () => {
  const css = source('src/styles/ui-improvements.css');

  assert.match(css, /body\s*\{[\s\S]*padding:\s*0/);
  assert.match(css, /\.app-header\s*\{[\s\S]*margin-bottom:\s*0[\s\S]*text-align:\s*left/);
});

test('dashboard custom range requires an explicit apply action', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');

  assert.match(dashboard, /function applyCustomRange\(\)/);
  assert.match(dashboard, />Apply</);
});

test('primary disclosure controls expose keyboard semantics without nesting controls', () => {
  const vtCard = source('src/components/vt/VtCard.tsx');
  const history = source('src/pages/HistoryTab.tsx');
  const correlation = source('src/components/vt/CorrelationPanel.tsx');

  assert.match(vtCard, /<button[\s\S]*className="vt-disclosure"[\s\S]*aria-expanded/);
  assert.doesNotMatch(vtCard, /className="vt-card-header"[\s\S]{0,120}role="button"/);
  assert.match(history, /<button[\s\S]*className="history-item__select"[\s\S]*aria-current/);
  assert.doesNotMatch(history, /className=\{`history-item[^`]*`\}[\s\S]{0,120}role="button"/);
  assert.match(correlation, /role=\{isExpandable \? 'button'/);
});

test('shared modal exposes semantics and manages focus lifecycle', () => {
  const modal = source('src/components/shared/Modal.tsx');
  const shortcuts = source('src/components/shared/ShortcutHelp.tsx');

  assert.match(modal, /role="dialog"/);
  assert.match(modal, /aria-modal="true"/);
  assert.match(modal, /aria-labelledby="modal-title"/);
  assert.match(modal, /previousFocus/);
  assert.match(modal, /querySelectorAll<HTMLElement>/);
  assert.match(shortcuts, /previousFocus/);
  assert.match(shortcuts, /querySelectorAll<HTMLElement>/);
});
