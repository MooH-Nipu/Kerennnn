const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('buttons and standard action toolbars stay content-sized', () => {
  const legacy = source('styles.css');
  const css = source('src/styles/ui-improvements.css');
  assert.match(legacy, /\.btn\s*\{[^}]*flex:\s*0 0 auto;[^}]*min-width:\s*0;/s);
  assert.doesNotMatch(legacy, /\.tab-actions\s*>\s*\.btn[^}]*\{[^}]*flex:\s*1;/s);
  assert.match(css, /\.tab-actions\s*\{[^}]*justify-content:\s*flex-start;[^}]*flex-wrap:\s*wrap;/s);
});

test('live-audited layouts preserve readable proportions at desktop and 700px', () => {
  const css = source('src/styles/ui-improvements.css');
  const logs = source('src/pages/AdminLogsTab.tsx');
  const dashboard = source('src/pages/DashboardTab.tsx');
  const charts = source('src/components/dashboard/DashboardCharts.tsx');
  assert.match(css, /\.history-layout\s*\{[^}]*grid-template-columns:\s*minmax\(320px, 36%\) 1fr;/s);
  assert.match(css, /\.history-placeholder\s*\{[^}]*display:\s*grid;[^}]*place-items:\s*center;/s);
  assert.match(css, /\.history-item__preview\s*\{[^}]*-webkit-line-clamp:\s*2;/s);
  assert.match(css, /\.eod-slots\s*\{[^}]*grid-template-columns:\s*repeat\(4, 1fr\);/s);
  assert.match(css, /@media \(max-width: 820px\)[\s\S]*?\.admin-create-form\s*\{[^}]*grid-template-columns:\s*1fr;/);
  assert.match(css, /@media \(max-width: 820px\)[\s\S]*?\.user-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
  assert.match(logs, /className="admin-log-row"/);
  assert.match(logs, /className="admin-log-when"/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.admin-log-row\s*\{[^}]*grid-template-columns:\s*1fr;/);
  assert.match(css, /\.ioc-scan-results\s*>\s*\.ioc-scan-empty\s*\{[^}]*min-height:\s*280px;/s);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.merger-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
  assert.match(`${dashboard}\n${charts}`, /className="dash-analysis-grid(?: dash-analysis-grid--stable)?"/);
  assert.match(css, /@media \(max-width: 820px\)[\s\S]*?\.dash-analysis-grid\s*\{[^}]*grid-template-columns:\s*1fr;/);
});

test('page tabs use the shared tab content and section header shell', () => {
  for (const file of [
    'src/pages/AdminLogsTab.tsx',
    'src/pages/DashboardTab.tsx',
    'src/pages/AdminUsersTab.tsx',
    'src/pages/IocScanTab.tsx',
    'src/pages/HistoryTab.tsx',
    'src/pages/IrManagerTab.tsx',
  ]) {
    const page = source(file);
    assert.match(page, /className="[^"]*tab-content/,
      `${file} must use shared tab-content geometry`);
    assert.match(page, /className="section-header"/,
      `${file} must use shared section-header alignment`);
  }
});

test('compact destructive row actions retain usable pointer targets', () => {
  const css = source('src/styles/ui-improvements.css');
  assert.match(css, /\.history-item__del\s*\{[^}]*min-width:\s*28px;[^}]*min-height:\s*28px;/s);
  assert.match(css, /\.status-msg__dismiss\s*\{[^}]*min-width:\s*28px;[^}]*min-height:\s*28px;/s);
});

test('mobile sidebar collapses into one horizontal navigation strip', () => {
  const css = source('src/styles/ui-improvements.css');
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.tab-nav--sidebar\s*\{[^}]*max-height:\s*none;[^}]*flex-wrap:\s*nowrap;/);
  assert.match(css, /@media \(max-width: 760px\)[\s\S]*?\.tab-nav--sidebar \.tab-nav__section\s*\{[^}]*display:\s*contents;/);
});

test('custom clickable rows expose keyboard behavior', () => {
  const ir = source('src/pages/IrManagerTab.tsx');
  const eod = source('src/pages/DailyEodTab.tsx');
  assert.match(ir, /className="ir-case-header"[^>]*role="button"[^>]*tabIndex=\{0\}/);
  assert.match(ir, /onKeyDown=/);
  assert.match(eod, /className=\{`eod-slot[^>]*role="button"[^>]*tabIndex=\{0\}/);
});

test('authenticated workspace blocks stale mounted tabs until identity reset commits', () => {
  const app = source('src/App.tsx');
  assert.match(app, /const workspaceIdentity = authed && role && username \? `\$\{username\}:\$\{role\}:\$\{allowedTeams\.join\(','\)\}` : null/);
  assert.match(app, /workspaceIdentityRef\.current = workspaceIdentity/);
  assert.match(app, /if \(workspaceIdentityRef\.current !== workspaceIdentity\)/);
  assert.match(app, /setMountedTabs\(new Set\(\[restored\]\)\)/);
});

test('hidden active tab remains mounted until permission fallback commits', () => {
  const app = source('src/App.tsx');
  assert.match(app, /allowedTabs\(role!, hiddenTabs, activeTab, allowedTeams\)/);
  assert.match(app, /\.filter\(id => permitted\.has\(id\)\)/);
});

test('Dashboard scan action preserves native table row semantics', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');
  assert.doesNotMatch(dashboard, /<tr[\s\S]{0,180}role="button"/);
  assert.match(dashboard, /<button[^>]*type="button"[^>]*className="dash-ip-action"/);
});

test('dashboard surfaces IP cache failures instead of believable zero metrics', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');
  assert.match(dashboard, /const \[ipError, setIpError\]/);
  assert.match(dashboard, /catch \(error\)[\s\S]{0,180}setIpError/);
  assert.match(dashboard, /ipError && <StatusMessage/);
});

test('API Usage validates cleared and reversed datetime ranges before conversion', () => {
  const usage = source('src/pages/AdminUsageTab.tsx');
  assert.match(usage, /function isValidRange/);
  assert.match(usage, /if \(!isValidRange\(f, t\)\)/);
  assert.match(usage, /disabled=\{loading \|\| refreshing \|\| !isValidRange\(from, to\)\}/);
});

test('legacy element selectors cannot override canonical controls and cards stay dense', () => {
  const legacy = source('styles.css');
  const bridge = source('src/styles/stisla-bridge.css');
  assert.doesNotMatch(legacy, /^\s*label\s*\{/m);
  assert.doesNotMatch(legacy, /^\s*textarea, input\[type=/m);
  assert.match(bridge, /\.card\s*\{[^}]*padding:\s*0;[^}]*gap:\s*0;[^}]*box-shadow:\s*none;/s);
  assert.match(bridge, /\.form-label\s*\{[^}]*font-size:\s*0\.75rem;[^}]*text-transform:\s*uppercase;/s);
});

test('narrow grids and search rows collapse without page overflow', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');
  const css = source('src/styles/ui-improvements.css');
  assert.doesNotMatch(dashboard, /minmax\((320|400)px, 1fr\)/);
  assert.match(css, /\.cve-search \.form-input\s*\{[^}]*min-width:\s*0;/s);
  assert.match(css, /@media \(max-width: 560px\)[\s\S]*?\.cve-search\s*\{[^}]*flex-direction:\s*column;/);
});

test('filtered result views explain zero matches instead of rendering blank', () => {
  const history = source('src/pages/HistoryTab.tsx');
  const ioc = source('src/pages/IocScanTab.tsx');
  assert.match(history, /allEntries/);
  assert.match(history, /No history matches/);
  assert.match(ioc, /No results match current filters/);
});

test('dynamic loading and scan progress remain visibly active and accessible', () => {
  const ioc = source('src/pages/IocScanTab.tsx');
  const spinner = source('src/components/shared/Spinner.tsx');
  const css = source('src/styles/ui-improvements.css');
  const output = source('src/components/shared/OutputBox.tsx');
  const highlighted = source('src/components/shared/HighlightedOutput.tsx');
  assert.match(ioc, /role="progressbar"/);
  assert.match(ioc, /aria-valuenow=/);
  assert.match(ioc, /role=\{statusType === 'error' \? 'alert' : 'status'\}/);
  assert.match(spinner, /className="loading-spinner"/);
  assert.match(spinner, /role="status"/);
  assert.match(css, /@keyframes loading-spinner-spin/);
  assert.match(css, /@media \(prefers-reduced-motion: reduce\)[\s\S]*?\.loading-spinner\s*\{[^}]*animation-duration:\s*1\.5s !important;[^}]*animation-iteration-count:\s*infinite !important;/);
  assert.match(output, /aria-label=\{ariaLabel\}/);
  assert.match(highlighted, /role="textbox"/);
  assert.match(highlighted, /tabIndex=\{0\}/);
});

test('Dashboard centers charts and caps per-user bars at six users plus Other', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');
  const charts = source('src/components/dashboard/DashboardCharts.tsx');
  const helper = source('src/lib/dashboard-data.ts');
  const css = source('src/styles/ui-improvements.css');
  assert.match(dashboard, /import \{ aggregateUserScans \}/);
  assert.match(helper, /\.slice\(0, 6\)/);
  assert.match(helper, /\.slice\(6\)\.reduce/);
  assert.match(helper, /username: 'Other'/);
  assert.match(dashboard, /const userScanChartData = aggregateUserScans\(ipScanData\?\.byUser \?\? \[\]\)/);
  assert.match(charts, /data=\{userScanChartData\}/);
  assert.match(charts, /userScanChartData\.length \* 34/);
  assert.match(charts, /className="card__body dash-chart-body"/);
  assert.match(css, /\.dash-chart-body\s*\{[^}]*display:\s*grid;[^}]*place-items:\s*center;[^}]*min-height:\s*286px;/s);
});

test('Dashboard defers chart runtime and preserves loading geometry', () => {
  const dashboard = source('src/pages/DashboardTab.tsx');
  const charts = source('src/components/dashboard/DashboardCharts.tsx');
  const css = source('src/styles/ui-improvements.css');

  assert.doesNotMatch(dashboard, /from 'recharts'/);
  assert.match(dashboard, /lazy\(\(\) => import\('\.\.\/components\/dashboard\/DashboardCharts'\)\)/);
  assert.match(charts, /from 'recharts'/);
  assert.match(dashboard, /className="dash-analysis-grid dash-analysis-grid--stable"/);
  assert.match(dashboard, /className="card dash-quota-slot"/);
  assert.match(`${dashboard}\n${charts}`, /className="card dash-usage-slot"/);
  assert.match(dashboard, /section="analysis"[\s\S]*className="card dash-quota-slot"[\s\S]*section="usage"/);
  assert.match(dashboard, /const chartsLoading = usageLoading && !usageData && !ipScanData;/);
  assert.match(dashboard, /chartsLoading \? <DashboardChartSkeleton section="analysis"/);
  assert.match(dashboard, /usageLoading && !usageData && \(/);
  assert.match(dashboard, /className="dash-tables-grid"/);
  assert.match(css, /\.dash-analysis-grid--stable\s*>\s*\.card\s*\{[^}]*min-height:\s*348px;/s);
  assert.match(css, /\.dash-quota-slot\s*\{[^}]*min-height:\s*160px;/s);
  assert.match(css, /\.dash-usage-slot\s*\{[^}]*min-height:\s*326px;/s);
  assert.match(css, /\.dash-table-card\s*\{[^}]*min-height:\s*690px;/s);
});

test('measured header, navigation, and success badge colors meet contrast fixes', () => {
  const css = source('src/styles/ui-improvements.css');
  assert.match(css, /\.app-header__title em\s*\{[^}]*color:\s*#6ea8fe;/s);
  assert.match(css, /\.tab-nav__section-label\s*\{[^}]*color:\s*var\(--text-secondary, #a3b3cc\);/s);
  assert.match(css, /\.badge--success\.badge--soft\s*\{[^}]*color:\s*#4ade80;/s);
  assert.match(css, /\.update-toast__badge\s*\{[^}]*color:\s*#6ea8fe;/s);
});

test('Team Filter warnings are not styled as success', () => {
  const filter = source('src/pages/PacFilterTab.tsx');
  assert.match(filter, /statusMsg\?\.startsWith\('⚠'\) \? 'warning'/);
});

test('IR import dialog owns focus, traps Tab, closes on Escape, and restores focus', () => {
  const ir = source('src/pages/IrManagerTab.tsx');
  assert.match(ir, /role="dialog"/);
  assert.match(ir, /aria-modal="true"/);
  assert.match(ir, /aria-labelledby="ir-import-title"/);
  assert.match(ir, /const importDialogRef = useRef<HTMLDivElement>/);
  assert.match(ir, /const importReturnFocusRef = useRef<HTMLElement \| null>/);
  assert.match(ir, /dialog\.querySelectorAll<HTMLElement>/);
  assert.match(ir, /event\.key !== 'Tab'/);
  assert.match(ir, /if \(event\.key === 'Escape'\) cancelImport\(\)/);
  assert.match(ir, /importReturnFocusRef\.current\?\.focus\(\)/);
  assert.match(ir, /ref=\{importDialogRef\}/);
});

test('Admin Logs detail wraps long audit payloads at narrow widths', () => {
  const logs = source('src/pages/AdminLogsTab.tsx');
  const css = source('src/styles/ui-improvements.css');
  assert.match(logs, /className="admin-log-detail"/);
  assert.match(css, /\.admin-log-detail\s*\{[^}]*overflow-wrap:\s*anywhere;/s);
});
