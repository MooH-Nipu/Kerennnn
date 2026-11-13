const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const ts = require('typescript');

function loadIocModule() {
  const source = fs.readFileSync(path.resolve(__dirname, '../src/lib/ioc.ts'), 'utf8');
  const js = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const module = { exports: {} };
  vm.runInNewContext(js, { module, exports: module.exports, URL });
  return module.exports;
}

const { operationalVerdict, privateVerdict } = loadIocModule();
const verdict = label => ({ label, cls: `verdict-${label.toLowerCase().replace(' ', '-')}` });

test('a private address can never be labelled CLEAN', () => {
  const clean = operationalVerdict(verdict('CLEAN'), 0, [{ verdict: 'clean' }]);
  assert.equal(clean.label, 'CLEAN');
  const priv = privateVerdict(true, clean);
  assert.equal(priv.label, 'PRIVATE');
  assert.equal(priv.cls, 'verdict-private');
  // Public addresses are untouched.
  assert.equal(privateVerdict(false, clean).label, 'CLEAN');
  // PRIVATE replaces the non-detection buckets, but never masks a detection.
  assert.equal(privateVerdict(true, verdict('UNKNOWN')).label, 'PRIVATE');
  assert.equal(privateVerdict(true, operationalVerdict(verdict('MALICIOUS'), 0, [])).label, 'MALICIOUS');
  assert.equal(privateVerdict(true, operationalVerdict(verdict('CLEAN'), 40, [{ verdict: 'clean' }])).label, 'SUSPICIOUS');
});

test('operational verdict requires confidence or corroboration for malicious', () => {
  assert.equal(operationalVerdict(verdict('CLEAN'), 74, [{ verdict: 'malicious' }]).label, 'MALICIOUS');
  assert.equal(operationalVerdict(verdict('CLEAN'), 0, [{ verdict: 'malicious' }, { verdict: 'malicious' }]).label, 'MALICIOUS');
  assert.equal(operationalVerdict(verdict('MALICIOUS'), 0, [{ verdict: 'clean' }]).label, 'MALICIOUS');
  assert.equal(operationalVerdict(verdict('CLEAN'), 0, [{ verdict: 'malicious' }]).label, 'SUSPICIOUS');
});

test('operational verdict never calls conflicting evidence clean', () => {
  assert.equal(operationalVerdict(verdict('CLEAN'), 40, [{ verdict: 'clean' }]).label, 'SUSPICIOUS');
  assert.equal(operationalVerdict(verdict('CLEAN'), 0, [{ verdict: 'suspicious' }]).label, 'SUSPICIOUS');
  assert.equal(operationalVerdict(verdict('CLEAN'), 15, [{ verdict: 'clean' }]).label, 'LOW RISK');
  assert.equal(operationalVerdict(verdict('CLEAN'), 0, [{ verdict: 'clean' }]).label, 'CLEAN');
  assert.equal(operationalVerdict(verdict('UNKNOWN'), null, []).label, 'UNKNOWN');
  assert.equal(operationalVerdict(verdict('UNKNOWN'), 0, []).label, 'UNKNOWN');
});

test('errored and skipped provider verdicts are ignored', () => {
  const sources = [
    { verdict: 'malicious', error: 'timeout' },
    { verdict: 'malicious', skipped: true },
    { verdict: 'clean' },
  ];
  assert.equal(operationalVerdict(verdict('CLEAN'), 0, sources).label, 'CLEAN');
});

test('all analyst-facing verdict paths use consensus-aware precedence', () => {
  const root = path.resolve(__dirname, '..');
  const card = fs.readFileSync(path.join(root, 'src/components/vt/VtCard.tsx'), 'utf8');
  const scan = fs.readFileSync(path.join(root, 'src/hooks/useVtScan.ts'), 'utf8');
  const detail = fs.readFileSync(path.join(root, 'src/pages/ResultPage.tsx'), 'utf8');
  assert.equal((card.match(/operationalVerdict\(v, item\.correlation\.confidence, item\.correlation\.sources\)/g) ?? []).length, 3);
  assert.match(scan, /operationalVerdict\(vtVerdict, \(item\.correlation as unknown as Record<string, unknown>\)\?\.confidence as number \| null \?\? null, item\.correlation\.sources\)/);
  assert.match(detail, /const v = privateVerdict\(isPrivateIp\(iocValue\), operationalVerdict\(vtVerdict, corrConfidence, corr\?\.sources\)\)/);
  assert.match(detail, /High-confidence or corroborated threat intelligence flagged this indicator as malicious/);
  assert.match(detail, /Monitor this indicator and validate surrounding context before escalation/);
  assert.match(detail, /No reliable threat-intelligence verdict is available yet/);
  assert.doesNotMatch(detail, /More than 3 AV engines flagged this indicator/);
  assert.match(scan, /if \(label === 'CLEAN'\) return true;[\s\S]*return filters\.unknown;/);
  assert.match(scan, /filters: \{ unknown: true, lowrisk: true, suspicious: true, malicious: true, private: true \}/);
  // Chip row: private sits where clean used to; clean has no chip of its own.
  assert.match(scan, /const \{ label \} = privateVerdict\(isPrivateIp\(item\.ioc\), base\)/);
  assert.match(scan, /if \(label === 'PRIVATE'\) return filters\.private;/);
  assert.doesNotMatch(scan, /if \(isPrivateIp\(item\.ioc\)\) return filters\.private;/);
  const chips = fs.readFileSync(path.join(root, 'src/components/vt/VtFilterChips.tsx'), 'utf8');
  assert.match(chips, /key: 'private',[\s\S]*key: 'unknown'/);
  assert.doesNotMatch(chips, /key: 'clean'/);
  assert.match(chips, /key: 'unknown',[\s\S]*label: 'Unknown'/);
});
