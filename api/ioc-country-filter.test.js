const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

test('IOC country filter exposes explicit include and exclude modes', () => {
  const source = fs.readFileSync(path.join(__dirname, '../src/components/vt/CountryFilter.tsx'), 'utf8');

  assert.match(source, /<option value="include">Include<\/option>/);
  assert.match(source, /<option value="exclude">Exclude<\/option>/);
  assert.match(source, /onChange\(\[\.\.\.filters, \{ code, mode \}\]\)/);
});