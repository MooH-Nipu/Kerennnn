const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const source = file => fs.readFileSync(path.join(root, file), 'utf8');

test('production serves compressible responses through compression middleware', () => {
  const server = source('server.js');
  const pkg = JSON.parse(source('package.json'));

  assert.equal(typeof pkg.dependencies.compression, 'string');
  assert.match(server, /const compression = require\('compression'\)/);
  assert.match(server, /app\.use\(compression\(\)\)/);
});

test('content-hashed local fonts use immutable caching', () => {
  const server = source('server.js');
  const css = source('src/styles/ui-improvements.css');
  const html = source('index.html');
  const syne = 'fonts/syne-latin-68b623f0.woff2';
  const mono = 'fonts/jetbrains-mono-latin-83c005d4.woff2';

  assert.ok(fs.existsSync(path.join(root, 'public', syne)));
  assert.ok(fs.existsSync(path.join(root, 'public', mono)));
  assert.match(css, new RegExp(`/${syne}`));
  assert.match(css, new RegExp(`/${mono}`));
  assert.match(html, new RegExp(`/${syne}`));
  assert.match(server, /fonts[\s\S]{0,180}max-age=31536000, immutable/);
});
