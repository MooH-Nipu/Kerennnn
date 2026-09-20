const { test, describe } = require('node:test');
const assert = require('node:assert/strict');

async function parser() {
  return import('../src/lib/bulk-ioc.mjs');
}

describe('bulk IOC preview parser', () => {
  test('preserves original input while normalizing defanged IOCs', async () => {
    const { parseBulkIocs } = await parser();
    const [row] = parseBulkIocs('hxxps://Evil[.]Example/path');
    assert.equal(row.original, 'hxxps://Evil[.]Example/path');
    assert.equal(row.normalized, 'evil.example');
    assert.equal(row.type, 'url');
    assert.equal(row.valid, true);
  });

  test('classifies URLs separately while scanning normalized hostname', async () => {
    const { parseBulkIocs } = await parser();
    const [row] = parseBulkIocs('https://example.com/login');
    assert.equal(row.type, 'url');
    assert.equal(row.normalized, 'example.com');
  });

  test('marks repeated normalized IOCs as duplicates', async () => {
    const { parseBulkIocs } = await parser();
    const rows = parseBulkIocs('EXAMPLE.COM\nexample[.]com');
    assert.equal(rows[0].duplicate, false);
    assert.equal(rows[1].duplicate, true);
    assert.equal(rows[1].selected, false);
  });

  test('keeps invalid rows with a useful reason', async () => {
    const { parseBulkIocs } = await parser();
    const [row] = parseBulkIocs('not an indicator');
    assert.equal(row.valid, false);
    assert.equal(row.selected, false);
    assert.match(row.invalidReason, /Unsupported or invalid IOC/);
  });

  test('extracts scalar values from JSON input', async () => {
    const { parseBulkIocs } = await parser();
    const rows = parseBulkIocs(JSON.stringify({ src: '192.0.2.10', nested: ['example.com'] }), 'json');
    assert.deepEqual(rows.map(row => row.normalized), ['192.0.2.10', 'example.com']);
  });

  test('keeps malformed JSON visible as an error row', async () => {
    const { parseBulkIocs } = await parser();
    const [row] = parseBulkIocs('{"ioc":', 'json');
    assert.equal(row.invalidReason, 'Malformed JSON');
    assert.equal(row.selected, false);
  });

  test('parses quoted CSV cells without splitting embedded commas', async () => {
    const { parseBulkIocs } = await parser();
    const rows = parseBulkIocs('"https://evil.example/path?a=1,b=2",owner', 'csv');
    assert.equal(rows[0].normalized, 'evil.example');
  });

  test('caps preview rows before scanning', async () => {
    const { parseBulkIocs, MAX_BULK_IOCS } = await parser();
    const rows = parseBulkIocs(Array.from({ length: MAX_BULK_IOCS + 10 }, (_, i) => `host${i}.example.com`).join('\n'));
    assert.equal(rows.length, MAX_BULK_IOCS);
  });

  test('caps raw text before parsing', async () => {
    const { parseBulkIocs, MAX_BULK_INPUT_CHARS } = await parser();
    const rows = parseBulkIocs(`${'x'.repeat(MAX_BULK_INPUT_CHARS)}\nexample.com`);
    assert.equal(rows.some(row => row.normalized === 'example.com'), false);
  });

  test('selects at most 100 rows and 100 domains by default', async () => {
    const { parseBulkIocs, MAX_SELECTED_DOMAINS } = await parser();
    const rows = parseBulkIocs([...Array.from({ length: 120 }, (_, i) => `domain${i}.example.com`), ...Array.from({ length: 80 }, (_, i) => `192.0.2.${i % 255}`)].join('\n'));
    assert.equal(rows.filter(row => row.selected && row.type === 'domain').length, MAX_SELECTED_DOMAINS);
    assert.equal(rows.filter(row => row.selected).length, 100);
  });
});
