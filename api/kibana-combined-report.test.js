'use strict';
/**
 * Kibana combined EOD report: DCI and CTBC share one layout but read
 * different rule-name columns ("signal.rule.name" vs "kibana.alert.rule.name").
 * SMI / MMS inputs are no longer supported.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const { Readable } = require('node:stream');
const ExcelJS = require('exceljs');

const handler = require('./kibana-combined-report');

const BOUNDARY = '----kerennnnEodBoundary';

function multipartBody(fields = {}, files = {}) {
  const chunks = [];
  for (const [name, value] of Object.entries(fields)) {
    chunks.push(Buffer.from(
      `--${BOUNDARY}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
  }
  for (const [name, { filename, content }] of Object.entries(files)) {
    chunks.push(Buffer.from(
      `--${BOUNDARY}\r\nContent-Disposition: form-data; name="${name}"; filename="${filename}"\r\nContent-Type: text/csv\r\n\r\n`));
    chunks.push(Buffer.from(content));
    chunks.push(Buffer.from('\r\n'));
  }
  chunks.push(Buffer.from(`--${BOUNDARY}--\r\n`));
  return Buffer.concat(chunks);
}

function request({ fields, files } = {}) {
  const req = Readable.from([multipartBody(fields, files)]);
  req.method = 'POST';
  req.headers = { 'content-type': `multipart/form-data; boundary=${BOUNDARY}` };
  // requireAuth() short-circuits on a revalidated request; no cookie needed here.
  req.authCurrent = true;
  req.auth = { userId: 1, role: 'admin', username: 'tester' };
  return req;
}

function response() {
  return {
    statusCode: null,
    body: null,
    headers: {},
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end(body) { this.body = body ?? this.body; return this; },
  };
}

async function run(input) {
  const res = response();
  await handler(request(input), res);
  return res;
}

async function loadSheets(buf) {
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(buf);
  return wb;
}

const DCI_CSV = [
  'signal.rule.name: Ascending,signal.rule.severity: Descending,@timestamp: Descending',
  'DCI Brute Force,7,"Oct 11, 2026 @ 08:15:30.000"',
].join('\n');

const CTBC_CSV = [
  'kibana.alert.rule.name: Descending,kibana.alert.severity: Descending,@timestamp: Descending',
  'CTBC Suspicious Login,3,"Oct 11, 2026 @ 09:45:00.000"',
].join('\n');

test('DCI csv maps alarm name from signal.rule.name', async () => {
  const res = await run({
    fields: { report_date: '2026-10-11', shift_name: 'Morning' },
    files: { dci: { filename: 'dci.csv', content: DCI_CSV } },
  });
  assert.equal(res.statusCode, 200);
  const wb = await loadSheets(res.body);
  assert.deepEqual(wb.worksheets.map(w => w.name), ['DCI']);
  const sheet = wb.getWorksheet('DCI');
  assert.deepEqual(sheet.getRow(1).values.slice(1), ['Date', 'Alarm Name', 'Severity', 'Alarm Time', 'Alarm Taken', 'Min', 'Shift Name']);
  const row = sheet.getRow(2).values;
  assert.equal(row[2], 'DCI Brute Force');
  assert.equal(row[3], '7');
  assert.equal(row[4], '08:15:30');
  assert.equal(row[5], '08:20:30');
  assert.equal(row[6], 5);
  assert.equal(row[7], 'Morning');
});

test('CTBC csv maps alarm name from kibana.alert.rule.name', async () => {
  const res = await run({
    fields: { report_date: '2026-10-11', shift_name: 'Night' },
    files: { ctbc: { filename: 'ctbc.csv', content: CTBC_CSV } },
  });
  assert.equal(res.statusCode, 200);
  const wb = await loadSheets(res.body);
  assert.deepEqual(wb.worksheets.map(w => w.name), ['CTBC']);
  const row = wb.getWorksheet('CTBC').getRow(2).values;
  assert.equal(row[2], 'CTBC Suspicious Login');
  assert.equal(row[4], '09:45:00');
  assert.equal(row[7], 'Night');
});

test('DCI and CTBC together produce one sheet each, in order', async () => {
  const res = await run({
    fields: { report_date: '2026-10-11', shift_name: 'Morning' },
    files: {
      dci: { filename: 'dci.csv', content: DCI_CSV },
      ctbc: { filename: 'ctbc.csv', content: CTBC_CSV },
    },
  });
  assert.equal(res.statusCode, 200);
  const wb = await loadSheets(res.body);
  assert.deepEqual(wb.worksheets.map(w => w.name), ['DCI', 'CTBC']);
  assert.equal(wb.getWorksheet('DCI').getRow(2).getCell(2).value, 'DCI Brute Force');
  assert.equal(wb.getWorksheet('CTBC').getRow(2).getCell(2).value, 'CTBC Suspicious Login');
});

test('CTBC rows never read the DCI rule column and vice versa', async () => {
  // a CTBC export dropped into the DCI slot must not silently pick kibana.alert values
  const swapped = [
    'signal.rule.name: Ascending,signal.rule.severity: Descending,@timestamp: Descending',
    ',7,Oct 11, 2026 @ 10:00:00.000',
  ].join('\n');
  const res = await run({
    fields: { report_date: '2026-10-11' },
    files: { dci: { filename: 'dci.csv', content: swapped } },
  });
  assert.equal(res.statusCode, 200);
  const wb = await loadSheets(res.body);
  assert.equal(wb.getWorksheet('DCI').getRow(2).getCell(2).value, '');
});

test('SMI and MMS uploads are no longer accepted inputs', async () => {
  const daily = ['id,fullDescription,severity', '1,Offense,5'].join('\n');
  const res = await run({
    fields: { report_date: '2026-10-11' },
    files: { smi: { filename: 'daily.csv', content: daily } },
  });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /DCI, CTBC, BPRKS, atau PAC/);
});

test('missing every file still reports the supported inputs', async () => {
  const res = await run({ fields: { report_date: '2026-10-11' } });
  assert.equal(res.statusCode, 400);
  assert.match(res.body.error, /DCI, CTBC, BPRKS, atau PAC/);
  assert.doesNotMatch(res.body.error, /SMI/i);
});

test('unsupported method is rejected', async () => {
  const res = response();
  const req = request({});
  req.method = 'GET';
  await handler(req, res);
  assert.equal(res.statusCode, 405);
});
