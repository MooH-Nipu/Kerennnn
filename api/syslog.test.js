const { test } = require('node:test');
const assert = require('node:assert/strict');
const parser = import('../src/lib/syslog.mjs');
const fortigate = '<45>date=2026-10-27 time=13:39:17 devname="xxx" devid="xxx" eventtime=xxx tz="+0800" logid="0000000020" type="traffic" subtype="forward" level="notice" vd="xxx" srcip=xxx srcname="xxx" srcport=39600 srcintf="xxx" srcintfrole="lan" dstip=xxx dstport=xxx dstintf="xxx" dstintfrole="xxx" srcuuid="xxx" dstuuid="xxx" srccountry="Reserved" dstcountry="Indonesia" sessionid=xxx proto=17 action="accept" policyid=36 policytype="policy" poluuid="xxx" policyname="xxx" service="udp/9253" trandisp="snat" transip=xxx transport=39600 appid=xxx app="xxx" appcat="xxx" apprisk="xxx" applist="default" duration=139 sentbyte=1440 rcvdbyte=0 sentpkt=20 rcvdpkt=0 vwlid=1 vwlquality="Seq_num(1 wan2 virtual-wan-link), alive, selected" vwlname="xxx" sentdelta=1440 rcvddelta=0 durationdelta=139 sentpktdelta=20 rcvdpktdelta=0 srchwvendor="Samsung" devtype="Phone" srcfamily="Galaxy" osname="Android" srchwversion="A" srcswversion="16" mastersrcmac="1a:35:53:12:e4:da" srcmac="1a:35:53:12:e4:da" srcserver=0';
const modern = '<165>1 2003-10-11T22:14:15.003Z host app 8710 ID47 ';

test('5424 decodes priority, calendar timestamp, headers and exact message', async () => {
  const { parseSyslogRecord } = await parser;
  const raw = modern + '[exampleSDID@32473 iut="3" eventSource="Application"] BOM  message  ';
  const r = parseSyslogRecord(raw);
  assert.equal(r.valid, true);
  assert.equal(r.raw, raw);
  assert.deepEqual(r.facility, { code: 20, name: 'local4' });
  assert.deepEqual(r.severity, { code: 5, name: 'Notice' });
  assert.equal(r.timestamp, '2003-10-11T22:14:15.003Z');
  assert.equal(r.hostname, 'host'); assert.equal(r.appName, 'app');
  assert.equal(r.procId, '8710'); assert.equal(r.msgId, 'ID47');
  assert.deepEqual(r.structuredData, [{ id: 'exampleSDID@32473', params: [{ name: 'iut', value: '3' }, { name: 'eventSource', value: 'Application' }] }]);
  assert.equal(r.message, 'BOM  message  ');
});
test('5424 NILVALUE and optional/empty message stay distinct', async () => {
  const { parseSyslogRecord } = await parser;
  const raw = '<0>1 - - - - - -';
  const r = parseSyslogRecord(raw);
  assert.equal(r.valid, true);
  for (const key of ['timestamp', 'hostname', 'appName', 'procId', 'msgId', 'message']) assert.equal(r[key], null);
  assert.deepEqual(r.structuredData, []);
  assert.equal(parseSyslogRecord(raw + ' ').message, '');
  assert.deepEqual(r.severity, { code: 0, name: 'Emergency' });
});
test('5424 handles all three escapes, multiple SD elements and hostile-looking text as data', async () => {
  const { parseSyslogRecord } = await parser;
  const sd = String.raw`[a p="quote\" slash\\ close\]"][b x="<script>"]`;
  const r = parseSyslogRecord(modern + sd + ' \uFEFFhello');
  assert.equal(r.valid, true);
  assert.equal(r.structuredDataRaw, sd);
  assert.deepEqual(r.structuredData, [{ id: 'a', params: [{ name: 'p', value: 'quote" slash\\ close]' }] }, { id: 'b', params: [{ name: 'x', value: '<script>' }] }]);
  assert.equal(r.message, '\uFEFFhello');
  const unknownEscape = parseSyslogRecord(modern + String.raw`[a x="bad\q"]`);
  assert.equal(unknownEscape.valid, true);
  assert.equal(unknownEscape.structuredData[0].params[0].value, String.raw`bad\q`);
});
test('3164 keeps missing year/timezone unknown, preserves spacing and extracts only clear tag/PID', async () => {
  const { parseSyslogRecord } = await parser;
  const raw = '<191>Feb  9 01:02:03 host sshd[007]:  failed  ';
  const r = parseSyslogRecord(raw);
  assert.equal(r.valid, true); assert.equal(r.format, 'RFC 3164');
  assert.equal(r.timestamp, 'Feb  9 01:02:03'); assert.equal(r.year, null); assert.equal(r.timezone, null);
  assert.deepEqual(r.facility, { code: 23, name: 'local7' });
  assert.equal(r.severity.name, 'Debug'); assert.equal(r.tag, 'sshd'); assert.equal(r.pid, '007');
  assert.equal(r.message, 'sshd[007]:  failed  '); assert.equal(r.content, ' failed  '); assert.equal(r.raw, raw);
  const unknown = parseSyslogRecord('<13>Feb 29 23:59:59 host app-name[abc]: hello');
  assert.equal(unknown.valid, true); assert.equal(unknown.tag, null); assert.equal(unknown.pid, null);
});
test('invalid records have explicit error and original raw, without poisoning adjacent records', async () => {
  const { parseSyslogRecord, parseSyslogInput } = await parser;
  const invalid = ['<192>1 - - - - - -', '<01>1 - - - - - -', 'hello', '<1>2 - - - - - -', '<1>1 2023-02-29T01:00:00Z - - - - -', '<1>1 2024-02-29T24:00:00Z - - - - -', '<1>1 2024-02-29T01:00:00 - - - - -', modern + '[a x="bad]value"]', modern + '[a x="open]', modern + '[a][a]', modern + '[a x="1" x="2"]', modern + '[a]no-space', '<1>Apr 31 12:00:00 host x', '<1>Jan  1 12:60:00 host x', '<1>Jan 1 12:00:00 host x', '<1>1 - - ' + 'a'.repeat(49) + ' - - -'];
  for (const raw of invalid) {
    const r = parseSyslogRecord(raw);
    assert.equal(r.valid, false, raw); assert.equal(r.raw, raw); assert.ok(r.error.length > 5, raw);
  }
  const rows = parseSyslogInput(modern + '- hi\r\n\ninvalid\n<13>Oct 11 12:00:00 host tag: ok\n');
  assert.deepEqual(rows.map(r => [r.line, r.valid, r.format]), [[1, true, 'RFC 5424'], [3, false, null], [4, true, 'RFC 3164']]);
});
test('bounded processing rejects whole oversize batch and marks oversized individual record', async () => {
  const { parseSyslogInput, parseSyslogRecord, MAX_SYSLOG_CHARS, MAX_SYSLOG_LINES, MAX_SYSLOG_RECORD_CHARS, syslogReadable } = await parser;
  assert.throws(() => parseSyslogInput('x'.repeat(MAX_SYSLOG_CHARS + 1)), /nothing processed/);
  assert.throws(() => parseSyslogInput('\n'.repeat(MAX_SYSLOG_LINES)), /nothing processed/);
  assert.equal(parseSyslogRecord('x'.repeat(MAX_SYSLOG_RECORD_CHARS + 1)).valid, false);
  assert.match(parseSyslogRecord('<1>Oct 11 12:00:00 host ' + 'é'.repeat(501)).error, /1024 bytes/);
  const rows = parseSyslogInput('bad');
  assert.match(syslogReadable(rows), /Line 1 · Unknown format · INVALID/);
  assert.match(syslogReadable(rows), /raw: bad/);
  assert.deepEqual(parseSyslogInput(' \n\t'), []);
});
test('FortiGate exact sample keeps every field string and full quoted quality', async () => {
  const { parseSyslogRecord, syslogReadable } = await parser;
  for (const raw of [fortigate, fortigate.slice(4)]) {
    const r = parseSyslogRecord(raw);
    assert.equal(r.valid, true, r.error);
    assert.equal(r.format, 'FortiGate / key-value');
    assert.equal(r.raw, raw);
    assert.equal(r.priority, raw.startsWith('<') ? 45 : null);
    assert.equal(r.fields.length, 62);
    const expected = [...fortigate.slice(4).matchAll(/(\w+)=(?:"([^"]*)"|(\S+))/g)].map(([, name, quoted, bare]) => ({ name, value: quoted ?? bare }));
    assert.deepEqual(r.fields, expected);
    assert.ok(r.fields.every(f => typeof f.value === 'string'));
    assert.equal(r.fields.find(f => f.name === 'vwlquality').value, 'Seq_num(1 wan2 virtual-wan-link), alive, selected');
    assert.equal(r.fields.find(f => f.name === 'logid').value, '0000000020');
    assert.equal(r.fields.find(f => f.name === 'eventtime').value, 'xxx');
    assert.match(syslogReadable([r]), /vwlquality: Seq_num\(1 wan2 virtual-wan-link\), alive, selected/);
    assert.ok(!syslogReadable([r]).includes('fields: ['));
  }
});
test('key-value tokenizer preserves duplicates, empties, escapes, precision and envelope MSG', async () => {
  const { parseSyslogRecord } = await parser;
  const body = String.raw`msg="a=b \"quote\" C:\\path" empty="" id=007 id=9007199254740993123 unknown="a\q"`;
  const r = parseSyslogRecord(body);
  assert.equal(r.valid, true, r.error);
  assert.equal(r.format, 'Key-value');
  assert.deepEqual(r.fields, [
    { name: 'msg', value: 'a=b "quote" C:\\path' }, { name: 'empty', value: '' },
    { name: 'id', value: '007' }, { name: 'id', value: '9007199254740993123' }, { name: 'unknown', value: String.raw`a\q` },
  ]);
  assert.ok(r.notes.some(n => n.includes('Duplicate key: id')));
  for (const raw of [modern + '- ' + body, '<13>Oct 11 12:00:00 host tag: ' + body]) {
    const envelope = parseSyslogRecord(raw);
    assert.equal(envelope.valid, true, envelope.error);
    assert.deepEqual(envelope.fields, r.fields);
  }
  for (const raw of ['a="open', 'a="ok"garbage', 'a=ok garbage', 'a="ok" b=', 'a=bare"quote', 'a="trailing\\']) {
    const bad = parseSyslogRecord(raw);
    assert.equal(bad.valid, false, raw); assert.equal(bad.raw, raw); assert.match(bad.error, /key-value/i);
  }
});
test('syslog tab survives server preference sanitization', () => {
  const { sanitizeIds, sanitizeLayout } = require('./user-prefs');
  assert.deepEqual(sanitizeIds(['syslog', 'unknown', 'syslog', 'json']), ['json']);
  assert.deepEqual(sanitizeLayout([
    { id: 'custom', label: 'Custom', tabs: ['formatter', 'syslog', 'cve'] },
    { id: 'utilities', label: 'Utilities', tabs: ['json', 'syslog', 'merger'] },
  ]), [
    { id: 'custom', label: 'Custom', tabs: ['formatter', 'json', 'cve'] },
    { id: 'utilities', label: 'Utilities', tabs: ['merger'] },
  ]);
  assert.deepEqual(sanitizeLayout([{ id: 'utilities', label: 'Utilities', tabs: ['syslog'] }]), [{ id: 'utilities', label: 'Utilities', tabs: ['json'] }]);
});
