// Run: node --test api/_ipscope.test.js
const test = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const { isPrivateIp } = require('./_ipscope');

const TRIVIAL = ['', null, undefined, 'not-an-ip', '10.0.0.256'];

test('private and reserved IPv4 is rejected', () => {
  for (const ip of ['10.0.0.1', '10.255.255.255', '172.16.5.4', '172.31.255.254',
    '192.168.1.1', '127.0.0.1', '169.254.10.10', '100.64.0.1', '0.0.0.0',
    '224.0.0.1', '240.0.0.1', '255.255.255.255']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
});

test('public IPv4 is allowed', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '172.15.0.1', '172.32.0.1',
    '192.167.1.1', '192.169.1.1', '11.0.0.1', '45.33.32.156',
    '192.0.2.10', '198.51.100.2', '203.0.113.9']) { // TEST-NET stays scannable
    assert.equal(isPrivateIp(ip), false, ip);
  }
});

test('private IPv6, mapped IPv4 and garbage', () => {
  for (const ip of ['::1', '::', 'fc00::1', 'fd12:3456::1', 'fe80::1',
    '::ffff:192.168.1.1', '::ffff:10.0.0.5', '[::1]']) {
    assert.equal(isPrivateIp(ip), true, ip);
  }
  for (const ip of ['2001:4860:4860::8888', '::ffff:8.8.8.8', ...TRIVIAL]) {
    assert.equal(isPrivateIp(ip), false, String(ip));
  }
});

// api/_ipscope.js and src/lib/ipscope.mjs are two copies (CJS vs ESM boundary).
// This keeps them from drifting apart.
test('server and browser classifiers agree', async () => {
  const browser = await import(path.join(__dirname, '..', 'src', 'lib', 'ipscope.mjs'));
  const sample = ['10.0.0.1', '172.16.0.1', '192.168.1.1', '127.0.0.1', '100.64.0.1',
    '169.254.1.1', '0.0.0.0', '224.0.0.1', '255.255.255.255', '8.8.8.8',
    '172.15.0.1', '192.169.0.1', '192.0.2.10', '::1', 'fc00::1', 'fe80::1',
    '::ffff:10.0.0.1', '2001:4860:4860::8888', ...TRIVIAL];
  for (const ip of sample) {
    assert.equal(browser.isPrivateIp(ip), isPrivateIp(ip), String(ip));
  }
});
