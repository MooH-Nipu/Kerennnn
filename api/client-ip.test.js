'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const { resolveTrustedClientIp } = require('./_clientip');

test('direct LAN peer cannot spoof the forward header', () => {
  assert.equal(
    resolveTrustedClientIp({ peer: '192.168.31.194', header: '203.0.113.9', fallback: '192.168.31.194' }),
    '192.168.31.194'
  );
  assert.equal(
    resolveTrustedClientIp({ peer: '10.0.0.5', header: '203.0.113.9', fallback: '10.0.0.5' }),
    '10.0.0.5'
  );
  assert.equal(
    resolveTrustedClientIp({ peer: '203.0.113.20', header: '203.0.113.9', fallback: '203.0.113.20' }),
    '203.0.113.20'
  );
});

test('loopback proxy peer is trusted', () => {
  assert.equal(
    resolveTrustedClientIp({ peer: '127.0.0.1', header: '203.0.113.9', fallback: '127.0.0.1' }),
    '203.0.113.9'
  );
  assert.equal(
    resolveTrustedClientIp({ peer: '::1', header: '203.0.113.10', fallback: '::1' }),
    '203.0.113.10'
  );
  assert.equal(
    resolveTrustedClientIp({ peer: '::ffff:127.0.0.1', header: '203.0.113.13', fallback: '::ffff:127.0.0.1' }),
    '203.0.113.13'
  );
});

test('docker bridge proxy peer is trusted', () => {
  assert.equal(
    resolveTrustedClientIp({ peer: '172.18.0.4', header: '203.0.113.11', fallback: '172.18.0.4' }),
    '203.0.113.11'
  );
});

test('invalid or multi-value headers fall back', () => {
  assert.equal(resolveTrustedClientIp({ peer: '127.0.0.1', header: 'not-an-ip', fallback: '127.0.0.1' }), '127.0.0.1');
  assert.equal(resolveTrustedClientIp({ peer: '127.0.0.1', header: '', fallback: '127.0.0.1' }), '127.0.0.1');
  assert.equal(
    resolveTrustedClientIp({ peer: '127.0.0.1', header: '203.0.113.12, 10.0.0.1', fallback: '127.0.0.1' }),
    '203.0.113.12'
  );
});
