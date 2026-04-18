const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const { extractIOC, detectType, normalizeIpLine } = require('./_ioc');

describe('extractIOC', () => {
  test('trims and lowercases', () => {
    assert.equal(extractIOC('  EXAMPLE.COM  '), 'example.com');
  });

  test('strips URL to hostname', () => {
    assert.equal(extractIOC('https://evil.example.com/path?q=1'), 'evil.example.com');
  });

  test('defang hxxps', () => {
    assert.equal(extractIOC('hxxps://test[.]org/'), 'test.org');
  });
});

describe('detectType', () => {
  test('ipv4', () => {
    assert.equal(detectType('8.8.8.8'), 'ip');
  });

  test('domain', () => {
    assert.equal(detectType('example.com'), 'domain');
  });

  test('md5 hash', () => {
    assert.equal(detectType('d41d8cd98f00b204e9800998ecf8427e'), 'hash');
  });
});

describe('normalizeIpLine', () => {
  test('returns normalized ipv4', () => {
    assert.equal(normalizeIpLine('  10.0.0.1 '), '10.0.0.1');
  });

  test('returns null for domain', () => {
    assert.equal(normalizeIpLine('example.com'), null);
  });

  test('returns null for garbage', () => {
    assert.equal(normalizeIpLine('not-an-ip'), null);
  });
});
