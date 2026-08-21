const { describe, test } = require('node:test');
const assert = require('node:assert/strict');
const { sanitizeFilterItems, isSchemaMissingError, requestId, isAllowedMethod, fetchAllTeamFilterRows } = require('./team-filter');

describe('team filter input boundary', () => {
  test('accepts unique IPv4 values and discards client payload fields', () => {
    assert.deepEqual(sanitizeFilterItems([
      { ip: '192.0.2.10', role: 'admin', team: 'CHARLIE' },
      { ioc: '192.0.2.10' },
      { ip: '198.51.100.2' },
    ]), [
      { ip: '192.0.2.10', payload: { ioc: '192.0.2.10' } },
      { ip: '198.51.100.2', payload: { ioc: '198.51.100.2' } },
    ]);
  });

  test('rejects IPv6, malformed input, and oversized batches', () => {
    assert.throws(() => sanitizeFilterItems([{ ip: '2001:db8::1' }]), /valid IPv4/);
    assert.throws(() => sanitizeFilterItems([{ ip: 'not-an-ip' }]), /valid IPv4/);
    assert.throws(() => sanitizeFilterItems([]), /at least one/);
    assert.throws(() => sanitizeFilterItems(Array.from({ length: 1001 }, (_, i) => ({ ip: `10.0.${Math.floor(i / 255)}.${i % 255}` }))), /maximum 1000/);
  });

  test('recognizes missing Supabase migration errors', () => {
    assert.equal(isSchemaMissingError({ code: '42P01' }), true);
    assert.equal(isSchemaMissingError({ code: 'PGRST205' }), true);
    assert.equal(isSchemaMissingError({ code: '23505' }), false);
  });

  test('request IDs are non-secret stable-format identifiers', () => {
    assert.match(requestId(), /^req_[0-9a-f]{24}$/);
  });

  test('rejects unsupported methods before database access', () => {
    assert.equal(isAllowedMethod('GET'), true);
    assert.equal(isAllowedMethod('POST'), true);
    assert.equal(isAllowedMethod('DELETE'), true);
    assert.equal(isAllowedMethod('PUT'), false);
  });

  test('fetches every team filter row beyond the old 20,000-row ceiling', async () => {
    const source = Array.from({ length: 20001 }, (_, i) => ({ ip: `10.${Math.floor(i / 65536)}.${Math.floor(i / 256) % 256}.${i % 256}` }));
    const ranges = [];
    const supabase = {
      from() {
        return {
          select() { return this; },
          eq() { return this; },
          order() { return this; },
          range(from, to) {
            ranges.push([from, to]);
            return Promise.resolve({ data: source.slice(from, to + 1), error: null });
          },
        };
      },
    };

    const result = await fetchAllTeamFilterRows(supabase, 'PAC');

    assert.equal(result.error, null);
    assert.equal(result.items.length, 20001);
    assert.deepEqual(ranges.at(-1), [20000, 20999]);
  });
});
