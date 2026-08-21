const test = require('node:test');
const assert = require('node:assert/strict');

function loadFresh() {
  delete require.cache[require.resolve('./_ratelimit')];
  return require('./_ratelimit');
}

test('client IP ignores forwarded headers unless proxy trust is explicit', () => {
  const { getClientIp } = loadFresh();
  const req = {
    headers: { 'x-forwarded-for': '198.51.100.7' },
    socket: { remoteAddress: '127.0.0.1' },
  };
  assert.equal(getClientIp(req), '127.0.0.1');
  req.trustedClientIp = '203.0.113.9';
  assert.equal(getClientIp(req), '203.0.113.9');
});

test('database limiter errors fall back to bounded local IP budget', async () => {
  const { checkLoginRateLimit, resetLocalRateLimitForTest } = loadFresh();
  resetLocalRateLimitForTest();
  const supabase = { from() { throw new Error('database unavailable'); } };
  let result;
  for (let i = 0; i < 10; i++) result = await checkLoginRateLimit(supabase, `user-${i}`, '192.0.2.1');
  assert.equal(result.locked, false);
  result = await checkLoginRateLimit(supabase, 'new-user', '192.0.2.1');
  assert.equal(result.locked, true);
});

test('local IP budget works when Supabase is unavailable', async () => {
  const { checkLoginRateLimit, resetLocalRateLimitForTest } = loadFresh();
  resetLocalRateLimitForTest();
  for (let i = 0; i < 10; i++) await checkLoginRateLimit(null, `guess-${i}`, '192.0.2.2');
  assert.equal((await checkLoginRateLimit(null, 'another', '192.0.2.2')).locked, true);
});
