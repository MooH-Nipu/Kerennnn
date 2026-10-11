const { describe, test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');

const envBackup = { ...process.env };
const supabasePath = require.resolve('./_supabase');
const authPath = require.resolve('./_auth');
const vtKeysPath = require.resolve('./_vtkeys');
const quotaPath = require.resolve('./admin/vt-quota');

function response() {
  return {
    headers: {},
    statusCode: null,
    body: null,
    setHeader(name, value) { this.headers[name] = value; },
    status(code) { this.statusCode = code; return this; },
    json(body) { this.body = body; return this; },
    end() { return this; },
  };
}

/** Minimal fake supabase: exact head-count per key prefix (prefix -> count). */
function fakeSupabase(prefixCounts) {
  const state = { prefix: null };
  const chain = {
    eq: () => chain,
    like: (_col, pattern) => { state.prefix = String(pattern).slice(0, 8); return chain; },
    gte: () => chain,
    lt: () => ({ count: state.prefix ? (prefixCounts[state.prefix] || 0) : 0, error: null }),
  };
  return { from: () => ({ select: () => chain }) };
}

function loadHandler(prefixCounts) {
  const fake = fakeSupabase(prefixCounts);
  require.cache[supabasePath] = { id: supabasePath, filename: supabasePath, loaded: true, exports: { getSupabase: () => fake } };
  const auth = require(authPath);
  require.cache[authPath].exports = { ...auth, requireCurrentRole: async () => true };
  delete require.cache[vtKeysPath];
  delete require.cache[quotaPath];
  return { handler: require(quotaPath), fake };
}

describe('VT shared-pool quota accounting', () => {
  beforeEach(() => {
    process.env.VT_API_KEY = 'keyone-aaaa';
    process.env.VT_API_KEY_2 = 'keytwo-bbbb';
    process.env.VT_DAILY_QUOTA_PER_KEY = '500';
    process.env.VT_DAILY_QUOTA_TOTAL = '1000';
    process.env.ABUSEIPDB_API_KEY = 'abuse-key-cccc';
  });

  afterEach(() => {
    process.env = { ...envBackup };
    delete require.cache[supabasePath];
    delete require.cache[authPath];
    delete require.cache[vtKeysPath];
    delete require.cache[quotaPath];
  });

  test('pool usage sums across keys against one pool limit', async () => {
    // 600 on key one + 450 on key two = 1050 pool > 1000 limit -> pool >100%
    const { handler } = loadHandler({ 'keyone-a': 600, 'keytwo-b': 450 });
    const res = response();

    await handler({ method: 'GET' }, res);

    assert.equal(res.statusCode, 200);
    const vt = res.body.services.find((s) => s.id === 'virustotal');
    assert.equal(vt.sharedPool, true);
    assert.equal(vt.poolLimit, 1000);
    assert.equal(vt.poolUsed, 1050);
    assert.equal(vt.poolRemaining, 0);
    assert.equal(vt.poolPercent, 100);
    // per-key stays informational
    assert.equal(vt.keys[0].used, 600);
    assert.equal(vt.keys[0].poolUsed, 1050);
    // every key in the shared pool reports the same pool numbers
    assert.equal(vt.keys[1].poolUsed, 1050);
    assert.equal(vt.keys[1].poolPercent, 100);
    // top-level legacy fields keep the same pool numbers
    assert.equal(res.body.poolUsed, 1050);
    assert.equal(res.body.sharedPool, true);
  });

  test('each key sees pool exhaustion even when its own count is low', async () => {
    // key one barely used, key two burned everything: pool must show full
    const { handler } = loadHandler({ 'keyone-a': 10, 'keytwo-b': 990 });
    const res = response();

    await handler({ method: 'GET' }, res);

    const vt = res.body.services.find((s) => s.id === 'virustotal');
    assert.equal(vt.poolUsed, 1000);
    assert.equal(vt.poolPercent, 100);
    assert.equal(vt.keys[0].used, 10);
    assert.equal(vt.keys[0].percent, 2); // per-key bar lies low; pool bar tells truth
    assert.equal(vt.keys[0].poolPercent, 100);
  });

  test('abuseipdb is not shared-pool and omits pool fields', async () => {
    const { handler } = loadHandler({ 'abuse-ke': 1 });
    const res = response();

    await handler({ method: 'GET' }, res);

    const aib = res.body.services.find((s) => s.id === 'abuseipdb');
    assert.equal(aib.sharedPool, false);
    assert.equal(aib.poolUsed, null);
    assert.equal(aib.keys[0].poolUsed, undefined);
  });

  test('unconfigured pool limit reports usage without fabricated ceiling', async () => {
    delete process.env.VT_DAILY_QUOTA_TOTAL;
    const { handler } = loadHandler({ 'keyone-a': 3, 'keytwo-b': 0 });
    const res = response();

    await handler({ method: 'GET' }, res);

    const vt = res.body.services.find((s) => s.id === 'virustotal');
    assert.equal(vt.poolLimit, null);
    assert.equal(vt.poolUsed, 3);
    assert.equal(vt.poolRemaining, null);
    assert.equal(vt.poolPercent, null);
  });
});
