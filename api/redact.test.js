// Run: node --test api/redact.test.js
// Pairs with src/lib/redact.mjs — the browser redactor. Same assertions as
// ~/redact.py --selftest, expressed against the JS port.
const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');

const load = () => import(path.join(__dirname, '..', 'src', 'lib', 'redact.mjs'));

const SALT = new Uint8Array(32).fill(7);

const SECRETS = {
  email: 'alice.wong@corp.example.net',
  jwt: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U',
  aws: 'AKIAIOSFODNN7EXAMPLE',
  github: 'ghp_1234567890abcdefghijklmnopqrstuvwxyz',
  openai: 'sk-proj-abcdefghijklmnopqrstuvwxyz123456',
  conn: 'postgres://admin:hunter2@db.internal:5432/prod',
  card: '4111 1111 1111 1111',
  nik: '3174091234567890',
  phone: '+6281234567890',
  ip: '10.20.30.40',
  homePath: '/home/pebry/.ssh/id_rsa',
  mac: 'aa:bb:cc:dd:ee:ff',
  device: 'agent-SalesBot-01',
  entropy: 'zK9fQ2mXvB7pL4wR8tY1nU6sE3aD5gH0jK2mN4oP',
  kv: 'hunter2-prod-db',
  pem: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7x\n-----END RSA PRIVATE KEY-----',
  authHeader: 'sk_live_abcdefghijklmnop123456',
  cookie: 'SESSIONID_ABC123DEF456',
  webhook: 'https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX',
  signed: 'deadbeef1234',
};

const CONTROLS = [
  '2026-01-01T10:00:00Z',
  '5f2c9a1e8b4d7c3a2f1e0d9c8b7a6f5e4d3c2b1a', // 40-hex git SHA
  'v2.14.3',
  'localhost:8080',
  'user@example.com',
  'id=42',
];

const FIXTURE = [
  `Authorization: Bearer sk_live_abcdefghijklmnop123456`,
  `password=hunter2-prod-db`,
  `ssh host=10.20.30.40 path=/home/pebry/.ssh/id_rsa`,
  `agent agent-SalesBot-01 reported card 4111 1111 1111 1111 nik 3174091234567890`,
  `token=zK9fQ2mXvB7pL4wR8tY1nU6sE3aD5gH0jK2mN4oP`,
  `pg postgres://admin:hunter2@db.internal:5432/prod`,
  `device mac aa:bb:cc:dd:ee:ff tel +6281234567890 mail alice.wong@corp.example.net`,
  `key AKIAIOSFODNN7EXAMPLE ghp_1234567890abcdefghijklmnopqrstuvwxyz sk-proj-abcdefghijklmnopqrstuvwxyz123456`,
  `jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U`,
  `-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA7x\n-----END RSA PRIVATE KEY-----`,
  `session cookie=SESSIONID_ABC123DEF456; path=/; HttpOnly`,
  `hook https://hooks.slack.com/services/T000/B000/XXXXXXXXXXXXXXXXXXXXXXXX`,
  `presign https://s3.amazonaws.com/b/o?X-Amz-Signature=deadbeef1234`,
  `ts 2026-01-01T10:00:00Z sha 5f2c9a1e8b4d7c3a2f1e0d9c8b7a6f5e4d3c2b1a ver v2.14.3`,
  `host localhost:8080 ping user@example.com id=42`,
].join('\n');

test('every secret is gone from the output', async () => {
  const { redact } = await load();
  const { text } = await redact(FIXTURE, SALT);
  for (const [name, value] of Object.entries(SECRETS)) {
    assert.ok(!text.includes(value), `LEAK ${name}: ${value}`);
  }
});

test('control strings survive: git SHA, timestamp, semver, loopback, example.com', async () => {
  const { redact } = await load();
  const { text } = await redact(FIXTURE, SALT);
  for (const value of CONTROLS) assert.ok(text.includes(value), `OVER-REDACT: ${value}\n${text}`);
});

test('key survives, only the value is replaced', async () => {
  const { redact } = await load();
  const { text } = await redact(FIXTURE, SALT);
  assert.ok(text.includes('password='), 'kv key must survive');
  assert.ok(text.includes('Authorization: '), 'header name must survive');
  assert.ok(/cookie=«KV_[0-9a-f]{8}»; path=\/; HttpOnly/.test(text), 'cookie attrs survive');
});

test('identical values share a token, different values do not', async () => {
  const { redact } = await load();
  const same = await redact('u1 alice@a.com u2 alice@a.com', SALT);
  const [t1, t2] = same.text.split(' ').filter(t => t.startsWith('\u00ab'));
  assert.equal(t1, t2, 'same value must map to one token');

  const diff = await redact('u1 alice@a.com u2 bob@b.com', SALT);
  const [d1, d2] = diff.text.split(' ').filter(t => t.startsWith('\u00ab'));
  assert.notEqual(d1, d2, 'different values must not collide');
});

test('idempotent: redacting the output changes nothing', async () => {
  const { redact } = await load();
  const once = await redact(FIXTURE, SALT);
  const twice = await redact(once.text, SALT);
  assert.equal(twice.text, once.text);
});

test('strict adds UUID, k8s name and 12-digit account id', async () => {
  const { redact } = await load();
  const src = 'req 550e8400-e29b-41d4-a716-446655440000 pod api-7d9f-xk2pq acct 123456789012';
  const base = await redact(src, SALT);
  assert.ok(base.text.includes('550e8400'), 'non-strict keeps UUIDs on purpose');
  const strict = await redact(src, SALT, { strict: true });
  for (const v of ['550e8400', 'api-7d9f-xk2pq', '123456789012']) {
    assert.ok(!strict.text.includes(v), `strict leak: ${v}`);
  }
});

test('registry catches a name no pattern would', async () => {
  const { redact } = await load();
  const { text } = await redact('node Agent-Zephyr online', SALT, { entities: ['Agent-Zephyr'] });
  assert.ok(!text.includes('Zephyr'));
  assert.ok(text.includes('node '), 'surrounding structure survives');
});

test('blocklist terms are redacted and reported', async () => {
  const { redact } = await load();
  const { text, stats } = await redact('payload contains badword here', SALT, { terms: ['badword'] });
  assert.ok(!text.includes('badword'));
  assert.equal(stats.term, 1);
});

test('legend names the token format so the model does not invent values', async () => {
  const { legend } = await load();
  assert.match(legend(), /<<CATEGORY_hash>>/);
});

test('fails closed without Web Crypto instead of emitting plaintext', async () => {
  const { redact } = await load();
  const saved = globalThis.crypto;
  Object.defineProperty(globalThis, 'crypto', { value: undefined, configurable: true });
  try {
    await assert.rejects(() => redact(FIXTURE, SALT), /Web Crypto/);
  } finally {
    Object.defineProperty(globalThis, 'crypto', { value: saved, configurable: true });
  }
});

// A pasted log is untrusted input to a client-side regex engine. Unbounded
// quantifiers in the email/fqdn/k8s rules turned "a.a.a.a…" into a 56-second
// main-thread hang (O(n^2) and exponential backtracking). Budget, not a
// benchmark: 2000ms is ~20x the current worst case and still catches a relapse.
test('adversarial input cannot hang the main thread (ReDoS budget)', async () => {
  const { redact } = await load();
  const N = 60000;
  const probes = {
    'dot-run': `a${'.a'.repeat(N)}`,
    'dash-run': `a${'-a'.repeat(N)}`,
    'dot-run-tight': `a${'.a'.repeat(N)}.x!`,
    'dash-run-tight': `a${'-a'.repeat(N)}-`,
    'at-run': `a${'@a'.repeat(N)}`,
  };
  for (const [name, input] of Object.entries(probes)) {
    const started = Date.now();
    await redact(input, SALT, { strict: true });
    const elapsed = Date.now() - started;
    assert.ok(elapsed < 2000, `${name} took ${elapsed}ms on ${input.length} chars — ReDoS regression`);
  }
});

test('email rule keeps matching real addresses after the ReDoS fix', async () => {
  const { redact } = await load();
  for (const addr of ['alice.wong@corp.example.net', 'first.last+tag@sub.domain.co.uk',
    'x_y-z@mail-server.io', 'user+tag@mail.acme.io']) {
    const { text } = await redact(`contact ${addr} now`, SALT);
    assert.ok(!text.includes(addr), `email missed: ${addr}`);
  }
  for (const notEmail of ['a.a.a.a.a', 'user@', '@domain.com', 'a@b', 'a@b.c']) {
    const { text } = await redact(`value ${notEmail} end`, SALT);
    assert.ok(text.includes(notEmail), `over-redacted non-email: ${notEmail}`);
  }
  // example.com is allow-listed on purpose: redacting it destroys the signal.
  const { text } = await redact('contact user@example.com now', SALT);
  assert.ok(text.includes('user@example.com'), 'allow-listed example.com must survive');
});

