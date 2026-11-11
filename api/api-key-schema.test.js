const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const sql = fs.readFileSync(path.join(__dirname, '..', 'supabase', 'api_keys.sql'), 'utf8');

test('api_keys schema stores hashes only, never the secret', () => {
  assert.match(sql, /create table if not exists public\.api_keys/);
  assert.match(sql, /key_hash\s+text not null unique/);
  assert.match(sql, /key_prefix\s+text not null/);
  assert.match(sql, /label\s+text/, 'keys need a label so several can be told apart');
  assert.doesNotMatch(sql, /\bkey\s+text/, 'must not persist a plaintext key column');
});

test('api_keys allows several live keys per user', () => {
  assert.doesNotMatch(sql, /unique index[^;]*\(user_id\)/i, 'a unique index on user_id would block multiple keys');
  assert.match(sql, /create index if not exists api_keys_user_live_idx\s+on public\.api_keys \(user_id\) where revoked_at is null/i);
});

test('api_keys carries ACL columns used by the handlers', () => {
  assert.match(sql, /scopes\s+text\[\] not null/);
  assert.match(sql, /allowed_types\s+text\[\] not null/);
  assert.match(sql, /enabled\s+boolean not null default true/);
});
