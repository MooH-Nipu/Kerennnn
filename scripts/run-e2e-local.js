'use strict';

const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { spawnSync } = require('child_process');

const env = {};
for (const file of ['.env', '.env.local']) {
  if (!fs.existsSync(file)) continue;
  for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || !line.includes('=')) continue;
    const split = line.indexOf('=');
    env[line.slice(0, split)] = line.slice(split + 1).trim().replace(/^['"]|['"]$/g, '');
  }
}

const base = `${env.SUPABASE_URL?.replace(/\/$/, '')}/rest/v1`;
const headers = {
  apikey: env.SUPABASE_SERVICE_ROLE_KEY,
  Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}`,
  'Content-Type': 'application/json',
  Prefer: 'return=representation',
};

async function request(path, init = {}) {
  const response = await fetch(base + path, { ...init, headers: { ...headers, ...init.headers } });
  const text = await response.text();
  if (!response.ok) throw new Error(`${response.status} ${text}`);
  return text ? JSON.parse(text) : null;
}

async function main() {
  if (!env.SUPABASE_URL || !env.SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase credentials missing.');
  const password = crypto.randomBytes(18).toString('base64url');
  const users = [];
  try {
    for (const role of ['admin', 'l1', 'pac']) {
      const username = `e2e-${role}-${Date.now()}`;
      const [user] = await request('/app_users', {
        method: 'POST',
        body: JSON.stringify({ username, password_hash: await bcrypt.hash(password, 10), role }),
      });
      users.push(user);
      process.env[`E2E_${role === 'admin' ? '' : `${role.toUpperCase()}_`}USERNAME`] = username;
      process.env[`E2E_${role === 'admin' ? '' : `${role.toUpperCase()}_`}PASSWORD`] = password;
    }
    const result = spawnSync('npm', ['run', 'test:e2e'], { stdio: 'inherit', env: process.env });
    process.exitCode = result.status ?? 1;
  } finally {
    const cleanupErrors = [];
    for (const user of users) {
      await request(`/user_prefs?user_id=eq.${encodeURIComponent(user.id)}`, { method: 'DELETE' }).catch(() => {});
      try {
        await request(`/app_users?id=eq.${encodeURIComponent(user.id)}`, { method: 'DELETE' });
      } catch (error) {
        cleanupErrors.push(`${user.username}: ${error.message}`);
      }
    }
    if (cleanupErrors.length) throw new Error(`E2E cleanup failed: ${cleanupErrors.join('; ')}`);
  }
}

main().catch(error => { console.error(error.message); process.exitCode = 1; });
