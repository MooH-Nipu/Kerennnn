'use strict';

const fs = require('fs');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { execFileSync, spawnSync } = require('child_process');

function loadEnv() {
  const env = {};
  for (const file of ['.env', '.env.local']) {
    if (!fs.existsSync(file)) continue;
    for (const raw of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
      const line = raw.trim();
      if (!line || line.startsWith('#') || !line.includes('=')) continue;
      const split = line.indexOf('=');
      env[line.slice(0, split)] = line.slice(split + 1).trim().replace(/^["']|["']$/g, '');
    }
  }
  return env;
}

function runPlaywright(projects, env) {
  const args = ['playwright', 'test', ...projects.flatMap(project => ['--project', project])];
  const result = spawnSync('npx', args, { stdio: 'inherit', env: { ...process.env, ...env } });
  return result.status ?? 1;
}

async function runDev() {
  const local = loadEnv();
  if (!local.SUPABASE_URL || !local.SUPABASE_SERVICE_ROLE_KEY) throw new Error('Supabase credentials missing.');
  const base = `${local.SUPABASE_URL.replace(/\/$/, '')}/rest/v1`;
  const headers = {
    apikey: local.SUPABASE_SERVICE_ROLE_KEY,
    Authorization: `Bearer ${local.SUPABASE_SERVICE_ROLE_KEY}`,
    'Content-Type': 'application/json',
    Prefer: 'return=representation',
  };
  async function request(path, init = {}) {
    const response = await fetch(base + path, { ...init, headers: { ...headers, ...init.headers } });
    const text = await response.text();
    if (!response.ok) throw new Error(`${response.status} ${text}`);
    return text ? JSON.parse(text) : null;
  }

  const stamp = `${Date.now()}-${crypto.randomBytes(3).toString('hex')}`;
  const password = crypto.randomBytes(18).toString('base64url');
  const definitions = [
    ['admin', 'admin', ['PAC', 'CHARLIE']],
    ['l1', 'l1', []],
    ['pac', 'pac', ['PAC']],
    ['dual', 'l1', ['PAC', 'CHARLIE']],
  ];
  const users = [];
  try {
    for (const [key, role, team_access] of definitions) {
      const username = `E2E_AUTO_${key.toUpperCase()}_${stamp}`;
      const [user] = await request('/app_users', {
        method: 'POST',
        body: JSON.stringify({ username, password_hash: await bcrypt.hash(password, 10), role, team_access }),
      });
      users.push(user);
      process.env[`E2E_AUTO_${key.toUpperCase()}_USERNAME`] = username;
      process.env[`E2E_AUTO_${key.toUpperCase()}_SESSION_TOKEN`] = execFileSync('docker', [
        'exec', process.env.E2E_DEV_CONTAINER || 'kerennnn-dev-app-1', 'node', '-e',
        `const {makeSessionToken}=require('./api/_auth');process.stdout.write(makeSessionToken(${JSON.stringify({ userId: user.id, username, role, teamAccess: user.team_access })},process.env.APP_AUTH_SECRET))`,
      ], { encoding: 'utf8' });
      if (key === 'admin') process.env.E2E_USERNAME = username;
    }
    process.env.E2E_AUTO_PASSWORD = password;
    process.env.E2E_PASSWORD = password;
    return runPlaywright(['dev-desktop', 'dev-narrow'], process.env);
  } finally {
    const errors = [];
    for (const user of users) {
      for (const path of [
        `/user_prefs?user_id=eq.${encodeURIComponent(user.id)}`,
        `/scan_history?user_id=eq.${encodeURIComponent(user.id)}`,
        `/login_attempts?username=eq.${encodeURIComponent(user.username)}`,
        `/app_users?id=eq.${encodeURIComponent(user.id)}`,
      ]) {
        try { await request(path, { method: 'DELETE' }); }
        catch (error) { errors.push(`${user.username} ${path.split('?')[0]}: ${error.message}`); }
      }
    }
    if (errors.length) throw new Error(`E2E cleanup failed: ${errors.join('; ')}`);
  }
}

function runProd() {
  const container = process.env.E2E_PROD_CONTAINER || 'kerennnn-app-1';
  const script = "const {getSupabase}=require('./api/_supabase');const {makeSessionToken}=require('./api/_auth');getSupabase().from('app_users').select('id,username,role,team_access').eq('role','l1').contains('team_access',['PAC','CHARLIE']).limit(1).single().then(({data,error})=>{if(error)throw error;process.stdout.write(makeSessionToken({userId:data.id,username:data.username,role:data.role,teamAccess:data.team_access},process.env.APP_AUTH_SECRET))})";
  const token = execFileSync('docker', ['exec', container, 'node', '-e', script], { encoding: 'utf8' });
  return runPlaywright(['prod-desktop', 'prod-narrow'], { E2E_SESSION_TOKEN: token });
}

const mode = process.argv[2];
if (!['dev', 'prod'].includes(mode)) {
  console.error('Usage: node scripts/run-e2e.js <dev|prod>');
  process.exit(2);
}
Promise.resolve(mode === 'dev' ? runDev() : runProd())
  .then(code => { process.exitCode = code; })
  .catch(error => { console.error(error.message); process.exitCode = 1; });
