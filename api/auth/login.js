const bcrypt = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const { buildSetCookie, makeSessionToken, readJsonBody } = require('../_auth');

function getSupabase() {
  return createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const secret = process.env.APP_AUTH_SECRET || '';
  if (!secret) {
    return res.status(503).json({ error: 'Auth not configured (APP_AUTH_SECRET).' });
  }

  let body = {};
  try {
    body = await readJsonBody(req);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body.' });
  }

  const username = body && typeof body.username === 'string' ? body.username.trim() : '';
  const password = body && typeof body.password === 'string' ? body.password : '';
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password.' });
  }

  const supabase = getSupabase();
  const { data: user } = await supabase
    .from('app_users')
    .select('id, username, password_hash, role')
    .eq('username', username)
    .single();

  // Always run bcrypt regardless of whether user exists to prevent timing-based enumeration
  const hashToCheck = user?.password_hash || '$2a$12$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ01234';
  const match = await bcrypt.compare(password, hashToCheck);

  if (!user || !match) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  const now = Math.floor(Date.now() / 1000);
  const ttlSec = 60 * 60 * 8; // 8 hours
  const token = makeSessionToken(
    { userId: user.id, role: user.role, username: user.username, exp: now + ttlSec },
    secret
  );

  res.setHeader('Set-Cookie', buildSetCookie(token, { maxAge: ttlSec }));
  return res.status(200).json({ ok: true, role: user.role, username: user.username });
};
