const { buildSetCookie, makeSessionToken, readJsonBody } = require('../_auth');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const expected = process.env.APP_PASSWORD || '';
  const secret = process.env.APP_AUTH_SECRET || '';
  if (!expected || !secret) {
    return res.status(503).json({ error: 'Auth not configured (APP_PASSWORD / APP_AUTH_SECRET).' });
  }

  let body = {};
  try {
    body = await readJsonBody(req);
  } catch {
    return res.status(400).json({ error: 'Invalid JSON body.' });
  }

  const password = body && typeof body.password === 'string' ? body.password : '';
  if (!password) return res.status(400).json({ error: 'Missing password.' });
  if (password !== expected) return res.status(401).json({ error: 'Invalid password.' });

  const now = Math.floor(Date.now() / 1000);
  const ttlSec = 60 * 60 * 8; // 8 hours
  const token = makeSessionToken({ role: 'admin', exp: now + ttlSec }, secret);

  res.setHeader('Set-Cookie', buildSetCookie(token, { maxAge: ttlSec }));
  return res.status(200).json({ ok: true });
};

