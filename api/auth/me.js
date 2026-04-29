const { requireAuth } = require('../_auth');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  const enabled = !!(process.env.APP_PASSWORD && process.env.APP_AUTH_SECRET);
  if (!enabled) {
    // Auth disabled: treat as already allowed (no login required)
    return res.status(200).json({ ok: true, enabled: false, authed: true });
  }

  if (!requireAuth(req, res)) return;
  return res.status(200).json({ ok: true, enabled: true, authed: true, role: req.auth?.role || 'admin' });
};

