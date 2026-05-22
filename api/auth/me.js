const { requireAuth } = require('../_auth');

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed' });

  if (!requireAuth(req, res)) return;
  return res.status(200).json({
    ok: true,
    role: req.auth.role,
    username: req.auth.username,
  });
};
