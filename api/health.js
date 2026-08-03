'use strict';

// Keep liveness endpoint dependency-free. Provider diagnostics belong behind
// authenticated admin routes and must never expose key metadata publicly.
module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return res.status(405).json({ error: 'Method not allowed.' });
  }
  if (req.method === 'HEAD') return res.status(200).end();
  return res.status(200).json({ ok: true });
};
