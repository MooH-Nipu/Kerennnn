module.exports = async function handler(req, res) {
  const apiKey = process.env.VT_API_KEY;
  res.status(200).json({
    ok: true,
    keySet: !!apiKey,
    keyLength: apiKey ? apiKey.length : 0,
    keyPrefix: apiKey ? apiKey.slice(0, 6) + '...' : null,
    node: process.version,
    env: process.env.NODE_ENV || 'unknown',
  });
};
