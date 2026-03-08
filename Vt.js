export default async function handler(req, res) {
  // CORS for local dev
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { type, ioc } = req.query;
  const apiKey = process.env.VT_API_KEY;

  if (!apiKey) {
    return res.status(500).json({ error: 'VT_API_KEY not configured on server.' });
  }
  if (!type || !ioc) {
    return res.status(400).json({ error: 'Missing type or ioc param.' });
  }

  const endpoints = {
    hash: `https://www.virustotal.com/api/v3/files/${encodeURIComponent(ioc)}`,
    ip:   `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ioc)}`,
  };

  const url = endpoints[type];
  if (!url) return res.status(400).json({ error: 'Invalid type. Use hash or ip.' });

  try {
    const vtRes = await fetch(url, {
      headers: { 'x-apikey': apiKey, 'Accept': 'application/json' },
    });
    const data = await vtRes.json();
    return res.status(vtRes.status).json(data);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}