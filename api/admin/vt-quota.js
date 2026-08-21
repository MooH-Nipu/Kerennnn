'use strict';
const { requireCurrentRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { getVtKeys, isVtKeyCoolingDown, isVtKeyQuotaExceeded, getVtKeyQuotaResetAt } = require('../_vtkeys');
const { getAbuseIPDBKeys } = require('../_abuseipdbkeys');
const { serverError } = require('../_errors');

function positiveInt(value, fallback) {
  const parsed = Number.parseInt(String(value || ''), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured.' });
  if (!await requireCurrentRole(req, res, supabase, ['admin', 'l2'])) return;

  const services = [
    { id: 'virustotal', name: 'VirusTotal', keys: getVtKeys(), limit: positiveInt(process.env.VT_DAILY_QUOTA_PER_KEY, 500) },
    { id: 'abuseipdb', name: 'AbuseIPDB', keys: getAbuseIPDBKeys(), limit: positiveInt(process.env.ABUSEIPDB_DAILY_QUOTA_PER_KEY, 1000) },
  ];
  const now = new Date();
  const resetAt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const periodStart = new Date(resetAt.getTime() - 24 * 60 * 60 * 1000);

  try {
    const quotaServices = await Promise.all(services.map(async (service) => {
      const rows = await Promise.all(service.keys.map(async (key, index) => {
      const prefix = key.slice(0, 8);
      const { count, error } = await supabase
        .from('api_usage')
        .select('id', { count: 'exact', head: true })
        .eq('service', service.name)
        .like('api_key', `${prefix}%`)
        .gte('created_at', periodStart.toISOString())
        .lt('created_at', resetAt.toISOString());
      if (error) throw error;
      const used = count || 0;
      const quotaResetAt = service.id === 'virustotal' ? getVtKeyQuotaResetAt(key) : null;
      return {
        key: `${service.name} key ${index + 1}`,
        prefix: `${prefix}...`,
        used,
        limit: service.limit,
        remaining: Math.max(0, service.limit - used),
        percent: Math.min(100, Math.round((used / service.limit) * 100)),
        coolingDown: service.id === 'virustotal' && isVtKeyCoolingDown(key),
        quotaExhausted: service.id === 'virustotal' && isVtKeyQuotaExceeded(key),
        quotaResetAt: quotaResetAt ? new Date(quotaResetAt).toISOString() : null,
      };
      }));
      return { id: service.id, name: service.name, dailyLimit: service.limit, keys: rows };
    }));

    const vt = quotaServices[0];

    return res.status(200).json({
      ok: true,
      periodStart: periodStart.toISOString(),
      resetAt: resetAt.toISOString(),
      dailyLimit: vt.dailyLimit,
      keys: vt.keys,
      services: quotaServices,
    });
  } catch (error) {
    return serverError(res, error, 'admin/vt-quota');
  }
};
