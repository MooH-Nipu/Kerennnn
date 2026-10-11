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

/**
 * Shared-pool quota: all VT keys belong to one VT group with a single daily
 * quota, so usage is summed across keys and measured against one pool limit.
 * Key-level limits stay informational (per-key pacing), not the real ceiling.
 */
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured.' });
  if (!await requireCurrentRole(req, res, supabase, ['admin', 'l2'])) return;

  const now = new Date();
  const resetAt = new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() + 1));
  const periodStart = new Date(resetAt.getTime() - 24 * 60 * 60 * 1000);
  const period = { start: periodStart.toISOString(), end: resetAt.toISOString() };

  const services = [
    {
      id: 'virustotal', name: 'VirusTotal', keys: getVtKeys(),
      limit: positiveInt(process.env.VT_DAILY_QUOTA_PER_KEY, 500),
      poolLimit: positiveInt(process.env.VT_DAILY_QUOTA_TOTAL, null),
      sharedPool: true,
    },
    {
      id: 'abuseipdb', name: 'AbuseIPDB', keys: getAbuseIPDBKeys(),
      limit: positiveInt(process.env.ABUSEIPDB_DAILY_QUOTA_PER_KEY, 1000),
      sharedPool: false,
    },
  ];

  try {
    const quotaServices = await Promise.all(services.map(async (service) => {
      // Pool usage: exact head-count per key prefix (old single fetch capped at
      // Supabase's 1000-row default and silently undercounted the pool exactly
      // when it mattered). Per-key counts already come back exact via count.
      const keyCounts = await Promise.all(service.keys.map(async (key) => {
        const prefix = key.slice(0, 8);
        const { count, error } = await supabase
          .from('api_usage')
          .select('id', { count: 'exact', head: true })
          .eq('service', service.name)
          .like('api_key', `${prefix}%`)
          .gte('created_at', period.start)
          .lt('created_at', period.end);
        if (error) throw error;
        return count || 0;
      }));
      const poolUsed = keyCounts.reduce((sum, n) => sum + n, 0);

      const keyRows = service.keys.map((key, index) => {
        const prefix = key.slice(0, 8);
        const used = keyCounts[index];
        const quotaResetAt = service.id === 'virustotal' ? getVtKeyQuotaResetAt(key) : null;
        return {
          key: `${service.name} key ${index + 1}`,
          prefix: `${prefix}...`,
          used,
          limit: service.limit,
          remaining: Math.max(0, service.limit - used),
          percent: Math.min(100, Math.round((used / service.limit) * 100)),
          poolUsed: service.sharedPool ? poolUsed : undefined,
          poolRemaining: service.sharedPool && service.poolLimit ? Math.max(0, service.poolLimit - poolUsed) : undefined,
          poolPercent: service.sharedPool && service.poolLimit
            ? Math.min(100, Math.round((poolUsed / service.poolLimit) * 100)) : undefined,
          coolingDown: service.id === 'virustotal' && isVtKeyCoolingDown(key),
          quotaExhausted: service.id === 'virustotal' && isVtKeyQuotaExceeded(key),
          quotaResetAt: quotaResetAt ? new Date(quotaResetAt).toISOString() : null,
        };
      });

      return {
        id: service.id,
        name: service.name,
        dailyLimit: service.limit,
        sharedPool: service.sharedPool,
        poolLimit: service.poolLimit || null,
        poolUsed: service.sharedPool ? poolUsed : null,
        poolRemaining: service.sharedPool && service.poolLimit ? Math.max(0, service.poolLimit - poolUsed) : null,
        poolPercent: service.sharedPool && service.poolLimit
          ? Math.min(100, Math.round((poolUsed / service.poolLimit) * 100)) : null,
        keys: keyRows,
      };
    }));

    const vt = quotaServices[0];

    return res.status(200).json({
      ok: true,
      periodStart: period.start,
      resetAt: period.end,
      dailyLimit: vt.dailyLimit,
      sharedPool: vt.sharedPool,
      poolLimit: vt.poolLimit,
      poolUsed: vt.poolUsed,
      poolRemaining: vt.poolRemaining,
      poolPercent: vt.poolPercent,
      keys: vt.keys,
      services: quotaServices,
    });
  } catch (error) {
    return serverError(res, error, 'admin/vt-quota');
  }
};
