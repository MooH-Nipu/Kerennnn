'use strict';
const { getSupabase } = require('../_supabase');
const { requireApiKey } = require('../_apikeys');
const { extractIOC, detectType } = require('../_ioc');
const { isFreshCacheRow } = require('../_vt-cache-policy');
const { labelFromConfidence, vtStats } = require('../_verdict');

const COLS = 'vt_verdict,vt_stats,vt_payload,corr_confidence,corr_payload,last_scanned_at';

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, X-API-Key');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') {
    return res.status(405).json({ ok: false, error: { code: 'METHOD_NOT_ALLOWED', message: 'Use GET.' } });
  }

  const supabase = getSupabase();
  if (!await requireApiKey(req, res, supabase, 'ioc:read')) return;

  const ioc = extractIOC(req.query?.ioc);
  const type = detectType(ioc);
  if (!type) return res.status(400).json({ ok: false, error: { code: 'INVALID_IOC', message: 'Pass ?ioc=8.8.8.8' } });
  if (!req.apiKey.allowedTypes.includes(type)) {
    return res.status(403).json({ ok: false, error: { code: 'TYPE_NOT_ALLOWED', message: `This key cannot read ${type} verdicts.` } });
  }

  const query = type === 'ip'
    ? supabase.from('vt_ip_cache').select(`ip,${COLS}`).eq('ip', ioc).maybeSingle()
    : supabase.from('vt_ioc_cache').select(`ioc,${COLS}`).eq('ioc_type', type).eq('ioc', ioc).maybeSingle();
  const { data, error } = await query;
  if (error) return res.status(503).json({ ok: false, error: { code: 'LOOKUP_FAILED', message: 'Unable to read the cache.' } });
  if (!data) return res.status(404).json({ ok: false, error: { code: 'NOT_CACHED', message: 'Scan this IOC with POST /api/v1/scan first.' } });

  const corr = data.corr_payload || null;
  return res.status(200).json({
    ok: true,
    ioc,
    type,
    cached: true,
    fresh: isFreshCacheRow({ vt_verdict: data.vt_verdict, last_scanned_at: data.last_scanned_at }),
    verdict: labelFromConfidence(corr && corr.confidence),
    confidence: typeof corr?.confidence === 'number' ? corr.confidence : (data.corr_confidence ?? null),
    vt: vtStats({ data: { attributes: data.vt_payload || {} } }),
    sources: Array.isArray(corr?.sources) ? corr.sources.filter(s => !s.skipped) : [],
    riskFactors: Array.isArray(corr?.riskFactors) ? corr.riskFactors : [],
    lastScannedAt: data.last_scanned_at ?? null,
  });
};
