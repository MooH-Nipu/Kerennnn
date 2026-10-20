'use strict';
const { extractIOC, detectType } = require('./_ioc');
const { isCompleteCorrelationPayload } = require('./_correlation-cache');
const { isFreshCacheRow } = require('./_vt-cache-policy');
const { httpPost, withTimeout } = require('./_http');
const { requireAuth } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { logApiUsage } = require('./_usage');
const { consumeScanBudget } = require('./_scan-budget');
const { assertSafeWebhookDestination } = require('./_webhook-security');
const { getAvailablePlugins, getPluginTimeout } = require('./plugins');
const { getTrustFactor, ispIsHighRiskHoster } = require('./plugins/_helpers');
const { buildVtResult } = require('./plugins/virustotal');
const { parseMalwareBazaar } = require('./plugins/malwarebazaar');

// Reuse a previously-stored correlation for this IP so a re-scan of an
// already-seen IP spends ZERO upstream calls across ALL sources.
// Returns the cached correlate payload, or null when there's no fresh row.
async function corrFromCache(ip) {
  const supabase = getSupabase();
  if (!supabase) return null;
  try {
    const { data: row } = await supabase
      .from('vt_ip_cache')
      .select('corr_payload,vt_verdict,last_scanned_at,first_scanned_at')
      .eq('ip', ip)
      .maybeSingle();
    const p = row?.corr_payload;
    if (isFreshCacheRow(row) && isCompleteCorrelationPayload(p)) return p;
  } catch {
    // fall through to live correlation
  }
  return null;
}

// ── Risk factor collection ────────────────────────────────────────────────
function collectRiskFactors(results) {
  const factors = [];
  for (const r of results) {
    if (r.skipped || r.error) continue;
    const m = r.meta || {};

    if (r.source === 'VirusTotal') {
      const mal = Number(m.Malicious) || 0;
      if (mal >= 1) {
        factors.push({
          type: 'vt_detection',
          severity: mal >= 5 ? 'high' : 'med',
          source: 'VirusTotal',
          message: `${mal}/${Number(m['Total Engines']) || 0} engines flagged malicious`,
          bonus: mal >= 5 ? 10 : 5,
        });
      }
    }

    if (r.source === 'AbuseIPDB') {
      const reports = Number(m['Total Reports']) || 0;
      if (reports >= 25) {
        factors.push({ type: 'many_reports', severity: 'high', source: 'AbuseIPDB', message: `${reports} abuse reports (90 days)`, bonus: 15 });
      } else if (reports >= 10) {
        factors.push({ type: 'many_reports', severity: 'med', source: 'AbuseIPDB', message: `${reports} abuse reports (90 days)`, bonus: 10 });
      }
      const hoster = ispIsHighRiskHoster(m.ISP);
      if (hoster) {
        factors.push({ type: 'hosting_provider', severity: 'med', source: 'AbuseIPDB', message: `Hosted at ${m.ISP} (commonly abused)`, bonus: 10 });
      }
      const usage = String(m['Usage Type'] || '').toLowerCase();
      if (!hoster && (usage.includes('data center') || usage.includes('hosting') || usage.includes('transit'))) {
        factors.push({ type: 'datacenter_usage', severity: 'low', source: 'AbuseIPDB', message: `Usage type: ${m['Usage Type']}`, bonus: 5 });
      }
    }

    if (r.source === 'AlienVault OTX') {
      const families = String(m['Malware Families'] || '');
      if (families && families !== '—') {
        factors.push({ type: 'malware_family', severity: 'high', source: 'AlienVault OTX', message: `Associated malware family: ${families}`, bonus: 10 });
      }
      if (m['Recent Pulse (<30d)'] === 'yes') {
        factors.push({ type: 'recent_pulse', severity: 'med', source: 'AlienVault OTX', message: 'Active pulse within last 30 days', bonus: 5 });
      }
    }

    if (r.source === 'Abuse.ch') {
      const online = Number(m['Online URLs']) || 0;
      if (online > 0) {
        factors.push({ type: 'urlhaus_online', severity: 'high', source: 'Abuse.ch', message: `${online} active malicious URLs on URLhaus`, bonus: 10 });
      }
    }

    if (r.source === 'URLScan.io') {
      if (r.verdict === 'malicious') {
        factors.push({ type: 'urlscan_malicious', severity: 'high', source: 'URLScan.io', message: 'URLScan.io flagged page as malicious', bonus: 12 });
      }
      if (String(m.Tags || '').toLowerCase().includes('phishing')) {
        factors.push({ type: 'urlscan_phishing', severity: 'high', source: 'URLScan.io', message: 'Phishing page detected by URLScan.io', bonus: 12 });
      }
    }

    if (r.source === 'Enrichment') {
      const age = Number(m['Age (days)']);
      if (Number.isFinite(age)) {
        if (age < 30) {
          factors.push({ type: 'new_registration', severity: 'high', source: 'Enrichment', message: `Newly registered (${age} days ago)`, bonus: 10 });
        } else if (age < 90) {
          factors.push({ type: 'new_registration', severity: 'med', source: 'Enrichment', message: `Recently registered (${age} days ago)`, bonus: 5 });
        }
      }
      const org = m.Org || m.ISP || m.ASN || '';
      if (ispIsHighRiskHoster(org)) {
        factors.push({ type: 'hosting_provider', severity: 'med', source: 'Enrichment', message: `High-risk ASN/org: ${org}`, bonus: 10 });
      }
    }
  }

  // Dedupe by factor type — keep highest-bonus instance to prevent double-counting.
  const byType = new Map();
  for (const f of factors) {
    const prev = byType.get(f.type);
    if (!prev || (f.bonus || 0) > (prev.bonus || 0)) byType.set(f.type, f);
  }
  return [...byType.values()];
}

// ── Scoring v2: Optimized confidence pipeline ────────────────────────────
// Implements 8 optimizations from IOC-SCORING-RESEARCH.md:
// 1. Cross-source corroboration bonus
// 2. IOC-type-specific weights
// 3. Warning list pre-filter
// 4. Enrichment as context multiplier
// 5. Time decay (MISP polynomial model)
// 6. Bayesian posterior aggregation
// 7. Sighting tracking
// 8. Source reliability tracking

// ── 3. Warning list pre-filter ───────────────────────────────────────────
const WARNING_LISTS = {
  cdn: ['cloudflare', 'akamai', 'fastly', 'cloudfront', 'cdn77', 'stackpath', 'maxcdn', 'keycdn'],
  dns_resolvers: ['1.1.1.1', '1.0.0.1', '8.8.8.8', '8.8.4.4', '9.9.9.9', '149.112.112.112', '208.67.222.222', '208.67.220.220'],
  tor_exit_url: 'https://check.torproject.org/torbulkexitlist',
  cloud_shared: ['amazon', 'microsoft', 'google cloud', 'oracle cloud', 'digitalocean', 'linode', 'vultr'],
};

function checkWarningList(ioc, enrichmentMeta) {
  // DNS resolvers — exact IP match
  if (WARNING_LISTS.dns_resolvers.includes(ioc)) return { listed: true, reason: 'dns_resolver' };

  // CDN / cloud via ISP/Org name from enrichment
  const org = String(enrichmentMeta?.Org || enrichmentMeta?.ISP || '').toLowerCase();
  if (org) {
    for (const cdn of WARNING_LISTS.cdn) {
      if (org.includes(cdn)) return { listed: true, reason: 'cdn', match: cdn };
    }
  }
  return { listed: false };
}

// ── 2. IOC-type-specific weights ─────────────────────────────────────────
const WEIGHTS_BY_TYPE = {
  ip: {
    'VirusTotal':     0.25,
    'AbuseIPDB':      0.30,
    'Abuse.ch':       0.15,
    'AlienVault OTX': 0.10,
    'URLScan.io':     0.00,
    'Enrichment':     0.00,
  },
  domain: {
    'VirusTotal':     0.25,
    'AbuseIPDB':      0.00,
    'Abuse.ch':       0.20,
    'AlienVault OTX': 0.15,
    'URLScan.io':     0.25,
    'Enrichment':     0.00,
  },
  hash: {
    'VirusTotal':     0.50,
    'AbuseIPDB':      0.00,
    'Abuse.ch':       0.00,
    'MalwareBazaar':  0.20,
    'AlienVault OTX': 0.30,
    'URLScan.io':     0.00,
    'Enrichment':     0.00,
  },
};

const TRUST_KEY_MAP = {
  'VirusTotal': 'TRUST_VT',
  'AbuseIPDB': 'TRUST_ABUSEIPDB',
  'Abuse.ch': 'TRUST_ABUSECH',
  'MalwareBazaar': 'TRUST_MALWAREBAZAAR',
  'AlienVault OTX': 'TRUST_OTX',
  'URLScan.io': 'TRUST_URLSCAN',
  'Enrichment': 'TRUST_ENRICHMENT',
};

function applyTypeWeights(results, iocType) {
  if (!Array.isArray(results)) return [];
  const typeWeights = WEIGHTS_BY_TYPE[iocType] || WEIGHTS_BY_TYPE.ip;
  return results.map(r => {
    if (r.skipped || r.error) return r;
    const w = typeWeights[r.source];
    if (w === undefined) return r; // unknown source — keep original weight
    const trustKey = TRUST_KEY_MAP[r.source];
    const trustFactor = trustKey ? getTrustFactor(trustKey, 1) : 1;
    return { ...r, weight: w * trustFactor };
  });
}

// ── 1. Cross-source corroboration bonus ──────────────────────────────────
function corroborationBonus(results) {
  if (!Array.isArray(results)) return 0;
  const active = results.filter(r => !r.skipped && !r.error && r.verdict !== undefined);
  const malSources = active.filter(r => r.verdict === 'malicious');
  const susSources = active.filter(r => r.verdict === 'suspicious');

  let bonus = 0;

  // Malicious consensus
  if (malSources.length >= 3) bonus += 15;
  else if (malSources.length >= 2) bonus += 10;

  // Diverse source type bonus (unique source names)
  const uniqueMalSources = new Set(malSources.map(r => r.source));
  if (uniqueMalSources.size >= 3) bonus += 5;

  // Suspicious consensus (weaker)
  if (susSources.length >= 3 && malSources.length === 0) bonus += 5;

  return Math.min(bonus, 20);
}

// ── 6. Bayesian posterior aggregation ────────────────────────────────────
function verdictToLikelihood(verdict, sourceWeight) {
  // Likelihood ratios: how much this verdict shifts belief toward malicious
  const baseLR = {
    malicious:  12.0,
    suspicious:  3.0,
    unknown:     1.0,
    clean:       0.15,
  };
  const lr = baseLR[verdict] ?? 1.0;
  // Weight acts as mild reliability adjustment (sqrt to avoid over-dampening)
  return Math.pow(lr, Math.pow(Math.max(0.1, sourceWeight), 0.5));
}

function bayesianConfidence(results, priorOdds) {
  if (!Array.isArray(results) || results.length === 0) return null;
  if (priorOdds === undefined) priorOdds = 0.25; // 20% prior — reasonable base rate
  const active = results.filter(r => !r.skipped && !r.error && r.verdict !== undefined);
  if (active.length === 0) return null;

  let logOdds = Math.log(priorOdds);
  for (const r of active) {
    const lr = verdictToLikelihood(r.verdict, r.weight);
    logOdds += Math.log(lr);
  }
  // Clamp to prevent exp() overflow/underflow
  logOdds = Math.max(-20, Math.min(20, logOdds));
  const posteriorOdds = Math.exp(logOdds);
  return Math.round((posteriorOdds / (1 + posteriorOdds)) * 100);
}

// ── 4. Enrichment as context multiplier ──────────────────────────────────
function enrichmentMultiplier(enrichmentMeta) {
  if (!enrichmentMeta || typeof enrichmentMeta !== 'object') return 1.0;
  let mult = 1.0;

  // High-risk hoster → boost
  const org = enrichmentMeta.Org || enrichmentMeta.ISP || '';
  if (ispIsHighRiskHoster(org)) mult += 0.15;

  // Registration age → boost for new, dampen for old
  const age = Number(enrichmentMeta['Age (days)']);
  if (Number.isFinite(age)) {
    if (age < 30) mult += 0.10;
    else if (age < 90) mult += 0.05;
  }

  return Math.max(0.5, Math.min(1.3, mult));
}

// ── 5. Time decay (MISP polynomial model) ────────────────────────────────
const DECAY_PARAMS = {
  ip:     { tau: 7 * 24,  alpha: 0.5 },   // 7 days, fast decay (volatile)
  domain: { tau: 14 * 24, alpha: 1.5 },   // 14 days, moderate
  hash:   { tau: 90 * 24, alpha: 2.5 },   // 90 days, slow decay (persistent)
};

function decayMultiplier(hoursSinceLastSeen, iocType) {
  if (!Number.isFinite(hoursSinceLastSeen) || hoursSinceLastSeen < 0) return 1.0;
  const params = DECAY_PARAMS[iocType] || DECAY_PARAMS.ip;
  const { tau, alpha } = params;
  if (hoursSinceLastSeen >= tau) return 0;
  return Math.max(0, 1 - Math.pow(hoursSinceLastSeen / tau, alpha));
}

// ── 7. Sighting boost ────────────────────────────────────────────────────
function sightingBoost(scanCount) {
  if (!Number.isFinite(scanCount) || scanCount <= 0) return 0;
  if (scanCount >= 10) return 10;
  if (scanCount >= 5) return 5;
  if (scanCount >= 2) return 3;
  return 0;
}

// ── Orchestrator: optimized confidence pipeline ──────────────────────────
function calculateOptimizedConfidence(results, factors, opts) {
  if (!Array.isArray(results)) results = [];
  const {
    iocType = 'ip',
    enrichmentMeta = null,
    hoursSinceLastSeen = null,
    scanCount = 0,
    priorOdds = 0.1,
  } = opts || {};

  // Apply type-specific weights
  const weighted = applyTypeWeights(results, iocType);

  // Components
  const bayesian = bayesianConfidence(weighted, priorOdds);
  const corrob = corroborationBonus(weighted);
  const riskBonus = Math.min((factors || []).reduce((s, f) => s + (f.bonus || 0), 0), 25);
  const sight = sightingBoost(scanCount);
  const enrichMult = enrichmentMultiplier(enrichmentMeta);
  const decay = decayMultiplier(hoursSinceLastSeen, iocType);

  // Raw confidence: Bayesian + bonuses
  const rawConfidence = (bayesian ?? 0) + corrob + riskBonus + sight;

  // Apply multipliers
  const confidence = Math.min(100, Math.max(0, Math.round(rawConfidence * enrichMult * decay)));

  // Two VT engines plus negative community reputation is conflicting evidence,
  // never clean evidence. Keep it SUSPICIOUS pending cross-source confirmation.
  const vt = weighted.find(r => r.source === 'VirusTotal' && !r.skipped && !r.error);
  const vtEvidenceFloor = iocType === 'ip'
    && Number(vt?.meta?.Malicious) >= 2
    && Number(vt?.meta?.Reputation) < 0 ? 40 : 0;
  const evidenceAdjustedConfidence = Math.max(confidence, vtEvidenceFloor);

  // Single-source guard: cap at 50 if only 1 active source
  const activeSources = weighted.filter(r => !r.skipped && !r.error && r.verdict !== undefined);
  const finalConfidence = activeSources.length <= 1 ? Math.min(evidenceAdjustedConfidence, 50) : evidenceAdjustedConfidence;

  // Stale IOC guard: cap at SUSPICIOUS (40) max for IPs/domains older than 30 days
  const staleCap = (iocType === 'ip' || iocType === 'domain')
    && Number.isFinite(hoursSinceLastSeen) && hoursSinceLastSeen > 30 * 24;
  const cappedConfidence = staleCap ? Math.min(finalConfidence, 40) : finalConfidence;

  return {
    confidence: cappedConfidence,
    bayesian,
    corroboration: corrob,
    riskBonus,
    sightingBoost: sight,
    enrichmentMultiplier: enrichMult,
    decay,
    activeSourceCount: activeSources.length,
    evidenceFloor: vtEvidenceFloor,
    // Backward compat fields (derived from optimized pipeline)
    baseline: bayesian,
    floor: 0, // floors are now implicit in Bayesian + corroboration
    bonus: riskBonus + corrob + sight,
  };
}

// ── Legacy: Weighted confidence + risk floors + factor bonus ──────────────
// Kept for backward compatibility; new code uses calculateOptimizedConfidence.
function calcConfidenceWithFloors(results, factors) {
  const verdictScore = { malicious: 1.0, suspicious: 0.5, unknown: 0.2, clean: 0.0 };

  let weightedSum = 0;
  let totalWeight = 0;
  let maliciousWeight = 0;
  let suspiciousWeight = 0;
  let maliciousCount = 0;
  let suspiciousCount = 0;
  for (const r of results) {
    if (r.skipped || r.error || r.verdict === undefined) continue;
    const w = r.weight;
    const vs = verdictScore[r.verdict] ?? 0;
    weightedSum += vs * w;
    totalWeight += w;
    if (r.verdict === 'malicious') { maliciousWeight += w; maliciousCount++; }
    else if (r.verdict === 'suspicious') { suspiciousWeight += w; suspiciousCount++; }
  }
  if (totalWeight === 0) return { baseline: null, floor: 0, bonus: 0, confidence: null };
  const baseline = Math.round((weightedSum / totalWeight) * 100);

  // Trust-weighted floors — dual condition (absolute weight OR ratio of active weight)
  // so sparse configs (e.g. VT-only) still produce the right floor without over-triggering
  // for low-trust-only source combinations.
  const maliciousRatio = maliciousWeight / totalWeight;
  const suspiciousRatio = suspiciousWeight / totalWeight;
  let floor = 0;
  if      (maliciousWeight >= 0.50 || (maliciousRatio >= 0.60 && maliciousCount >= 2))   floor = 70;
  else if (maliciousWeight >= 0.20 || (maliciousRatio >= 0.50 && maliciousCount >= 1))   floor = 40;
  else if (suspiciousWeight >= 0.50 || (suspiciousRatio >= 0.60 && suspiciousCount >= 2)) floor = 40;
  else if (suspiciousWeight >= 0.25 || (suspiciousRatio >= 0.40 && suspiciousCount >= 1)) floor = 25;

  const bonus = Math.min((factors || []).reduce((sum, f) => sum + (f.bonus || 0), 0), 25);
  const confidence = Math.min(100, Math.max(baseline, floor) + bonus);

  return { baseline, floor, bonus, confidence };
}

// ── MALICIOUS alert webhook (fires when confidence ≥ ALERT_THRESHOLD) ───────
// Best-effort Slack/Teams/Discord (payload auto-detected from URL) or generic
// JSON POST. Fire-and-forget — never blocks or fails the scan response.
const ALERT_THRESHOLD = 70;

function buildAlertText(ioc, type, confidence, factors, resultUrl) {
  const top = (factors || []).slice(0, 3).map(f => `• ${f.message}`).join('\n');
  return `🚨 MALICIOUS IOC detected (${confidence}%)\n` +
    `${String(type).toUpperCase()}: ${ioc}` +
    (top ? `\n${top}` : '') +
    (resultUrl ? `\n${resultUrl}` : '');
}

// Look up the cached row id so the alert can deep-link to /result/:id.
async function lookupStableId(ioc, type) {
  const supabase = getSupabase();
  if (!supabase) return null;
  try {
    if (type === 'ip') {
      const { data } = await supabase.from('vt_ip_cache').select('id').eq('ip', ioc).maybeSingle();
      return data?.id || null;
    }
    const { data } = await supabase.from('vt_ioc_cache').select('id').eq('ioc_type', type).eq('ioc', ioc).maybeSingle();
    return data?.id || null;
  } catch {
    return null;
  }
}

async function fireAlertWebhook(url, ioc, type, confidence, factors) {
  let resultUrl = null;
  const base = process.env.APP_BASE_URL;
  if (base) {
    const id = await lookupStableId(ioc, type);
    if (id) resultUrl = `${base.replace(/\/$/, '')}/result/${id}`;
  }
  const text = buildAlertText(ioc, type, confidence, factors, resultUrl);
  const headers = { 'Content-Type': 'application/json', 'User-Agent': 'Charlie-kerennnn/1.0' };
  let body;
  if (/hooks\.slack\.com/i.test(url)) body = JSON.stringify({ text });
  else if (/discord(?:app)?\.com\/api\/webhooks/i.test(url)) body = JSON.stringify({ content: text });
  else if (/webhook\.office\.com|office365\.com|outlook\.office/i.test(url)) body = JSON.stringify({ text });
  else body = JSON.stringify({ ioc, type, confidence, riskFactors: (factors || []).slice(0, 5), resultUrl });
  try {
    const destination = await assertSafeWebhookDestination(url);
    // Pin validated DNS answer into actual request to prevent DNS rebinding.
    await httpPost(destination.url, body, headers, { timeout: 5000, lookup: destination.lookup });
  } catch {
    /* best-effort */
  }
}

// Resolve the webhook to fire for this request: the scanning user's own webhook
// (from user_webhooks) takes precedence; otherwise fall back to a global
// ALERT_WEBHOOK_URL env. The per-user min_confidence overrides ALERT_THRESHOLD.
async function maybeFireAlert(req, ioc, type, confidence, factors) {
  let url = null;
  let threshold = ALERT_THRESHOLD;

  const supabase = getSupabase();
  const userId = req && req.auth ? req.auth.userId : null;
  if (supabase && userId) {
    try {
      const { data } = await supabase
        .from('user_webhooks')
        .select('webhook_url, enabled, min_confidence')
        .eq('user_id', userId)
        .maybeSingle();
      if (data && data.enabled && data.webhook_url) {
        url = data.webhook_url;
        if (Number.isFinite(data.min_confidence)) threshold = data.min_confidence;
      }
    } catch {
      /* fall through to env fallback */
    }
  }
  if (!url && process.env.ALERT_WEBHOOK_URL) url = process.env.ALERT_WEBHOOK_URL;
  if (!url || !(confidence >= threshold)) return;
  await fireAlertWebhook(url, ioc, type, confidence, factors);
}

// ── Handler ───────────────────────────────────────────────────────────────
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const { ioc: rawIoc } = req.query;
  if (!rawIoc) return res.status(400).json({ error: 'Missing ?ioc= param.' });

  const ioc = extractIOC(rawIoc);
  const type = detectType(ioc);
  if (!type) return res.status(400).json({ error: `Cannot detect IOC type for: "${ioc}"` });

  // Re-scan short-circuit: an IP already correlated within the cache TTL is served
  // straight from its stored correlation — no source is re-called, so nothing is
  // logged to api_usage and no duplicate alert fires. This makes a repeat IP scan
  // cost ZERO upstream calls across ALL sources, exactly like the VT cache reuse.
  if (type === 'ip') {
    const cachedCorr = await corrFromCache(ioc);
    if (cachedCorr) return res.status(200).json(cachedCorr);
  }

  if (!consumeScanBudget(req, res, 'correlate')) return;

  // Fetch scan count for sighting boost. Live source checks are a fresh sighting,
  // so their evidence age is zero regardless of the previous cache timestamp.
  const supabase = getSupabase();
  let scanMeta = { scanCount: 0 };
  if (supabase) {
    try {
      const table = type === 'ip' ? 'vt_ip_cache' : 'vt_ioc_cache';
      const query = supabase.from(table).select('scan_count');
      const { data } = type === 'ip'
        ? await query.eq('ip', ioc).maybeSingle()
        : await query.eq('ioc_type', type).eq('ioc', ioc).maybeSingle();
      if (data) scanMeta.scanCount = Number(data.scan_count) || 0;
    } catch { /* best-effort, don't block correlation */ }
  }

  // Plugin loop: every source that supports this IOC type and is configured runs
  // in parallel, each wrapped in its own timeout (URLScan gets 45s for the
  // submit+poll cycle, everything else 15s).
  const plugins = getAvailablePlugins(type);
  const results = await Promise.all(
    plugins.map(p =>
      withTimeout(p.check(ioc, type), getPluginTimeout(p), p.name)
        .catch(e => ({ source: p.name, error: e.message || 'timed out', skipped: false }))
    )
  );

  // Only send sources that actually ran — skip sources with missing API keys
  // or unsupported IOC types so the client never sees "SKIPPED" rows. Strip the
  // internal `keyPrefix` (used only for usage logging below) so no key fragment
  // is ever returned to the client or persisted into corr_payload.
  const visibleResults = results
    .filter(r => !r.skipped)
    .map(r => {
      const clone = { ...r };
      delete clone.keyPrefix;
      return clone;
    });

  const riskFactors = collectRiskFactors(results);

  // Check warning list (CDN, DNS resolver, etc.)
  const enrichmentResult = results.find(r => r.source === 'Enrichment' && !r.skipped && !r.error);
  const warningListResult = checkWarningList(ioc, enrichmentResult?.meta);

  // Sources above just ran (or VT was accepted within cache TTL): current evidence
  // is a fresh sighting. Previous scan age must not decay newly fetched evidence.
  const hoursSinceLastSeen = 0;
  const optimized = calculateOptimizedConfidence(results, riskFactors, {
    iocType: type,
    enrichmentMeta: enrichmentResult?.meta,
    hoursSinceLastSeen,
    scanCount: scanMeta.scanCount,
  });

  // Legacy confidence (for backward compat in response)
  const legacy = calcConfidenceWithFloors(results, riskFactors);

  // Use optimized confidence as primary, legacy as fallback
  const confidence = optimized.confidence ?? legacy.confidence;
  const baseline = optimized.baseline ?? legacy.baseline;
  const floor = Math.max(legacy.floor, optimized.evidenceFloor);
  const bonus = legacy.bonus;

  const activeWeights = results
    .filter(r => !r.skipped && !r.error && r.verdict !== undefined)
    .reduce((sum, r) => sum + r.weight, 0);

  // Fire-and-forget MALICIOUS alert (per-user webhook, else env fallback) —
  // does not block or fail the scan response.
  if (Number.isFinite(confidence)) {
    maybeFireAlert(req, ioc, type, confidence, riskFactors).catch(() => {});
  }

  // Telemetry: log each source that actually performed an external call. The IP
  // VirusTotal result is reused from vt.js's cache (no call here), so it's logged
  // by vt.js, not double-counted here.
  logApiUsage(
    req,
    results
      .filter(r => !r.skipped && !(r.source === 'VirusTotal' && type === 'ip'))
      .map(r => ({
        service: r.source,
        ioc_type: type,
        outcome: r.error ? (/rate limit|429|quota/i.test(r.error) ? 'rate_limited' : 'error') : 'ok',
        api_key: r.keyPrefix || null,
      }))
  ).catch(() => {});

  const responsePayload = {
    ioc,
    type,
    confidence,
    baselineConfidence: baseline,
    floor,
    bonus,
    activeWeights,
    riskFactors,
    sources: visibleResults,
    // Versioned scoring metadata invalidates stale cached methodology.
    scoring: {
      version: 4,
      bayesian: optimized.bayesian,
      evidenceFloor: optimized.evidenceFloor,
      corroboration: optimized.corroboration,
      enrichmentMultiplier: optimized.enrichmentMultiplier,
      decay: optimized.decay,
      sightingBoost: optimized.sightingBoost,
      activeSourceCount: optimized.activeSourceCount,
      warningList: warningListResult.listed ? warningListResult : undefined,
    },
  };

  // Persist only server-calculated correlation. Never trust client-supplied verdicts.
  if (supabase) {
    try {
      const cacheRow = { corr_confidence: confidence, corr_payload: responsePayload };
      if (type === 'ip') {
        await supabase.from('vt_ip_cache').update(cacheRow).eq('ip', ioc);
      } else {
        await supabase.from('vt_ioc_cache').update(cacheRow).eq('ioc_type', type).eq('ioc', ioc);
      }
    } catch { /* best-effort; scan response remains authoritative */ }
  }

  return res.status(200).json(responsePayload);
};

// Exposed for unit tests.
module.exports.collectRiskFactors = collectRiskFactors;
module.exports.calcConfidenceWithFloors = calcConfidenceWithFloors;
module.exports.checkWarningList = checkWarningList;
module.exports.corroborationBonus = corroborationBonus;
module.exports.bayesianConfidence = bayesianConfidence;
module.exports.enrichmentMultiplier = enrichmentMultiplier;
module.exports.decayMultiplier = decayMultiplier;
module.exports.sightingBoost = sightingBoost;
module.exports.applyTypeWeights = applyTypeWeights;
module.exports.calculateOptimizedConfidence = calculateOptimizedConfidence;
// Source check helpers now live in ./plugins; re-export for backward compat.
module.exports.buildVtResult = buildVtResult;
module.exports.parseMalwareBazaar = parseMalwareBazaar;
