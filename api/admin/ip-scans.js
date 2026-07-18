'use strict';
const { requireRole } = require('../_auth');
const { getSupabase } = require('../_supabase');
const { serverError } = require('../_errors');

function pickBucket(from, to) {
  const hours = (to.getTime() - from.getTime()) / (1000 * 60 * 60);
  if (hours <= 36) return '30m';
  if (hours <= 24 * 45) return '1d';
  return '1w';
}

// Display buckets follow WIB while database filtering remains exact UTC timestamps.
function bucketLabel(value, bucket) {
  const date = new Date(new Date(value).getTime() + 7 * 60 * 60 * 1000);
  if (bucket === '30m') date.setUTCMinutes(date.getUTCMinutes() < 30 ? 0 : 30, 0, 0);
  else {
    if (bucket === '1w') date.setUTCDate(date.getUTCDate() - ((date.getUTCDay() + 6) % 7));
    date.setUTCHours(0, 0, 0, 0);
  }
  const pad = (n) => String(n).padStart(2, '0');
  const day = `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())}`;
  return bucket === '30m' ? `${day} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}` : day;
}

async function fetchPages(buildQuery) {
  const pageSize = 1000;
  const rows = [];
  for (let offset = 0; ; offset += pageSize) {
    const { data, error } = await buildQuery().range(offset, offset + pageSize - 1);
    if (error) throw error;
    rows.push(...(data || []));
    if (!data || data.length < pageSize) return rows;
  }
}

function wibDayStart(value) {
  const shifted = new Date(new Date(value).getTime() + 7 * 60 * 60 * 1000);
  return new Date(Date.UTC(
    shifted.getUTCFullYear(),
    shifted.getUTCMonth(),
    shifted.getUTCDate()
  ) - 7 * 60 * 60 * 1000).toISOString();
}

async function fetchAnalyticsRows(supabase, from, to) {
  const { data: firstEvent, error } = await supabase
    .from('ip_scan_events')
    .select('created_at')
    .order('created_at', { ascending: true })
    .limit(1)
    .maybeSingle();
  if (error) throw error;

  // Never mix estimated historical calls and exact events in the same WIB day.
  const cutover = firstEvent ? wibDayStart(firstEvent.created_at) : to;
  const historicalTo = new Date(Math.min(new Date(cutover).getTime(), new Date(to).getTime())).toISOString();
  const historical = new Date(from) < new Date(historicalTo)
    ? await fetchPages(() => supabase
        .from('api_usage')
        .select('username,created_at')
        .eq('service', 'VirusTotal')
        .eq('ioc_type', 'ip')
        .gte('created_at', from)
        .lt('created_at', historicalTo)
        .order('created_at', { ascending: true }))
    : [];

  const trackedFrom = new Date(Math.max(new Date(from).getTime(), new Date(cutover).getTime())).toISOString();
  const tracked = new Date(trackedFrom) < new Date(to)
    ? await fetchPages(() => supabase
        .from('ip_scan_events')
        .select('username,created_at')
        .gte('created_at', trackedFrom)
        .lt('created_at', to)
        .order('created_at', { ascending: true }))
    : [];

  return [
    ...historical.map(row => ({ ...row, source: 'historical VT calls' })),
    ...tracked.map(row => ({ ...row, source: 'tracked scans' })),
  ];
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireRole(req, res, ['admin', 'l2'])) return;
  if (req.method !== 'GET') return res.status(405).json({ error: 'Method not allowed.' });

  const from = new Date(String(req.query?.from || ''));
  const to = new Date(String(req.query?.to || ''));
  if (Number.isNaN(from.getTime()) || Number.isNaN(to.getTime()) || from >= to) {
    return res.status(400).json({ error: 'Valid ISO from and to timestamps are required.' });
  }

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured.' });

  let data;
  try {
    data = await fetchAnalyticsRows(supabase, from.toISOString(), to.toISOString());
  } catch (error) {
    return serverError(res, error, 'admin/ip-scans');
  }

  const bucket = pickBucket(from, to);
  const timelineCounts = new Map();
  const userCounts = new Map();
  for (const row of data) {
    const time = bucketLabel(row.created_at, bucket);
    const entry = timelineCounts.get(time) || { scans: 0, sources: new Set() };
    entry.scans += 1;
    entry.sources.add(row.source);
    timelineCounts.set(time, entry);
    const username = row.username || '(unknown)';
    userCounts.set(username, (userCounts.get(username) || 0) + 1);
  }

  const timeline = [...timelineCounts]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([time, entry]) => ({ time, scans: entry.scans, source: [...entry.sources].join(' + ') }));
  const byUser = [...userCounts]
    .map(([username, scans]) => ({ username, scans, uniqueIps: null }))
    .sort((a, b) => b.scans - a.scans || a.username.localeCompare(b.username));

  return res.status(200).json({
    ok: true,
    total: data.length,
    byUser,
    bucket,
    timeline,
    timelineNote: 'Historical VT calls before scan-event tracking; exact user scan actions afterward. Cache hits count as scans but not VT quota usage.',
  });
};
