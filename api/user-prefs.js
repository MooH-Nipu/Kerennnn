'use strict';
const { requireAuth, readJsonBody } = require('./_auth');
const { getSupabase } = require('./_supabase');
const { serverError } = require('./_errors');

const KNOWN_TABS = [
  'dashboard', 'formatter', 'json', 'merger', 'ioc-scan', 'history',
  'pac-filter', 'daily-eod', 'admin-users', 'admin-logs', 'ir-manager',
  'cve', 'attack', 'settings', 'admin-usage',
];
const KNOWN_GROUPS = ['work', 'operations', 'utilities', 'admin'];
const GROUP_ID_RE = /^[a-z0-9][a-z0-9-]{0,31}$/;

function sanitizeIds(arr) {
  if (!Array.isArray(arr)) return [];
  const seen = new Set();
  return arr.filter(id => typeof id === 'string' && KNOWN_TABS.includes(id) && !seen.has(id) && seen.add(id));
}

function sanitizeLabels(value, allowedIds) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  const out = {};
  for (const [id, raw] of Object.entries(value)) {
    if (!allowedIds.includes(id) || typeof raw !== 'string' || [...raw].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)) continue;
    const label = raw.trim().slice(0, 24);
    if (label) out[id] = label;
  }
  return out;
}

function cleanLabel(raw) {
  if (typeof raw !== 'string' || [...raw].some(char => char.charCodeAt(0) < 32 || char.charCodeAt(0) === 127)) return '';
  return raw.trim().slice(0, 24);
}

function sanitizeLayout(value) {
  if (!Array.isArray(value)) return [];
  const seenGroups = new Set();
  const seenTabs = new Set();
  const out = [];
  for (const raw of value.slice(0, 12)) {
    const id = typeof raw?.id === 'string' ? raw.id : '';
    const label = cleanLabel(raw?.label);
    if (!GROUP_ID_RE.test(id) || seenGroups.has(id) || !label) continue;
    seenGroups.add(id);
    const tabs = sanitizeIds(raw.tabs).filter(tab => tab !== 'settings' && !seenTabs.has(tab) && seenTabs.add(tab));
    out.push({ id, label, tabs });
  }
  return out;
}

function sanitizeTutorialDismissed(value) {
  return value === true;
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'GET, PUT, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!requireAuth(req, res)) return;

  const supabase = getSupabase();
  if (!supabase) return res.status(503).json({ error: 'Supabase is not configured (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY).' });
  const userId = req.auth.userId;

  if (req.method === 'GET') {
    const { data, error } = await supabase
      .from('user_prefs')
      .select('tab_order, hidden_tabs, tab_labels, group_labels')
      .eq('user_id', userId)
      .maybeSingle();
    if (error) return serverError(res, error, 'user-prefs GET');
    return res.status(200).json({
      ok: true,
      tab_order: data?.tab_order ?? [],
      hidden_tabs: data?.hidden_tabs ?? [],
      tab_labels: data?.tab_labels ?? {},
      group_labels: sanitizeLabels(data?.group_labels, KNOWN_GROUPS),
      nav_layout: sanitizeLayout(data?.group_labels?.__layout),
      nav_tutorial_dismissed: sanitizeTutorialDismissed(data?.group_labels?.__tutorialDismissed),
    });
  }

  if (req.method === 'PUT') {
    let body;
    try { body = await readJsonBody(req); } catch { return res.status(400).json({ error: 'Invalid JSON.' }); }
    const values = {
      user_id: userId,
      hidden_tabs: sanitizeIds(body?.hidden_tabs).filter(id => id !== 'settings'),
      updated_at: new Date().toISOString(),
    };
    if ('tab_order' in (body || {})) values.tab_order = sanitizeIds(body.tab_order);
    if ('tab_labels' in (body || {})) values.tab_labels = sanitizeLabels(body.tab_labels, KNOWN_TABS);
    if ('group_labels' in (body || {}) || 'nav_layout' in (body || {})) {
      values.group_labels = {
        ...sanitizeLabels(body?.group_labels, KNOWN_GROUPS),
        __layout: sanitizeLayout(body?.nav_layout),
        __tutorialDismissed: sanitizeTutorialDismissed(body?.nav_tutorial_dismissed),
      };
    }
    const { data, error } = await supabase
      .from('user_prefs')
      .upsert(
        values,
        { onConflict: 'user_id' }
      )
      .select('tab_order, hidden_tabs, tab_labels, group_labels')
      .single();
    if (error) return serverError(res, error, 'user-prefs PUT');
    return res.status(200).json({
      ok: true,
      ...data,
      group_labels: sanitizeLabels(data?.group_labels, KNOWN_GROUPS),
      nav_layout: sanitizeLayout(data?.group_labels?.__layout),
      nav_tutorial_dismissed: sanitizeTutorialDismissed(data?.group_labels?.__tutorialDismissed),
    });
  }

  return res.status(405).json({ error: 'Method not allowed.' });
};

module.exports.sanitizeIds = sanitizeIds;
module.exports.sanitizeLabels = sanitizeLabels;
module.exports.sanitizeLayout = sanitizeLayout;
module.exports.sanitizeTutorialDismissed = sanitizeTutorialDismissed;
