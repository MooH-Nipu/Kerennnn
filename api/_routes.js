'use strict';

const ROUTES = [
  ['/api/health', require('./health.js')],
  ['/api/auth/login', require('./auth/login.js')],
  ['/api/auth/logout', require('./auth/logout.js')],
  ['/api/auth/me', require('./auth/me.js')],
  ['/api/vt', require('./vt.js')],
  ['/api/correlate', require('./correlate.js')],
  ['/api/cve', require('./cve.js')],
  ['/api/attack', require('./attack.js')],
  ['/api/passive-dns', require('./passive-dns.js')],
  ['/api/crt', require('./crt.js')],
  ['/api/scan-merger', require('./scan-merger.js')],
  ['/api/v1/team-filter', require('./team-filter.js')],
  ['/api/scan-history', require('./scan-history.js')],
  ['/api/user-prefs', require('./user-prefs.js')],
  ['/api/user-webhook', require('./user-webhook.js')],
  ['/api/admin/usage', require('./admin/usage.js')],
  ['/api/admin/ip-scans', require('./admin/ip-scans.js')],
  ['/api/admin/vt-quota', require('./admin/vt-quota.js')],
  ['/api/kibana-combined-report', require('./kibana-combined-report.js')],
  ['/api/admin/users', require('./admin/users.js')],
  ['/api/admin/logs', require('./admin/logs.js')],
  ['/api/ip-cache/by-id', require('./ip-cache/by-id.js')],
  ['/api/ip-cache/cleanup', require('./ip-cache/cleanup.js')],
  ['/api/ip-cache/recent', require('./ip-cache/recent.js')],
  ['/api/ir-cases/detail', require('./ir-cases/detail.js')],
  ['/api/ir-cases', require('./ir-cases.js')],
];

function getApiRoute(pathname) {
  const entry = ROUTES.find(([route]) => route === pathname);
  return entry ? { path: entry[0], handler: entry[1] } : null;
}

module.exports = { ROUTES, getApiRoute };
