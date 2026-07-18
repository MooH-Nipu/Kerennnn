'use strict';
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Security headers (mirror these in vercel.json for the Vercel deployment).
// CSP is tuned for this Vite SPA: bundled self-hosted JS, inline style attributes
// from React, and Google Fonts. All API calls are same-origin (connect-src 'self').
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data:",
  "connect-src 'self'",
  "frame-ancestors 'none'",
  "base-uri 'self'",
  "form-action 'self'",
  "object-src 'none'",
].join('; ');

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('Content-Security-Policy', CSP);
  next();
});

// JSON body parsing — skip multipart so busboy handlers read the raw stream directly
app.use((req, res, next) => {
  if (req.is('multipart/form-data')) return next();
  express.json({ limit: '10mb' })(req, res, next);
});

// In-memory per-IP rate limiter (100 req/min per IP, 200 burst)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX = 100;
app.use('/api/', (req, res, next) => {
  // Dashboard and admin reads must never be served from browser/CDN cache.
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
    || req.socket?.remoteAddress || 'unknown';
  const now = Date.now();
  const entry = rateLimitStore.get(ip) || { count: 0, reset: now + RATE_LIMIT_WINDOW_MS };
  if (now > entry.reset) { entry.count = 0; entry.reset = now + RATE_LIMIT_WINDOW_MS; }
  entry.count++;
  rateLimitStore.set(ip, entry);
  res.setHeader('X-RateLimit-Limit', RATE_LIMIT_MAX);
  res.setHeader('X-RateLimit-Remaining', Math.max(0, RATE_LIMIT_MAX - entry.count));
  res.setHeader('X-RateLimit-Reset', Math.ceil(entry.reset / 1000));
  if (entry.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: 'Too many requests. Try again later.' });
  }
  // Cleanup old entries every 5 min
  if (Math.random() < 0.01) {
    for (const [k, v] of rateLimitStore) { if (now > v.reset) rateLimitStore.delete(k); }
  }
  next();
});

// API routes
const routes = [
  ['/api/health',                 './api/health.js'],
  ['/api/auth/login',             './api/auth/login.js'],
  ['/api/auth/logout',            './api/auth/logout.js'],
  ['/api/auth/me',                './api/auth/me.js'],
  ['/api/vt',                     './api/vt.js'],
  ['/api/correlate',              './api/correlate.js'],
  ['/api/cve',                    './api/cve.js'],
  ['/api/attack',                 './api/attack.js'],
  ['/api/passive-dns',            './api/passive-dns.js'],
  ['/api/crt',                    './api/crt.js'],
  ['/api/scan-merger',            './api/scan-merger.js'],
  ['/api/scan-history',           './api/scan-history.js'],
  ['/api/user-prefs',             './api/user-prefs.js'],
  ['/api/user-webhook',           './api/user-webhook.js'],
  ['/api/admin/usage',            './api/admin/usage.js'],
  ['/api/admin/ip-scans',         './api/admin/ip-scans.js'],
  ['/api/admin/vt-quota',          './api/admin/vt-quota.js'],
  ['/api/kibana-combined-report', './api/kibana-combined-report.js'],
  ['/api/admin/users',            './api/admin/users.js'],
  ['/api/admin/logs',             './api/admin/logs.js'],
  ['/api/ip-cache/by-id',         './api/ip-cache/by-id.js'],
  ['/api/ip-cache/cleanup',       './api/ip-cache/cleanup.js'],
  ['/api/ip-cache/correlation',   './api/ip-cache/correlation.js'],
  ['/api/ip-cache/recent',        './api/ip-cache/recent.js'],
  ['/api/ir-cases/detail',        './api/ir-cases/detail.js'],
  ['/api/ir-cases',               './api/ir-cases.js'],
];

for (const [route, file] of routes) {
  const handler = require(file);
  app.all(route, (req, res) => handler(req, res));
}

// Static frontend
const dist = path.join(__dirname, 'dist');
app.use(express.static(dist));

// SPA fallback — let React Router handle all non-API paths
app.get('*', (_req, res) => res.sendFile(path.join(dist, 'index.html')));

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[server] listening on :${PORT}`);
});
