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

// API routes
const routes = [
  ['/api/health',                 './api/health.js'],
  ['/api/auth/login',             './api/auth/login.js'],
  ['/api/auth/logout',            './api/auth/logout.js'],
  ['/api/auth/me',                './api/auth/me.js'],
  ['/api/vt',                     './api/vt.js'],
  ['/api/correlate',              './api/correlate.js'],
  ['/api/scan-merger',            './api/scan-merger.js'],
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
