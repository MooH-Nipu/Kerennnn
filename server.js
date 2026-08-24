'use strict';
const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
// Only loopback reverse proxy may supply X-Forwarded-For; direct clients cannot spoof req.ip.
app.set('trust proxy', 'loopback');
app.use((req, _res, next) => { req.trustedClientIp = req.ip; next(); });

// Security headers for the Docker deployment.
// CSP is tuned for this Vite SPA: bundled self-hosted JS, inline style attributes
// from React, and Google Fonts. All API calls are same-origin (connect-src 'self').
const CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
  "font-src 'self' https://fonts.gstatic.com",
  "img-src 'self' data: https://urlscan.io",
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
  const ip = req.trustedClientIp || req.socket?.remoteAddress || 'unknown';
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
const { revalidateRequestIdentity } = require('./api/_auth');
const { getSupabase } = require('./api/_supabase');
const { ROUTES: routes } = require('./api/_routes');
const identitySupabase = getSupabase();

for (const [route, handler] of routes) {
  app.all(route, async (req, res) => {
    const unsupportedTeamFilterMethod = route === '/api/v1/team-filter' && !['GET', 'POST', 'DELETE', 'OPTIONS'].includes(req.method);
    const needsIdentity = req.method !== 'OPTIONS' && !unsupportedTeamFilterMethod;
    if (needsIdentity && !identitySupabase && !['/api/health', '/api/auth/login', '/api/auth/logout'].includes(route)) {
      return res.status(503).json({ error: 'Unable to validate current account.' });
    }
    if (needsIdentity && identitySupabase && !await revalidateRequestIdentity(req, res, identitySupabase)) return;
    return handler(req, res);
  });
}

// Static frontend
const dist = path.join(__dirname, 'dist');
app.use(express.static(dist, {
  setHeaders(res, filePath) {
    if (filePath.includes(`${path.sep}assets${path.sep}`)) {
      res.setHeader('Cache-Control', 'public, max-age=31536000, immutable');
    } else if (filePath.includes(`${path.sep}fonts${path.sep}`)) {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    } else if (filePath.endsWith('.html')) {
      res.setHeader('Cache-Control', 'no-cache');
    } else {
      res.setHeader('Cache-Control', 'public, max-age=86400');
    }
  },
}));

// SPA fallback — let React Router handle all non-API paths
app.get('*', (_req, res) => {
  res.setHeader('Cache-Control', 'no-cache');
  res.sendFile(path.join(dist, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`[server] listening on :${PORT}`);
});
