const crypto = require('crypto');

const COOKIE_NAME = 'soc_session';

function b64urlEncode(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '');
}

function b64urlDecodeToBuffer(s) {
  const str = String(s || '').replace(/-/g, '+').replace(/_/g, '/');
  const pad = str.length % 4 === 0 ? 0 : 4 - (str.length % 4);
  const padded = str + '='.repeat(pad);
  return Buffer.from(padded, 'base64');
}

function timingSafeEqual(a, b) {
  const ab = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

function signHmacSha256(secret, msg) {
  return b64urlEncode(crypto.createHmac('sha256', secret).update(String(msg)).digest());
}

function parseCookies(req) {
  const raw = String(req.headers?.cookie || '');
  const out = {};
  raw.split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i < 0) return;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (!k) return;
    try { out[k] = decodeURIComponent(v); } catch { /* malformed cookie entry: ignore */ }
  });
  return out;
}

function readCookie(req, name) {
  return parseCookies(req)[name];
}

function envBool(key, defaultValue) {
  const v = process.env[key];
  if (v == null || v === '') return defaultValue;
  return String(v).toLowerCase() === '1' || String(v).toLowerCase() === 'true' || String(v) === 'yes';
}

function positiveIntEnv(key, fallback) {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  const n = Number.parseInt(String(raw), 10);
  return Number.isFinite(n) && n > 0 ? n : fallback;
}

function getSessionTtlSeconds() {
  return Math.max(60, positiveIntEnv('SESSION_TTL_MINUTES', 120)) * 60;
}

function getSessionRefreshWindowSeconds() {
  const ttl = getSessionTtlSeconds();
  return Math.min(ttl, Math.max(30, positiveIntEnv('SESSION_REFRESH_MINUTES', 30) * 60));
}

function buildSetCookie(value, opts = {}) {
  const secure =
    opts.secure !== undefined ? !!opts.secure : envBool('COOKIE_SECURE', process.env.NODE_ENV === 'production');
  const maxAge = typeof opts.maxAge === 'number' ? Math.max(0, Math.floor(opts.maxAge)) : getSessionTtlSeconds();
  const sameSite = opts.sameSite || 'Lax';

  let s = `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; SameSite=${sameSite}`;
  if (secure) s += '; Secure';
  if (maxAge > 0) s += `; Max-Age=${maxAge}`;
  return s;
}

function buildClearCookie() {
  // expire immediately
  return `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0`;
}

function makeSessionToken(payload, secret, ttlSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const ttl = typeof ttlSeconds === 'number' && ttlSeconds > 0 ? ttlSeconds : getSessionTtlSeconds();
  const inputExp = payload && typeof payload.exp === 'number' ? payload.exp : null;
  const body = {
    ...payload,
    iat: now,
    exp: inputExp != null ? inputExp : now + ttl,
  };
  const json = JSON.stringify(body);
  const msg = b64urlEncode(json);
  const sig = signHmacSha256(secret, msg);
  return `${msg}.${sig}`;
}

function verifySessionToken(token, secret) {
  const t = String(token || '');
  const parts = t.split('.');
  if (parts.length !== 2) return { ok: false, error: 'bad_token' };
  const [msg, sig] = parts;
  const expected = signHmacSha256(secret, msg);
  if (!timingSafeEqual(expected, sig)) return { ok: false, error: 'bad_sig' };

  let payload;
  try {
    payload = JSON.parse(b64urlDecodeToBuffer(msg).toString('utf8'));
  } catch {
    return { ok: false, error: 'bad_payload' };
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = payload && typeof payload.exp === 'number' ? payload.exp : null;
  if (exp != null && now > exp) return { ok: false, error: 'expired' };

  return { ok: true, payload };
}

function getAuthSecret() {
  return process.env.APP_AUTH_SECRET || '';
}

function requireAuth(req, res) {
  if (req.authCurrent === true && req.auth) return true;
  const secret = getAuthSecret();
  if (!secret) {
    res.statusCode = 503;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Auth not configured (APP_AUTH_SECRET).' }));
    return false;
  }
  const token = readCookie(req, COOKIE_NAME);
  if (!token) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return false;
  }
  const v = verifySessionToken(token, secret);
  if (!v.ok) {
    res.statusCode = 401;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Set-Cookie', buildClearCookie());
    res.end(JSON.stringify({ error: 'Session expired. Please sign in again.', reason: v.error }));
    return false;
  }
  req.auth = v.payload;

  const now = Math.floor(Date.now() / 1000);
  const exp = v.payload.exp || 0;
  const ttl = getSessionTtlSeconds();
  if (ttl > 0 && exp - now <= getSessionRefreshWindowSeconds()) {
    const refreshed = makeSessionToken(
      { userId: v.payload.userId, role: v.payload.role, username: v.payload.username },
      secret,
      ttl
    );
    res.setHeader('Set-Cookie', buildSetCookie(refreshed, { maxAge: ttl }));
  }

  return true;
}

function requireRole(req, res, allowedRoles) {
  if (!requireAuth(req, res)) return false;
  if (!allowedRoles.includes(req.auth.role)) {
    res.statusCode = 403;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ error: 'Forbidden' }));
    return false;
  }
  return true;
}

function validateCurrentIdentity(tokenAuth, dbUser, allowedRoles) {
  if (!tokenAuth?.userId || !dbUser || dbUser.id !== tokenAuth.userId) return { ok: false, status: 401 };
  if (!allowedRoles.includes(dbUser.role)) return { ok: false, status: 403 };
  return {
    ok: true,
    auth: { userId: dbUser.id, role: dbUser.role, username: dbUser.username },
  };
}

function shouldRevalidateRoute(route) {
  return !['/api/health', '/api/auth/login', '/api/auth/logout'].includes(route);
}

async function revalidateRequestIdentity(req, res, supabase) {
  if (!shouldRevalidateRoute(req.path)) return true;
  if (!requireAuth(req, res)) return false;
  const tokenExp = req.auth.exp || 0;
  const { data, error } = await supabase
    .from('app_users')
    .select('id,username,role')
    .eq('id', req.auth.userId)
    .maybeSingle();
  if (error) {
    res.status(503).json({ error: 'Unable to validate current account.' });
    return false;
  }
  const result = validateCurrentIdentity(req.auth, data, ['admin', 'soc_lead', 'pac', 'charlie', 'l1', 'l2']);
  if (!result.ok) {
    res.setHeader('Set-Cookie', buildClearCookie());
    res.status(401).json({ error: 'Session account no longer exists.' });
    return false;
  }
  req.auth = result.auth;
  req.authCurrent = true;
  const ttl = getSessionTtlSeconds();
  const now = Math.floor(Date.now() / 1000);
  if (ttl > 0 && tokenExp - now <= getSessionRefreshWindowSeconds()) {
    const refreshed = makeSessionToken(result.auth, getAuthSecret(), ttl);
    res.setHeader('Set-Cookie', buildSetCookie(refreshed, { maxAge: ttl }));
  }
  return true;
}

async function requireCurrentRole(req, res, supabase, allowedRoles) {
  if (!requireAuth(req, res)) return false;
  if (req.authCurrent === true) {
    if (allowedRoles.includes(req.auth.role)) return true;
    res.status(403).json({ error: 'Forbidden' });
    return false;
  }
  const { data, error } = await supabase
    .from('app_users')
    .select('id,username,role')
    .eq('id', req.auth.userId)
    .maybeSingle();
  if (error) {
    res.status(503).json({ error: 'Unable to validate current account.' });
    return false;
  }
  const result = validateCurrentIdentity(req.auth, data, allowedRoles);
  if (!result.ok) {
    res.setHeader('Set-Cookie', buildClearCookie());
    res.status(result.status).json({ error: result.status === 401 ? 'Session account no longer exists.' : 'Forbidden' });
    return false;
  }
  req.auth = result.auth;
  return true;
}

async function readJsonBody(req) {
  if (req.body != null && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => {
      raw += c;
      if (raw.length > 2e6) req.destroy(new Error('Body too large'));
    });
    req.on('end', () => {
      if (!raw.trim()) return resolve({});
      try {
        resolve(JSON.parse(raw));
      } catch (e) {
        reject(e);
      }
    });
    req.on('error', reject);
  });
}

module.exports = {
  COOKIE_NAME,
  buildSetCookie,
  buildClearCookie,
  makeSessionToken,
  verifySessionToken,
  requireAuth,
  requireRole,
  requireCurrentRole,
  validateCurrentIdentity,
  shouldRevalidateRoute,
  revalidateRequestIdentity,
  readJsonBody,
};

