'use strict';

function createScanBudget(limits, windowMs) {
  const entries = new Map();
  return {
    consume(userId, operation, now = Date.now()) {
      if (entries.size > 1000) {
        for (const [key, value] of entries) if (now >= value.resetAt) entries.delete(key);
      }
      const limit = limits[operation];
      if (!Number.isFinite(limit) || limit < 1) return { allowed: false, remaining: 0, retryAfter: Math.ceil(windowMs / 1000) };
      const key = `${userId}:${operation}`;
      let entry = entries.get(key);
      if (!entry || now >= entry.resetAt) entry = { count: 0, resetAt: now + windowMs };
      if (entry.count >= limit) {
        entries.set(key, entry);
        return { allowed: false, remaining: 0, retryAfter: Math.max(1, Math.ceil((entry.resetAt - now) / 1000)) };
      }
      entry.count += 1;
      entries.set(key, entry);
      return { allowed: true, remaining: limit - entry.count, retryAfter: 0 };
    },
  };
}

const scanBudget = createScanBudget({
  vt: Number.parseInt(process.env.SCAN_VT_PER_MINUTE, 10) || 100,
  correlate: Number.parseInt(process.env.SCAN_CORRELATE_PER_MINUTE, 10) || 100,
}, 60_000);

function consumeScanBudget(req, res, operation) {
  const userId = req.auth?.userId || req.auth?.username || 'unknown';
  const result = scanBudget.consume(userId, operation);
  res.setHeader('X-ScanBudget-Remaining', String(result.remaining));
  if (result.allowed) return true;
  res.setHeader('Retry-After', String(result.retryAfter));
  res.status(429).json({ error: { code: 'SCAN_BUDGET_EXCEEDED', message: `Per-user ${operation} scan budget exceeded.`, retryable: true } });
  return false;
}

module.exports = { createScanBudget, consumeScanBudget };
