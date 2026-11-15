// Client-only redaction of log text before it is pasted into an LLM prompt.
// Port of ~/redact.py. Mirrors api/_redact.js semantics; keep the two in step.
// Tokens are «CAT_hmac8» = HMAC(session salt, "CAT\0value") truncated, so the same
// value maps to the same token inside one session and nothing is reversible.

const TOK_L = '\u00ab';
const TOK_R = '\u00bb';
const ESC = '\u0000'; // placeholder envelope while rules run
const MARK = '\u0002'; // resolved-secret marker, swapped for a token at the end

// Shielded BEFORE redaction: these are not secrets and redacting them destroys debug signal.
const ALLOW = [
  // anchored: `corp.example.net` must NOT be shielded by the `example.net` inside it
  '(?<![.\\w-])(?:localhost|example\\.(?:com|org|net)|127\\.0\\.0\\.1|0\\.0\\.0\\.0|::1)(?![.\\w-])',
  'data:[a-z/+.-]+;base64,[A-Za-z0-9+/=]{40,}',
];

// Order matters: leftmost and most specific first, because a match is consumed.
const RULES = [
  ['jwt', 'eyJ[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}\\.[A-Za-z0-9_-]{6,}'],
  ['aws_key', '\\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[0-9A-Z]{16}\\b'],
  ['github', '\\bgh[pousr]_[A-Za-z0-9]{20,}'],
  ['slack', '\\bxox[baprs]-[A-Za-z0-9-]{10,}'],
  ['openai', '\\bsk-[A-Za-z0-9_-]{20,}'],
  ['google', '\\bAIza[0-9A-Za-z_-]{35}\\b'],
  ['stripe', '\\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}'],
  ['webhook', 'https://(?:hooks\\.slack\\.com/services|discord(?:app)?\\.com/api/webhooks|api\\.telegram\\.org/bot)[^\\s"\'<>]+'],
  ['conn_string', '\\b[a-zA-Z][a-zA-Z0-9+.-]{1,15}://[^\\s:/@]{1,64}:[^\\s/@]{1,200}@[^\\s"\'<>]+'],
  // Bounded labels, not [A-Za-z0-9.-]+: the unbounded form is O(n^2) on a run of
  // "a.a.a.a…" (57s at 260KB) because the engine retries every start offset.
  ['email', '\\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\\.){1,8}[A-Za-z]{2,63}\\b'],
  ['phone', '(?:\\+62|62|0)8\\d{7,11}\\b'],
  ['mac', '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b'],
  ['ipv4', '\\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b'],
  ['path_user', '(?:/home/|/Users/)[A-Za-z0-9._-]+|C:\\\\[Uu]sers\\\\[A-Za-z0-9._ -]+'],
  ['numid', '\\b(?:\\d[ -]?){12,18}\\d\\b'],
  ['device', '\\b(?:agt|agent|dev|device|srv|node|host|pod|sensor|gateway|gw)[-_.][A-Za-z0-9._-]*\\d[A-Za-z0-9_-]*'],
];

const STRICT = [
  ['uuid', '\\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\\b'],
  ['uuid32', '\\b[0-9a-f]{32}\\b'],
  ['ipv6', '\\b(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}\\b'],
  // Bounded repetition, not (?:\.x+)*: an unbounded nested quantifier backtracks
  // exponentially on "a.a.a.a…" (4.7s at 40k chars) — a client-side hang from a
  // pasted log. Capped at 8 labels / 63 chars each, which is past any real FQDN.
  ['fqdn', '\\b(?:[a-z0-9][a-z0-9-]{0,62}\\.){1,8}(?:internal|local|localdomain|corp|lan|svc|cluster)\\b'],
  ['arn', '\\barn:aws[^\\s,;"\'<>]+'],
  ['account', '\\b\\d{12}\\b'],
  // Same fix: pods are word-word-<suffix>. Bounded groups, not (?:-[a-z0-9]+)*.
  ['k8s_name', '\\b[a-z][a-z0-9]{0,62}(?:-[a-z0-9]{1,63}){0,8}-[a-z0-9]{5,10}\\b'],
];

// key: value — the KEY survives (structure), only the VALUE dies.
const KV = [
  ['AUTH', /\b((?:proxy-)?authorization)(\s*:\s*)([^\r\n]+)/gi],
  ['COOKIE', /\b((?:set-)?cookie)(\s*:\s*)([^\r\n]+)/gi],
  ['KV', /\b((?:pass(?:word|wd)?|passwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|session[_-]?id|auth[_-]?token|client[_-]?secret|refresh[_-]?token|totp|otp[_-]?seed|signature|cookie|credential|bearer))\b(\s*[:=]\s*["']?)([^\s"',;}]{4,})/gi],
];

// Signed URL params: keep the leading ? or & so the URL still parses.
const SIGNED = /(?<=[?&])(?:x-amz-signature|x-amz-credential|x-amz-security-token|sig|signature|token|access_token|api_key|apikey|key|secret)=[^&\s"'<>]+/gi;

const PEM = /-----BEGIN [A-Z0-9 ]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----[\s\S]*?-----END [A-Z0-9 ]*(?:PRIVATE KEY|OPENSSH PRIVATE KEY)-----/g;

// Entropy fallback. Hex caps at 4.0 bits/char, so hex digests (git SHA, sha256,
// 32-hex request ids) can never trip this; base64 p1 at 24 chars is ~3.9, so
// >=24 chars at >4.1 bits catches real keys and leaves short ids alone.
const ENT = /(?<![\w+/-])([A-Za-z0-9+/_-]{24,}={0,2})(?![\w+/=-])/g;
const ENT_MIN = 24;
const ENT_BITS = 4.1;

const TOKEN = new RegExp(`${TOK_L}[A-Z_]+_[0-9a-f]{8}${TOK_R}`);

function shannon(s) {
  const n = s.length;
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const v of counts.values()) {
    const p = v / n;
    h -= p * Math.log2(p);
  }
  return h;
}

function luhn(digits) {
  let total = 0;
  let alt = false;
  for (let i = digits.length - 1; i >= 0; i -= 1) {
    let n = digits.charCodeAt(i) - 48;
    if (alt) {
      n *= 2;
      if (n > 9) n -= 9;
    }
    total += n;
    alt = !alt;
  }
  return total % 10 === 0;
}

async function hmac8(salt, cat, value) {
  const key = await crypto.subtle.importKey('raw', salt, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(`${cat}\u0000${value.toLowerCase()}`));
  const bytes = new Uint8Array(sig).slice(0, 4);
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

export function newSalt() {
  const salt = new Uint8Array(32);
  crypto.getRandomValues(salt);
  return salt;
}

export function legend() {
  return `${TOK_L}redact${TOK_R} tokens of the form <<CATEGORY_hash>> replaced sensitive values. `
    + 'Identical values share a token; different values never do. '
    + 'Do not guess, reconstruct or invent the original values.\n';
}

/**
 * @param {string} text
 * @param {Uint8Array} salt  stable for the session so tokens stay comparable
 * @param {{strict?: boolean, entities?: string[], terms?: string[]}} [opts]
 * @returns {Promise<{text: string, stats: Record<string, number>}>}
 */
export async function redact(text, salt, opts = {}) {
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    // Fail closed: without Web Crypto there is no irreversible token, so emit nothing.
    throw new Error('Redaction unavailable: Web Crypto needs a secure context (https or localhost).');
  }
  const { strict = false, entities = [], terms = [] } = opts;
  const keep = [];
  const secrets = new Map(); // "CAT\0value" -> marker index
  const tokens = [];
  const stats = {};

  const hold = value => {
    keep.push(value);
    return `${ESC}${keep.length - 1}${ESC}`;
  };

  const emit = (cat, value) => {
    if (TOKEN.test(value)) return value; // already a token -> idempotent re-run
    const key = `${cat}\u0000${value.toLowerCase()}`;
    let idx = secrets.get(key);
    if (idx === undefined) {
      idx = tokens.length;
      secrets.set(key, idx);
      tokens.push({ cat, value });
      stats[cat.toLowerCase()] = (stats[cat.toLowerCase()] || 0) + 1;
    }
    return hold(`${MARK}${idx}${MARK}`);
  };

  const classify = (cat, raw) => {
    if (cat !== 'numid') return emit(cat.toUpperCase(), raw);
    const digits = raw.replace(/[ -]/g, '');
    if (!/^\d+$/.test(digits)) return raw;
    if (digits.length >= 13 && digits.length <= 19 && luhn(digits)) return emit('CARD', raw);
    if (digits.length === 16) return emit('NIK', raw);
    return raw; // 13-digit epochs and short counters must survive
  };

  const applyRules = (input, rules) => {
    let out = input;
    for (const [cat, src] of rules) {
      out = out.replace(new RegExp(src, 'g'), m => classify(cat, m));
    }
    return out;
  };

  let out = String(text).replace(/\u0000/g, '');
  out = out.replace(/\x1b\[[0-9;?]*[ -/]*[@-~]/g, '');

  for (const pattern of ALLOW) out = out.replace(new RegExp(pattern, 'gi'), hold);
  out = out.replace(PEM, m => emit('PRIVATE_KEY', m));

  for (const [list, cat] of [[entities, 'ENTITY'], [terms, 'TERM']]) {
    const names = [...new Set(list.map(n => String(n).trim()).filter(n => n.length >= 3))]
      .sort((a, b) => b.length - a.length);
    for (const name of names) {
      const escaped = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      out = out.replace(new RegExp(`(?<![\\w-])${escaped}(?![\\w-])`, 'gi'), m => emit(cat, m));
    }
  }

  for (const [cat, rx] of KV) {
    out = out.replace(rx, (m, key, sep, value) => `${key}${sep}${emit(cat, value)}`);
  }
  out = out.replace(SIGNED, m => emit('SIGNED_URL', m));

  out = applyRules(out, RULES);
  if (strict) out = applyRules(out, STRICT);

  out = out.replace(ENT, (m, candidate) => (
    candidate.length < ENT_MIN || shannon(candidate) < ENT_BITS ? m : emit('SECRET', candidate)
  ));

  out = out.replace(new RegExp(`${ESC}(\\d+)${ESC}`, 'g'), (m, i) => keep[Number(i)]);

  const resolved = await Promise.all(tokens.map(t => hmac8(salt, t.cat, t.value)));
  out = out.replace(new RegExp(`${MARK}(\\d+)${MARK}`, 'g'),
    (m, i) => `${TOK_L}${tokens[Number(i)].cat}_${resolved[Number(i)]}${TOK_R}`);

  return { text: out, stats };
}
