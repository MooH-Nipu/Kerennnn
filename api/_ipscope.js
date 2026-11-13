// Private/reserved IPv4 classification — the DB-push gate.
// Keep in sync with src/lib/ipscope.mjs.
const { isIP } = require('node:net');

// [base, prefix] — everything a filter DB must never store.
// Deliberately excludes TEST-NET (192.0.2/24, 198.51.100/24, 203.0.113/24):
// those are valid scan targets, not internal infrastructure.
const V4_BLOCKS = [
  ['0.0.0.0', 8],       // "this network"
  ['10.0.0.0', 8],      // RFC1918
  ['100.64.0.0', 10],   // RFC6598 CGNAT
  ['127.0.0.0', 8],     // loopback
  ['169.254.0.0', 16],  // link-local
  ['172.16.0.0', 12],   // RFC1918
  ['192.0.0.0', 24],    // IETF protocol assignments
  ['192.168.0.0', 16],  // RFC1918
  ['224.0.0.0', 4],     // multicast
  ['240.0.0.0', 4],     // reserved + broadcast
];

function v4ToInt(ip) {
  const [a, b, c, d] = ip.split('.').map(Number);
  return ((a * 256 + b) * 256 + c) * 256 + d;
}

function isPrivateIp(input) {
  const s = String(input ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const kind = isIP(s);

  if (kind === 4) {
    const n = v4ToInt(s);
    return V4_BLOCKS.some(([base, prefix]) => {
      const size = 2 ** (32 - prefix);
      return Math.floor(n / size) === Math.floor(v4ToInt(base) / size);
    });
  }

  if (kind === 6) {
    if (s === '::' || s === '::1') return true;
    if (/^f[cd]/.test(s)) return true;          // fc00::/7 unique-local
    if (/^fe[89ab]/.test(s)) return true;       // fe80::/10 link-local
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIp(mapped[1]) : false;
  }

  return false;
}

module.exports = { isPrivateIp };
