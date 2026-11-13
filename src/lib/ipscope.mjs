// Private/reserved IPv4 classification — mirrors api/_ipscope.js (keep in sync).
// Anything true here must never reach the filter DB.

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

export function isPrivateIp(input) {
  const s = String(input ?? '').trim().toLowerCase().replace(/^\[|\]$/g, '');
  const octets = s.split('.');
  const isV4 = octets.length === 4 && octets.every(o => /^\d{1,3}$/.test(o) && Number(o) <= 255);

  if (isV4) {
    const n = v4ToInt(s);
    return V4_BLOCKS.some(([base, prefix]) => {
      const size = 2 ** (32 - prefix);
      return Math.floor(n / size) === Math.floor(v4ToInt(base) / size);
    });
  }

  if (s.includes(':')) {
    if (s === '::' || s === '::1') return true;
    if (/^f[cd]/.test(s)) return true;          // fc00::/7 unique-local
    if (/^fe[89ab]/.test(s)) return true;       // fe80::/10 link-local
    const mapped = s.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    return mapped ? isPrivateIp(mapped[1]) : false;
  }

  return false;
}
