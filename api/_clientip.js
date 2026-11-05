'use strict';

const net = require('net');

// Only the reverse proxy may assert a client address via CF-Connecting-IP.
// Loopback covers a host-run cloudflared; 172.16/12 covers a cloudflared
// container on a Docker bridge. LAN peers (10/8, 192.168/16, public) must not
// be trusted, otherwise any direct client spoofs its limiter identity.
function isTrustedProxyPeer(ip) {
  // Node may report IPv4 peers as ::ffff:a.b.c.d on dual-stack sockets.
  const s = String(ip || '').replace(/^::ffff:/i, '');
  if (s === '::1' || s.startsWith('127.')) return true;
  const [a, b] = s.split('.').map(Number);
  return a === 172 && b >= 16 && b <= 31;
}

function resolveTrustedClientIp({ peer, header, fallback }) {
  const first = String(header || '').split(',')[0].trim();
  if (isTrustedProxyPeer(peer) && net.isIP(first)) return first;
  return fallback || String(peer || '') || 'unknown';
}

module.exports = { isTrustedProxyPeer, resolveTrustedClientIp };
