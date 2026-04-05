// Shared IOC normalization — keep in sync with VirusTotal / correlate behavior.

function extractIOC(raw) {
  let s = String(raw ?? '').trim();

  s = s.replace(/^\[|\]$/g, '');
  s = s.replace(/^hxxps?/i, 'https');
  s = s.replace(/\[\.\]/g, '.').replace(/\(dot\)/gi, '.');

  if (/^https?:\/\//i.test(s)) {
    try {
      const u = new URL(s);
      s = u.hostname;
    } catch {
      s = s.replace(/^https?:\/\//i, '').split('/')[0];
    }
  }

  s = s.split('/')[0].split('?')[0].split('#')[0];
  s = s.replace(/:(\d+)$/, '');
  s = s.replace(/\.$/, '');

  return s.toLowerCase();
}

function detectType(s) {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
  if (/^[0-9a-f:]{3,39}$/.test(s) && s.includes(':') && s.split(':').length >= 3) return 'ip';
  if (/^[0-9a-f]+$/.test(s) && [32, 40, 56, 64, 96, 128].includes(s.length)) return 'hash';
  if (/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/.test(s)) return 'domain';
  return null;
}

/** Returns normalized IOC string or null if not an IP. */
function normalizeIpLine(raw) {
  const ioc = extractIOC(raw);
  if (detectType(ioc) !== 'ip') return null;
  return ioc;
}

module.exports = { extractIOC, detectType, normalizeIpLine };
