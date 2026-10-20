export const MAX_SAMPLE_BYTES = 32 * 1024 * 1024;
export const MAX_REVERSE_CANDIDATES = 5;
export const MAX_RELATION_EDGES = 12;

export async function sha256Sample(file, cryptoApi = globalThis.crypto) {
  if (!file || !Number.isSafeInteger(file.size) || file.size < 0) throw new Error('Invalid sample size.');
  if (file.size > MAX_SAMPLE_BYTES) throw new Error('Sample exceeds 32 MiB limit. Nothing uploaded.');
  if (!cryptoApi?.subtle) throw new Error('Web Crypto SHA-256 unavailable. Use a secure browser context.');
  const bytes = await file.arrayBuffer();
  const digest = await cryptoApi.subtle.digest('SHA-256', bytes);
  return Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
}

const validIp = value => {
  if (typeof value !== 'string') return false;
  const parts = value.split('.');
  return parts.length === 4 && parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255);
};
const validDomain = value => typeof value === 'string' && value.length <= 253 &&
  value.split('.').length >= 2 && value.split('.').every(p => p.length > 0 && p.length <= 63 && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(p));
const host = value => typeof value === 'string' ? value.trim().toLowerCase().replace(/\.$/, '') : '';

// ponytail: IPv4 A-record pairs only; add validated AAAA pairs if provider supplies them.
export function resolutionEdges(root, type, responses) {
  const target = type === 'domain' ? host(root) : root;
  if (type === 'domain' ? !validDomain(target) : !validIp(target)) return [];
  const edges = new Set();
  for (const response of Array.isArray(responses) ? responses : []) {
    if (!response || response.type !== 'domain' || !Array.isArray(response.records)) continue;
    const query = host(response.ioc);
    if (!validDomain(query) || (type === 'domain' && query !== target)) continue;
    for (const row of response.records) {
      const domain = host(row?.host);
      const ip = row?.ip;
      // Domain lookup may return subdomains. Reverse-IP candidate must itself resolve to root IP.
      if (!validDomain(domain) || !validIp(ip) || (type === 'domain' && domain !== target && !domain.endsWith(`.${target}`)) ||
        (type === 'ip' && (domain !== query || ip !== target))) continue;
      edges.add(`${domain}\t${ip}`);
      if (edges.size >= MAX_RELATION_EDGES) break;
    }
    if (edges.size >= MAX_RELATION_EDGES) break;
  }
  return [...edges].map(pair => {
    const [domain, ip] = pair.split('\t');
    return { domain, ip };
  });
}

export function reverseCandidates(response) {
  if (!response || !Array.isArray(response.records)) return [];
  return [...new Set(response.records.map(row => host(row?.host)).filter(validDomain))].slice(0, MAX_REVERSE_CANDIDATES);
}
