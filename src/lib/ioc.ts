import type { IocType } from '../types/vt';

export function extractIOC(raw: string): string {
  let s = String(raw ?? '').trim();
  s = s.replace(/^\[|\]$/g, '');
  s = s.replace(/^hxxps?/i, 'https');
  s = s.replace(/\[\.\]/g, '.').replace(/\(dot\)/gi, '.');

  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).hostname;
    } catch {
      s = s.replace(/^https?:\/\//i, '').split('/')[0];
    }
  }

  s = s.split('/')[0].split('?')[0].split('#')[0];
  // Only strip port (`:digits`) for IPv4/domain — IPv6 has multiple colons so skip
  if ((s.match(/:/g) ?? []).length <= 1) s = s.replace(/:(\d+)$/, '');
  s = s.replace(/\.$/, '');
  return s.toLowerCase();
}

export function detectType(s: string): IocType {
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
  if (/^[0-9a-f:]{3,39}$/.test(s) && s.includes(':') && s.split(':').length >= 3) return 'ip';
  if (/^[0-9a-f]+$/.test(s) && [32, 40, 56, 64, 96, 128].includes(s.length)) return 'hash';
  if (/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(s)) return 'domain';
  return null;
}

export function parseIocList(raw: string): Array<{ ioc: string; type: IocType }> {
  const seen = new Set<string>();
  const results: Array<{ ioc: string; type: IocType }> = [];
  for (const line of raw.split('\n')) {
    const ioc = extractIOC(line);
    if (!ioc || seen.has(ioc)) continue;
    seen.add(ioc);
    results.push({ ioc, type: detectType(ioc) });
  }
  return results.filter(r => r.type !== null);
}

export function countryFlag(code: string): string {
  if (!code || code.length !== 2) return '';
  return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1f1e6 - 65 + c.charCodeAt(0)));
}

export function calcVerdict(mal: number, sus: number, total: number): { label: string; cls: string } {
  if (!total) return { label: 'UNKNOWN', cls: 'verdict-unknown' };
  if (mal > 3)             return { label: 'MALICIOUS',  cls: 'verdict-malicious' };
  if (mal > 0 || sus > 3) return { label: 'SUSPICIOUS', cls: 'verdict-suspicious' };
  return { label: 'CLEAN', cls: 'verdict-clean' };
}

export function confLabel(score: number | null): string {
  if (score === null || score === undefined) return 'NO DATA';
  if (score >= 70) return 'HIGH RISK';
  if (score >= 40) return 'MEDIUM RISK';
  if (score >= 15) return 'LOW RISK';
  return 'LIKELY CLEAN';
}

export function confClass(score: number | null): string {
  if (score === null || score === undefined) return 'conf-none';
  if (score >= 70) return 'conf-critical';
  if (score >= 40) return 'conf-high';
  if (score >= 15) return 'conf-medium';
  return 'conf-low';
}

export function confToVerdict(score: number | null): { label: string; cls: string } {
  if (score === null || score === undefined) return { label: 'UNKNOWN', cls: 'verdict-unknown' };
  if (score >= 70) return { label: 'MALICIOUS',  cls: 'verdict-malicious' };
  if (score >= 40) return { label: 'SUSPICIOUS', cls: 'verdict-suspicious' };
  if (score >= 15) return { label: 'LOW RISK',   cls: 'verdict-unknown' };
  return { label: 'CLEAN', cls: 'verdict-clean' };
}

export function hashLabel(len: number): string {
  if (len === 32) return 'MD5';
  if (len === 40) return 'SHA1';
  if (len === 64) return 'SHA256';
  if (len === 96) return 'SHA384';
  if (len === 128) return 'SHA512';
  return 'HASH';
}

// ── IOC extraction from free text (logs, JSON, emails, …) ───────────────────

export interface ExtractedIOCs {
  ips: string[];
  domains: string[];
  urls: string[];
  hashes: string[];
  emails: string[];
}

// File extensions the bare-domain regex would otherwise mistake for domains
// (e.g. "report.pdf", "data.json"). Used to drop false-positive domains.
const FILE_EXT_RE =
  /\.(?:exe|dll|sys|bin|bat|cmd|ps1|sh|js|mjs|ts|jsx|tsx|json|csv|tsv|txt|log|xml|html?|css|php|py|rb|go|jar|war|zip|rar|7z|gz|tgz|tar|pdf|docx?|xlsx?|pptx?|rtf|png|jpe?g|gif|svg|ico|webp|bmp|mp[34]|m4a|wav|avi|mov|mkv|md|yml|yaml|ini|conf|cfg|toml|lock)$/i;

// Refang common defang notations so plain regexes match.
function refang(text: string): string {
  return String(text ?? '')
    .replace(/\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\)/gi, '.')
    .replace(/\[:\]|\(:\)/g, ':')
    .replace(/\[\/\]/g, '/')
    .replace(/h(?:xx|XX)p(s?)/g, 'http$1')
    .replace(/f(?:xx|XX)p/g, 'ftp');
}

const uniqSorted = (arr: string[]) => Array.from(new Set(arr)).sort();

// Regex-scan arbitrary text (JSON, logs, anything) for IOCs. Defang-aware;
// classifies and dedupes into IPs, domains, URLs, hashes and emails. Reuses
// detectType() to validate ambiguous domain candidates.
export function extractIOCsFromText(text: string): ExtractedIOCs {
  const src = refang(text);

  const urls = uniqSorted(
    (src.match(/\b(?:https?|ftp):\/\/[^\s"'`<>()[\]{}]+/gi) ?? [])
      .map(u => u.replace(/[.,;:!?)\]}'"]+$/, ''))
  );

  const emails = uniqSorted(
    (src.match(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi) ?? [])
      .map(e => e.toLowerCase())
  );

  const hashes = uniqSorted(
    (src.match(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi) ?? [])
      .map(h => h.toLowerCase())
  );

  const ipv4 = src.match(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g) ?? [];
  const ipv6 = (src.match(/\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi) ?? []).map(s => s.toLowerCase());
  const ips = uniqSorted([...ipv4, ...ipv6]);
  const ipSet = new Set(ips);

  const domains = uniqSorted(
    (src.match(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi) ?? [])
      .map(d => d.toLowerCase())
      .filter(d => detectType(d) === 'domain' && !ipSet.has(d) && !FILE_EXT_RE.test(d))
  );

  return { ips, domains, urls, hashes, emails };
}

// ── IOC span location (for inline highlighting) ─────────────────────────────

export type IOCMatchType = 'url' | 'email' | 'hash' | 'ip' | 'domain';

export interface IOCMatch {
  start: number;
  end: number;
  value: string;
  type: IOCMatchType;
}

// Locate IOCs in `text` as non-overlapping spans against the ORIGINAL string.
// Unlike extractIOCsFromText() this does NOT refang/normalise (that would shift
// character offsets), so the returned start/end stay valid for highlighting the
// exact substrings shown to the user. Higher-priority types claim their span
// first (URL > email > hash > ip > domain) so a domain inside a URL, or an IP
// inside nothing, isn't double-marked.
export function findIOCMatches(text: string): IOCMatch[] {
  const src = String(text ?? '');
  const claimed: IOCMatch[] = [];
  const overlaps = (s: number, e: number) => claimed.some(m => s < m.end && e > m.start);

  const collect = (
    re: RegExp,
    type: IOCMatchType,
    opts?: { trimTrailing?: boolean; validate?: (v: string) => boolean }
  ) => {
    re.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = re.exec(src)) !== null) {
      let value = m[0];
      const start = m.index;
      if (opts?.trimTrailing) value = value.replace(/[.,;:!?)\]}'"]+$/, '');
      const end = start + value.length;
      if (value && !(opts?.validate && !opts.validate(value)) && !overlaps(start, end)) {
        claimed.push({ start, end, value, type });
      }
    }
  };

  collect(/\b(?:https?|ftp):\/\/[^\s"'`<>()[\]{}]+/gi, 'url', { trimTrailing: true });
  collect(/\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b/gi, 'email');
  collect(/\b[a-f0-9]{64}\b|\b[a-f0-9]{40}\b|\b[a-f0-9]{32}\b/gi, 'hash');
  collect(/\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g, 'ip');
  collect(/\b(?:[a-f0-9]{1,4}:){2,7}[a-f0-9]{1,4}\b/gi, 'ip');
  collect(/\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}\b/gi, 'domain', {
    validate: d => detectType(d.toLowerCase()) === 'domain' && !FILE_EXT_RE.test(d.toLowerCase()),
  });

  return claimed.sort((a, b) => a.start - b.start);
}
