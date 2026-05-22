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
  s = s.replace(/:(\d+)$/, '');
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

export function hashLabel(len: number): string {
  if (len === 32) return 'MD5';
  if (len === 40) return 'SHA1';
  if (len === 64) return 'SHA256';
  if (len === 96) return 'SHA384';
  if (len === 128) return 'SHA512';
  return 'HASH';
}
