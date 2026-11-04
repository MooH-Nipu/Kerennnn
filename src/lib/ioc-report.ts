import { extractIOCsFromText } from './ioc';
import { parseSyslogInput } from './syslog.mjs';

// Attribute only successfully parsed fields; arbitrary/malformed text stays unknown.
function iocOrigins(src: string): Map<string, Set<string>> {
  const origins = new Map<string, Set<string>>();
  function add(field: string, value: string) {
    for (const values of Object.values(extractIOCsFromText(value))) for (const ioc of values) {
      if (!origins.has(ioc)) origins.set(ioc, new Set());
      origins.get(ioc)!.add(field);
    }
  }
  function jsonFields(value: unknown, prefix = '') {
    const pending: Array<[unknown, string]> = [[value, prefix]];
    while (pending.length) {
      const [item, path] = pending.pop()!;
      if (typeof item === 'string') add(path || '$', item);
      else if (item && typeof item === 'object') {
        for (const [key, child] of Object.entries(item)) {
          const suffix = Array.isArray(item) ? `[${key}]` : /^[A-Za-z_$][\w$]*$/.test(key) ? (path ? `.${key}` : key) : `[${JSON.stringify(key)}]`;
          pending.push([child, path + suffix]);
        }
      }
    }
  }
  try { jsonFields(JSON.parse(src)); return origins; } catch { /* NDJSON or syslog */ }
  for (const [index, line] of src.split(/\r\n|\n|\r/).entries()) {
    if (!line.trim()) continue;
    try { jsonFields(JSON.parse(line), `line[${index + 1}]`); continue; } catch { /* syslog */ }
    try {
      const record = parseSyslogInput(line)[0];
      if (!record?.valid) continue;
      for (const field of record.fields ?? []) add(field.name, field.value);
      const structured = record.structuredData as Array<{ id: string; params: Array<{ name: string; value: string }> }> | undefined;
      for (const element of structured ?? []) for (const param of element.params) add(`${element.id}.${param.name}`, param.value);
    } catch { /* Keep extraction usable even when log validation fails. */ }
  }
  return origins;
}

// Pull every IOC out of arbitrary text and render it as grouped, copy-friendly
// sections (one IOC per line under a "# Group (n)" heading).
export function extractReport(src: string): { out: string; status: { type: 'success' | 'error'; text: string } } {
  const found = extractIOCsFromText(src);
  const groups: Array<[string, string[]]> = [
    ['IPs', found.ips],
    ['Domains', found.domains],
    ['URLs', found.urls],
    ['Hashes', found.hashes],
    ['Emails', found.emails],
  ].filter(([, v]) => v.length > 0) as Array<[string, string[]]>;

  const total = groups.reduce((n, [, v]) => n + v.length, 0);
  if (total === 0) {
    return { out: '', status: { type: 'error', text: 'No IOCs found in the input.' } };
  }

  const origins = iocOrigins(src);
  const out = groups.map(([label, values]) => `# ${label} (${values.length})\n${values.flatMap(value => {
    const fields = origins.get(value);
    return fields?.size ? [...fields].sort().map(field => `${field}=${value}`) : [`[field unknown]=${value}`];
  }).join('\n')}`).join('\n\n');
  const summary = groups.map(([label, v]) => `${v.length} ${label.toLowerCase()}`).join(', ');
  return { out, status: { type: 'success', text: `Found ${total} IOC${total !== 1 ? 's' : ''} — ${summary}.` } };
}

