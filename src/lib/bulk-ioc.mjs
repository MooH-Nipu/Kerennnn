export const MAX_BULK_IOCS = 1000;
export const MAX_BULK_INPUT_CHARS = 256 * 1024;
export const MAX_BULK_LINES = 5000;
export const MAX_SELECTED_IOCS = 100;
export const MAX_SELECTED_DOMAINS = 100;

function normalize(raw) {
  let value = String(raw ?? '').trim().replace(/^\[|\]$/g, '');
  value = value.replace(/^hxxps?/i, 'https').replace(/\[\.\]|\(dot\)/gi, '.');
  if (/^https?:\/\//i.test(value)) {
    try { value = new URL(value).hostname; }
    catch { value = value.replace(/^https?:\/\//i, '').split('/')[0]; }
  }
  value = value.split('/')[0].split('?')[0].split('#')[0];
  if ((value.match(/:/g) ?? []).length <= 1) value = value.replace(/:(\d+)$/, '');
  return value.replace(/\.$/, '').toLowerCase();
}

function typeOf(value, original = '') {
  if (/^https?:\/\//i.test(String(original).replace(/^hxxps?/i, 'https').replace(/\[\.\]|\(dot\)/gi, '.'))) return 'url';
  if (/^(?:\d{1,3}\.){3}\d+$/.test(value) && value.split('.').every(part => Number(part) <= 255)) return 'ip';
  if (/^(?:\d+\.){3}\d+$/.test(value)) return null;
  if (value.includes(':')) {
    try { if (new URL(`http://[${value}]/`).hostname) return 'ip'; } catch { /* invalid IPv6 */ }
  }
  if (/^[0-9a-f]+$/.test(value) && [32, 40, 56, 64, 96, 128].includes(value.length)) return 'hash';
  if (/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+$/.test(value)) return 'domain';
  return null;
}

function jsonScalars(value, output = []) {
  if (Array.isArray(value)) value.forEach(item => jsonScalars(item, output));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => jsonScalars(item, output));
  else if (typeof value === 'string' || typeof value === 'number') output.push(String(value));
  return output;
}

function csvCells(raw) {
  const rows = [];
  let cell = '', row = [], quoted = false;
  for (let i = 0; i < raw.length; i += 1) {
    const char = raw[i];
    if (char === '"') {
      if (quoted && raw[i + 1] === '"') { cell += '"'; i += 1; }
      else quoted = !quoted;
    } else if (!quoted && (char === ',' || char === '\t')) {
      row.push(cell); cell = '';
    } else if (!quoted && (char === '\n' || char === '\r')) {
      if (char === '\r' && raw[i + 1] === '\n') i += 1;
      row.push(cell); rows.push(row); row = []; cell = '';
    } else cell += char;
  }
  if (quoted) throw new Error('Malformed CSV');
  if (cell || row.length) { row.push(cell); rows.push(row); }
  return rows.flatMap(cells => cells.map(value => value.trim()).filter(Boolean));
}

function candidates(raw, format) {
  if (format === 'json') {
    return jsonScalars(JSON.parse(raw));
  }
  const lines = String(raw ?? '').split(/\r?\n/).slice(0, MAX_BULK_LINES).map(line => line.trim()).filter(Boolean);
  return format === 'csv' ? csvCells(String(raw ?? '')) : lines;
}

export function parseBulkIocs(raw, format = 'text') {
  const seen = new Set();
  let selectedCount = 0;
  let selectedDomainCount = 0;
  const bounded = String(raw ?? '').slice(0, MAX_BULK_INPUT_CHARS);
  let values;
  try { values = candidates(bounded, format); }
  catch { return [{ id: '0-invalid', original: bounded.slice(0, 200), normalized: '', type: null, valid: false, duplicate: false, invalidReason: `Malformed ${format.toUpperCase()}`, selected: false }]; }
  return values.slice(0, MAX_BULK_IOCS).map((original, index) => {
    const normalized = normalize(original);
    const type = typeOf(normalized, original);
    const duplicate = !!type && seen.has(normalized);
    if (type && !duplicate) seen.add(normalized);
    const valid = type !== null;
    const isDomain = type === 'domain' || type === 'url';
    const selected = valid && !duplicate && selectedCount < MAX_SELECTED_IOCS && (!isDomain || selectedDomainCount < MAX_SELECTED_DOMAINS);
    if (selected) {
      selectedCount += 1;
      if (isDomain) selectedDomainCount += 1;
    }
    return {
      id: `${index}-${normalized || 'invalid'}`,
      original,
      normalized,
      type,
      valid,
      duplicate,
      invalidReason: valid ? '' : 'Unsupported or invalid IOC',
      selected,
    };
  });
}
