// Client-only, line-delimited syslog. No transport framing or inferred dates.
export const MAX_SYSLOG_CHARS = 262144;
export const MAX_SYSLOG_LINES = 200;
export const MAX_SYSLOG_RECORD_CHARS = 16384;
const facilities = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news', 'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock', 'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7'];
const severities = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Informational', 'Debug'];
const months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
function check(ok, message) { if (!ok) throw new Error(message); }
function dayValid(year, month, day) {
  const leap = year % 4 === 0 && (year % 100 !== 0 || year % 400 === 0);
  return month >= 1 && month <= 12 && day >= 1 && day <= [31, leap ? 29 : 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31][month - 1];
}
function timestamp5424(value) {
  if (value === '-') return null;
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d{1,6})?(Z|[+-]\d{2}:\d{2})$/.exec(value);
  check(m && dayValid(+m[1], +m[2], +m[3]) && +m[4] <= 23 && +m[5] <= 59 && +m[6] <= 59 && (m[7] === 'Z' || (+m[7].slice(1, 3) <= 23 && +m[7].slice(4) <= 59)), 'Invalid RFC 5424 timestamp (calendar date, time, fraction or timezone).');
  return value;
}
function structuredData(text) {
  if (text[0] === '-') return { elements: [], length: 1, raw: '-' };
  check(text[0] === '[', 'Structured data must be NILVALUE (-) or [elements].');
  let i = 0;
  const elements = [], ids = new Set();
  function name() {
    const start = i;
    while (i < text.length && /[\x21-\x7e]/.test(text[i]) && !' =]"'.includes(text[i])) i++;
    const value = text.slice(start, i);
    check(value.length >= 1 && value.length <= 32, 'Structured-data names must contain 1–32 printable ASCII characters (no space, =, ], or quote).');
    return value;
  }
  while (text[i] === '[') {
    i++;
    const id = name();
    check(!ids.has(id), `Duplicate structured-data ID: ${id}.`);
    ids.add(id);
    const params = [], names = new Set();
    while (text[i] === ' ') {
      i++;
      const key = name();
      check(!names.has(key), `Duplicate structured-data parameter: ${key}.`);
      names.add(key);
      check(text.slice(i, i + 2) === '=\"', 'Structured-data parameters require name="value".');
      i += 2;
      let value = '', closed = false;
      while (i < text.length) {
        const char = text[i++];
        if (char === '"') { closed = true; break; }
        if (char === '\\') {
          check(i < text.length, 'Unterminated structured-data escape.');
          // RFC 5424: unknown escapes retain the literal backslash.
          value += '\\"]'.includes(text[i]) ? text[i++] : '\\';
        } else {
          check(char !== ']', 'Escape ] inside structured-data values as \\].');
          value += char;
        }
      }
      check(closed, 'Unterminated structured-data parameter value.');
      params.push({ name: key, value });
    }
    check(text[i] === ']', 'Unterminated or malformed structured-data element.');
    i++;
    elements.push({ id, params });
  }
  return { elements, length: i, raw: text.slice(0, i) };
}
const keyValueStart = /^[A-Za-z_][\w.-]*=/;
function keyValues(text) {
  const fields = [], seen = new Set(), notes = [];
  let i = 0;
  while (i < text.length) {
    while (/\s/.test(text[i] ?? '') && i < text.length) i++;
    if (i === text.length) break;
    const key = /^[A-Za-z_][\w.-]*=/.exec(text.slice(i));
    check(key, `Malformed key-value field at character ${i + 1}; expected key=value.`);
    const name = key[0].slice(0, -1);
    i += key[0].length;
    let value = '';
    if (text[i] === '"') {
      i++;
      let closed = false;
      while (i < text.length) {
        const char = text[i++];
        if (char === '"') { closed = true; break; }
        if (char === '\\' && ['"', '\\'].includes(text[i])) value += text[i++];
        else value += char;
      }
      check(closed, `Unterminated key-value quote for ${name}.`);
      check(i === text.length || /\s/.test(text[i]), `Trailing garbage after quoted key-value field ${name}.`);
    } else {
      const start = i;
      while (i < text.length && !/\s/.test(text[i])) {
        check(text[i] !== '"', `Unexpected quote in unquoted key-value field ${name}.`);
        i++;
      }
      value = text.slice(start, i);
      check(value.length, `Missing key-value value for ${name}; use "" for empty text.`);
    }
    if (seen.has(name)) notes.push(`Duplicate key: ${name}; all occurrences retained in order.`);
    seen.add(name);
    fields.push({ name, value });
  }
  return { fields, notes };
}
function withMessageFields(record, message) {
  if (!keyValueStart.test(message ?? '')) return record;
  const kv = keyValues(message);
  return { ...record, fields: kv.fields, notes: [...record.notes, ...kv.notes] };
}
export function parseSyslogRecord(raw, line = 1) {
  let format = null;
  try {
    check(typeof raw === 'string', 'Record must be text.');
    check(raw.length <= MAX_SYSLOG_RECORD_CHARS, `Record exceeds ${MAX_SYSLOG_RECORD_CHARS} characters.`);
    check(!/[\r\n\u0000]/.test(raw), 'Record contains a newline or NUL.');
    const pri = /^<(0|[1-9]\d{0,2})>/.exec(raw);
    check((pri && +pri[1] <= 191) || (!raw.startsWith('<') && keyValueStart.test(raw)), 'PRI must be <0> through <191>, without leading zeros.');
    const priority = pri ? +pri[1] : null;
    const body = pri ? raw.slice(pri[0].length) : raw;
    const common = { line, raw, valid: true, priority, facility: priority === null ? null : { code: Math.floor(priority / 8), name: facilities[Math.floor(priority / 8)] }, severity: priority === null ? null : { code: priority % 8, name: severities[priority % 8] } };
    if (keyValueStart.test(body)) {
      format = 'Key-value';
      const kv = keyValues(body);
      if (['date', 'time', 'devname', 'devid', 'logid'].every(name => kv.fields.some(field => field.name === name))) format = 'FortiGate / key-value';
      return { ...common, format, fields: kv.fields, notes: ['Vendor key=value syntax; not an RFC envelope. Values stay strings; raw text is preserved.', ...kv.notes] };
    }
    if (/^\d/.test(body)) {
      format = 'RFC 5424';
      const header = /^(\S+) (\S+) (\S+) (\S+) (\S+) (\S+) /.exec(body);
      check(header, 'RFC 5424 requires VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA.');
      const [, version, time, host, app, proc, msgid] = header;
      check(version === '1', `Unsupported RFC 5424 version: ${version}. Expected 1.`);
      for (const [label, value, max] of [['HOSTNAME', host, 255], ['APP-NAME', app, 48], ['PROCID', proc, 128], ['MSGID', msgid, 32]]) {
        check(/^[\x21-\x7e]+$/.test(value) && value.length <= max, `${label} must contain 1–${max} printable ASCII characters or NILVALUE (-).`);
      }
      const timestamp = timestamp5424(time);
      const tail = body.slice(header[0].length);
      const sd = structuredData(tail);
      check(tail.length === sd.length || tail[sd.length] === ' ', 'Expected a space between structured data and message.');
      return withMessageFields({ ...common, format, version: 1, timestamp, hostname: host === '-' ? null : host, appName: app === '-' ? null : app, procId: proc === '-' ? null : proc, msgId: msgid === '-' ? null : msgid, structuredData: sd.elements, structuredDataRaw: sd.raw, message: tail.length === sd.length ? null : tail.slice(sd.length + 1), notes: ['NILVALUE (-) is represented as null; message text is not normalized.'] }, tail.length === sd.length ? null : tail.slice(sd.length + 1));
    }
    format = 'RFC 3164';
    const header = /^([A-Z][a-z]{2}) ( [1-9]|[12]\d|3[01]) (\d{2}):(\d{2}):(\d{2}) ([!-~]+) (.*)$/.exec(body);
    check(header, 'RFC 3164 requires Mmm dd hh:mm:ss HOSTNAME MSG (single-digit day is space-padded).');
    const [, month, day, hour, minute, second, hostname, message] = header;
    // Leap day is possible: the source supplies no year, so never infer one.
    check(months.includes(month) && dayValid(2000, months.indexOf(month) + 1, +day) && +hour <= 23 && +minute <= 59 && +second <= 59, 'Invalid RFC 3164 calendar day or time.');
    check(new TextEncoder().encode(raw).length <= 1024, 'RFC 3164 record exceeds 1024 bytes.');
    const tag = /^([A-Za-z0-9]{1,32})(?:\[(\d+)\])?: ?/.exec(message);
    return withMessageFields({ ...common, format, timestamp: body.slice(0, 15), year: null, timezone: null, hostname, tag: tag?.[1] ?? null, pid: tag?.[2] ?? null, message, content: tag ? message.slice(tag[0].length) : message, notes: ['Year and timezone are absent in RFC 3164; neither is inferred.', 'Tag/PID extracted only for unambiguous alphanumeric TAG[digits]: or TAG: prefixes; message is preserved.'] }, tag ? message.slice(tag[0].length) : message);
  } catch (error) {
    return { line, raw, valid: false, format, error: error.message };
  }
}
export function parseSyslogInput(input) {
  check(typeof input === 'string', 'Input must be text.');
  check(input.length <= MAX_SYSLOG_CHARS, `Input exceeds ${MAX_SYSLOG_CHARS} characters; nothing processed.`);
  const lines = input.split(/\r\n|\n|\r/);
  check(lines.length <= MAX_SYSLOG_LINES, `Input exceeds ${MAX_SYSLOG_LINES} lines; nothing processed.`);
  return lines.flatMap((raw, i) => raw.trim() ? [parseSyslogRecord(raw, i + 1)] : []);
}
export function syslogReadable(records) {
  return records.map(record => {
    const { line, format, valid, raw, fields: vendorFields, ...fields } = record;
    return `Line ${line} · ${format ?? 'Unknown format'} · ${valid ? 'VALID' : 'INVALID'}\n${[...Object.entries(fields).map(([key, value]) => `${key}: ${typeof value === 'string' ? value : JSON.stringify(value, null, 2)}`), ...(vendorFields ?? []).map(({ name, value }) => `${name}: ${value === '' ? '""' : value}`)].join('\n')}\nraw: ${raw}`;
  }).join('\n\n');
}
