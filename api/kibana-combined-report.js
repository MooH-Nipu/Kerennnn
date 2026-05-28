/**
 * Combined DCI / BPRKS / PAC / SMI Excel export (port of coba.py subset).
 * POST multipart: dci, bprks, pac, daily (CSV); pic; reportDate (Y-m-d); defaultAlarmTime (HH:MM or HH:MM:SS) for rows without timestamp (DCI / BPRKS / PAC).
 */

const busboy = require('busboy');
const { parse } = require('csv-parse/sync');
const ExcelJS = require('exceljs');
const { requireAuth } = require('./_auth');

const BPRKS_PAC_RULE = 'Top values of signal.rule.name';
const BPRKS_PAC_SEV = 'Top values of signal.rule.severity';

const OUTPUT_KEYS = ['Date', 'Alarm Name', 'Severity', 'Alarm Time', 'Alarm Taken', 'Min', 'Shift Name'];

// Columns 3-7: Severity, Alarm Time, Alarm Taken, Min, Shift Name
const EOD_CENTER_COLS = new Set([3, 4, 5, 6, 7]);

const SMI_COLUMN_DEFS = [
  { header: 'id',                  key: 'id',            width: 10 },
  { header: 'fullDescription',     key: 'fullDescription', width: 40 },
  { header: 'severity',            key: 'severity',      width: 12 },
  { header: '',                    key: '_blank1',       width: 10 },
  { header: 'attacker',            key: 'attacker',      width: 20 },
  { header: 'target',              key: 'target',        width: 20 },
  { header: '',                    key: '_na1',          width: 10 },
  { header: 'usernameOrderBy',     key: 'usernameOrderBy', width: 20 },
  { header: '',                    key: '_blank2',       width: 10 },
  { header: '',                    key: '_blank3',       width: 10 },
  { header: '',                    key: '_na2',          width: 10 },
  { header: '',                    key: '_blank4',       width: 10 },
  { header: 'startTime - endTime', key: 'timeRange',     width: 22 },
];

const RULE_CANDIDATES = [
  BPRKS_PAC_RULE,
  'Top values of kibana.alert.rule.name',
  'kibana.alert.rule.name: Descending',
  'Rule Name',
  'rule.name',
];
const SEV_CANDIDATES = [
  BPRKS_PAC_SEV,
  'kibana.alert.severity: Descending',
  'signal.rule.severity: Descending',
  'Severity',
  'severity',
];
const TS_CANDIDATES = [
  '@timestamp: Descending',
  'Top values of @timestamp',
  'Top values of @timestamp: Descending',
  'Time',
  '@timestamp',
  'Timestamp',
];

function authEnabled() {
  return !!(process.env.APP_PASSWORD && process.env.APP_AUTH_SECRET);
}

function todayMMDDYYYY() {
  const d = new Date();
  const mm = String(d.getMonth() + 1).padStart(2, '0');
  const dd = String(d.getDate()).padStart(2, '0');
  const y = d.getFullYear();
  return `${mm}/${dd}/${y}`;
}

/** HTML date (YYYY-MM-DD) or MM/DD/YYYY → Date column format MM/DD/YYYY */
function resolveReportDate(raw) {
  const s = raw != null ? String(raw).trim() : '';
  if (!s) return todayMMDDYYYY();
  const iso = s.match(/^(\d{4})-(\d{2})-(\d{2})$/);
  if (iso) return `${iso[2]}/${iso[3]}/${iso[1]}`;
  const us = s.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})$/);
  if (us) {
    const mm = us[1].padStart(2, '0');
    const dd = us[2].padStart(2, '0');
    return `${mm}/${dd}/${us[3]}`;
  }
  return todayMMDDYYYY();
}

/** HH:MM atau HH:MM:SS dari form → Date anchor untuk Alarm Time jika CSV tanpa timestamp */
function resolveDefaultAlarmTime(raw) {
  const s = raw != null ? String(raw).trim() : '';
  if (!s) return new Date(2000, 0, 1, 0, 0, 0);
  const m = s.match(/^(\d{1,2}):(\d{2})(?::(\d{2}))?$/);
  if (!m) return new Date(2000, 0, 1, 0, 0, 0);
  const h = Math.min(23, Math.max(0, parseInt(m[1], 10)));
  const mi = Math.min(59, Math.max(0, parseInt(m[2], 10)));
  const sec = m[3] !== undefined ? Math.min(59, Math.max(0, parseInt(m[3], 10))) : 0;
  return new Date(2000, 0, 1, h, mi, sec);
}

function sniffDelimiter(sample) {
  const firstLine = (sample.split(/\r?\n/).find((l) => l.trim()) || '').trim();
  const commas = (firstLine.match(/,/g) || []).length;
  const semi = (firstLine.match(/;/g) || []).length;
  return semi > commas ? ';' : ',';
}

function parseCsvBuffer(buf) {
  if (!buf || !buf.length) return [];
  const text = buf.toString('utf8');
  if (!text.trim()) return [];
  const delimiter = sniffDelimiter(text.slice(0, 2048));
  return parse(text, {
    columns: true,
    skip_empty_lines: true,
    delimiter,
    relax_column_count: true,
    bom: true,
    trim: true,
  });
}

function firstPresent(row, names) {
  if (!row || typeof row !== 'object') return '';
  for (const name of names) {
    if (!name) continue;
    if (Object.prototype.hasOwnProperty.call(row, name) && row[name] !== undefined && row[name] !== '') {
      return row[name];
    }
  }
  const keys = Object.keys(row);
  for (const name of names) {
    if (!name) continue;
    const found = keys.find((k) => k.trim() === name.trim());
    if (found !== undefined && row[found] !== undefined && row[found] !== '') return row[found];
  }
  return '';
}

function parseTimestampToDate(tsRaw) {
  const now = new Date();
  const s = String(tsRaw ?? '');
  if (!s || s === 'undefined' || s === 'null') return now;

  if (s.includes('@')) {
    const part = s.split('@')[1]?.trim() || '';
    const m = part.match(/^(\d{2}):(\d{2}):(\d{2})(\.\d+)?/);
    if (m) {
      const h = Number(m[1]);
      const mi = Number(m[2]);
      const sec = Number(m[3]);
      const sub = m[4] ? parseFloat(m[4]) : 0;
      const d = new Date(2000, 0, 1, h, mi, sec + sub);
      return isNaN(d.getTime()) ? now : d;
    }
  }
  const m2 = s.match(/\d{2}:\d{2}:\d{2}/);
  if (m2) {
    const [h, mi, sec] = m2[0].split(':').map(Number);
    const d = new Date(2000, 0, 1, h, mi, sec);
    return isNaN(d.getTime()) ? now : d;
  }
  return now;
}

function formatHHMMSS(d) {
  const h = String(d.getHours()).padStart(2, '0');
  const m = String(d.getMinutes()).padStart(2, '0');
  const sec = String(d.getSeconds()).padStart(2, '0');
  return `${h}:${m}:${sec}`;
}

function addMinutesTime(d, mins) {
  const x = new Date(d.getTime() + mins * 60 * 1000);
  return formatHHMMSS(x);
}

function processUsernameOrderBy(val) {
  const s = String(val ?? '').trim();
  return !s || s.toLowerCase() === 'null' ? 'N/A' : s;
}

function processSeverityLogic(severity) {
  const n = parseFloat(severity);
  if (!Number.isNaN(n)) {
    if (n < 4) return 'LOW';
    if (n <= 7) return 'MEDIUM';
    return 'HIGH';
  }
  return String(severity ?? '').toUpperCase();
}

function extractTimeDaily(timestampStr) {
  const m = String(timestampStr).match(/(\d{2}:\d{2}:\d{2})/);
  return m ? m[1] : '00:00:00';
}

function sortDailyById(rows) {
  if (!rows.length || rows[0].id === undefined) return rows;
  return [...rows].sort((a, b) => {
    const ia = Number(a.id);
    const ib = Number(b.id);
    if (!Number.isNaN(ia) && !Number.isNaN(ib)) return ia - ib;
    return String(a.id).localeCompare(String(b.id));
  });
}

function processDci(rows, picName, reportDate, fallbackAlarmTime) {
  const today = reportDate;
  const out = [];
  const fb = fallbackAlarmTime || new Date(2000, 0, 1, 0, 0, 0);
  for (const row of rows) {
    const tsRaw = String(firstPresent(row, ['@timestamp: Descending']) || '');
    const ts = tsRaw.trim() ? parseTimestampToDate(tsRaw) : fb;
    const name = firstPresent(row, ['signal.rule.name: Ascending']);
    const sev = firstPresent(row, ['signal.rule.severity: Descending']);
    out.push({
      Date: today,
      'Alarm Name': name,
      Severity: sev,
      'Alarm Time': formatHHMMSS(ts),
      'Alarm Taken': addMinutesTime(ts, 5),
      Min: 5,
      'Shift Name': picName,
    });
  }
  return out.sort((a, b) => a['Alarm Time'].localeCompare(b['Alarm Time']));
}

function processKibanaBprksPac(rows, picName, reportDate, fallbackAlarmTime) {
  const today = reportDate;
  const out = [];
  const fb = fallbackAlarmTime || new Date(2000, 0, 1, 0, 0, 0);
  for (const row of rows) {
    const valRule = firstPresent(row, RULE_CANDIDATES);
    const valSev = firstPresent(row, SEV_CANDIDATES);
    const tsRaw = String(firstPresent(row, TS_CANDIDATES) || '');
    const ts = tsRaw.trim() ? parseTimestampToDate(tsRaw) : fb;
    out.push({
      Date: today,
      'Alarm Name': valRule || 'N/A',
      Severity: valSev || 'N/A',
      'Alarm Time': formatHHMMSS(ts),
      'Alarm Taken': addMinutesTime(ts, 5),
      Min: 5,
      'Shift Name': picName,
    });
  }
  return out.sort((a, b) => a['Alarm Time'].localeCompare(b['Alarm Time']));
}

function processSmiFromDaily(rows) {
  const sorted = sortDailyById(rows);
  return sorted.map((row) => {
    const tStart = extractTimeDaily(row.startTime ?? '00:00:00');
    const tEnd   = extractTimeDaily(row.endTime   ?? '00:00:00');
    return {
      id:              row.id ?? '',
      fullDescription: String(row.fullDescription ?? '').trim(),
      severity:        processSeverityLogic(row.severity ?? ''),
      _blank1:         '',
      attacker:        String(row.attacker ?? '').trim(),
      target:          String(row.target   ?? '').trim(),
      _na1:            'N/A',
      usernameOrderBy: processUsernameOrderBy(row.usernameOrderBy),
      _blank2:         '',
      _blank3:         '',
      _na2:            'N/A',
      _blank4:         '',
      timeRange:       `${tStart} - ${tEnd}`,
    };
  });
}

function applySheetStyling(sheet, centerCols = new Set()) {
  const thin = {
    top: { style: 'thin' },
    left: { style: 'thin' },
    bottom: { style: 'thin' },
    right: { style: 'thin' },
  };
  sheet.eachRow((row) => {
    row.eachCell((cell) => {
      cell.font = { name: 'Times New Roman', size: 11 };
      cell.border = thin;
      if (centerCols.has(cell.col)) {
        cell.alignment = { horizontal: 'center' };
      }
    });
  });
}

function parseMultipart(req) {
  return new Promise((resolve, reject) => {
    const fields = {};
    const files = {};
    const bb = busboy({
      headers: req.headers,
      limits: { fileSize: 12 * 1024 * 1024, files: 8 },
    });

    bb.on('file', (name, file) => {
      const chunks = [];
      file.on('data', (d) => chunks.push(d));
      file.on('limit', () => file.resume());
      file.on('end', () => {
        files[name] = Buffer.concat(chunks);
      });
    });

    bb.on('field', (name, val) => {
      fields[name] = val;
    });

    bb.on('finish', () => resolve({ fields, files }));
    bb.on('error', reject);
    req.pipe(bb);
  });
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') {
    res.setHeader('Content-Type', 'application/json');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  if (authEnabled() && !requireAuth(req, res)) return;

  let fields;
  let files;
  try {
    ({ fields, files } = await parseMultipart(req));
  } catch (e) {
    res.setHeader('Content-Type', 'application/json');
    return res.status(400).json({ error: e.message || 'Failed to parse multipart body.' });
  }

  const picRaw = fields.shift_name != null ? String(fields.shift_name) : '';
  const picName = picRaw.trim();
  const reportDate = resolveReportDate(fields.report_date);
  const fallbackAlarmTime = resolveDefaultAlarmTime(fields.default_alarm_time);

  const buffers = {
    dci: files.dci,
    bprks: files.bprks,
    pac: files.pac,
    smi: files.smi,
  };

  const anyFile = Object.values(buffers).some((b) => b && b.length);
  if (!anyFile) {
    res.setHeader('Content-Type', 'application/json');
    return res.status(400).json({ error: 'Unggah minimal satu file CSV (DCI, BPRKS, PAC, atau Daily untuk SMI).' });
  }

  const sheets = [];

  try {
    if (buffers.dci && buffers.dci.length) {
      const rows = parseCsvBuffer(buffers.dci);
      const data = processDci(rows, picName, reportDate, fallbackAlarmTime);
      if (data.length) sheets.push({ name: 'DCI', data, centerCols: EOD_CENTER_COLS });
    }
    if (buffers.bprks && buffers.bprks.length) {
      const rows = parseCsvBuffer(buffers.bprks);
      const data = processKibanaBprksPac(rows, picName, reportDate, fallbackAlarmTime);
      if (data.length) sheets.push({ name: 'BPRKS', data, centerCols: EOD_CENTER_COLS });
    }
    if (buffers.pac && buffers.pac.length) {
      const rows = parseCsvBuffer(buffers.pac);
      const data = processKibanaBprksPac(rows, picName, reportDate, fallbackAlarmTime);
      if (data.length) sheets.push({ name: 'PAC', data, centerCols: EOD_CENTER_COLS });
    }
    if (buffers.smi && buffers.smi.length) {
      const rows = parseCsvBuffer(buffers.smi);
      const data = processSmiFromDaily(rows);
      if (data.length) sheets.push({ name: 'SMI', data, columns: SMI_COLUMN_DEFS });
    }
  } catch (e) {
    res.setHeader('Content-Type', 'application/json');
    return res.status(400).json({ error: e.message || 'CSV processing failed.' });
  }

  if (!sheets.length) {
    res.setHeader('Content-Type', 'application/json');
    return res.status(400).json({ error: 'Tidak ada baris data yang valid dari file yang diunggah.' });
  }

  const wb = new ExcelJS.Workbook();
  for (const { name, data, columns, centerCols } of sheets) {
    const sheet = wb.addWorksheet(name);
    sheet.columns = columns ?? OUTPUT_KEYS.map((k) => ({ header: k, key: k, width: 22 }));
    data.forEach((row) => sheet.addRow(row));
    applySheetStyling(sheet, centerCols);
  }

  const buf = await wb.xlsx.writeBuffer();
  const body = Buffer.isBuffer(buf) ? buf : Buffer.from(buf);

  res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
  res.setHeader('Content-Disposition', 'attachment; filename="output_combined.xlsx"');
  return res.status(200).end(body);
};
