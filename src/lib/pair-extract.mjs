// Turns pasted "label + count" data into [label, count] rows, whatever the layout:
//   - Kibana/Grafana cell dumps (label / count alternating lines, with "Row: n; Column: n" markers)
//   - one pair per line, split by tab, 2+ spaces, space, comma, semicolon or pipe
// A "count" is a number with optional thousands commas; anything else is a label.
// ponytail: a label that is itself a bare number (e.g. port "443") is read as a count.

const MARKER = /^Row:\s*\d+;\s*Column:\s*\d+$/i;
const NUM = /^\d{1,3}(?:,\d{3})+(?:\.\d+)?$|^\d+(?:\.\d+)?$/;
const INLINE = /^(.+?)(?:\t|\s*[;|,]\s*|\s+)"?(\d{1,3}(?:,\d{3})+(?:\.\d+)?|\d+(?:\.\d+)?)"?$/;

export function extractPairs(raw) {
  const rows = [];
  let skipped = 0;
  let pending = null;
  for (const line of String(raw ?? '').split(/\r?\n/).map(s => s.trim())) {
    if (!line || MARKER.test(line)) continue;
    if (NUM.test(line)) {
      if (pending === null) skipped++;
      else { rows.push([pending, line]); pending = null; }
      continue;
    }
    const m = INLINE.exec(line);
    if (m) { rows.push([m[1].replace(/^"|"$/g, '').trim(), m[2]]); pending = null; continue; }
    if (pending !== null) skipped++;
    pending = line;
  }
  if (pending !== null) skipped++;
  return { rows, skipped };
}

export const toTsv = rows => rows.map(r => r.join('\t')).join('\n');
