import { useState, useEffect } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';
import { extractIOCsFromText } from '../lib/ioc';

interface StatusMsg {
  type: 'success' | 'error' | 'warning' | 'info';
  text: string;
}

type Mode = 'beautify' | 'minify' | 'extract';

// Fixed 2-space indentation for beautified output.
const INDENT = 2;

// Build a friendly error. V8 usually embeds "position N" (and newer engines
// also "line L column C"); we surface line/column either way.
function describeJsonError(err: unknown, src: string): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/line \d+/i.test(msg)) return `Invalid JSON: ${msg}`;
  const m = /position (\d+)/i.exec(msg);
  if (m) {
    const pos = Number(m[1]);
    const upTo = src.slice(0, pos);
    const line = upTo.split('\n').length;
    const col = pos - upTo.lastIndexOf('\n');
    return `Invalid JSON: ${msg} (line ${line}, column ${col}).`;
  }
  return `Invalid JSON: ${msg}`;
}

// Logs are often NDJSON — one JSON object per line. Only treat as NDJSON when
// there are ≥2 lines and EVERY non-empty line parses on its own.
function tryNdjson(
  src: string,
  minify: boolean
): { ok: true; out: string; count: number } | { ok: false } {
  const lines = src.split('\n').map(l => l.trim()).filter(Boolean);
  if (lines.length < 2) return { ok: false };
  const parsed: unknown[] = [];
  for (const line of lines) {
    try {
      parsed.push(JSON.parse(line));
    } catch {
      return { ok: false };
    }
  }
  const out = parsed
    .map(p => (minify ? JSON.stringify(p) : JSON.stringify(p, null, INDENT)))
    .join(minify ? '\n' : '\n\n');
  return { ok: true, out, count: parsed.length };
}

function formatJson(
  src: string,
  minify: boolean
): { ok: true; out: string; status: StatusMsg } | { ok: false; status: StatusMsg } {
  try {
    const parsed = JSON.parse(src);
    return {
      ok: true,
      out: minify ? JSON.stringify(parsed) : JSON.stringify(parsed, null, INDENT),
      status: { type: 'success', text: `Valid JSON — ${minify ? 'minified' : 'beautified'}.` },
    };
  } catch (err) {
    // Fallback: maybe it's a log stream (NDJSON), not one JSON document.
    const nd = tryNdjson(src, minify);
    if (nd.ok) {
      return {
        ok: true,
        out: nd.out,
        status: {
          type: 'success',
          text: `${nd.count} JSON lines ${minify ? 'minified' : 'beautified'} (NDJSON log).`,
        },
      };
    }
    return { ok: false, status: { type: 'error', text: describeJsonError(err, src) } };
  }
}

// Pull every IOC out of arbitrary text and render it as grouped, copy-friendly
// sections (one IOC per line under a "# Group (n)" heading).
function extractReport(src: string): { out: string; status: StatusMsg } {
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

  const out = groups.map(([label, v]) => `# ${label} (${v.length})\n${v.join('\n')}`).join('\n\n');
  const summary = groups.map(([label, v]) => `${v.length} ${label.toLowerCase()}`).join(', ');
  return { out, status: { type: 'success', text: `Found ${total} IOC${total !== 1 ? 's' : ''} — ${summary}.` } };
}

const MODES: Array<{ id: Mode; label: string }> = [
  { id: 'beautify', label: 'Beautify' },
  { id: 'minify', label: 'Minify' },
  { id: 'extract', label: 'Extract IOCs' },
];

export function JsonTab() {
  const [raw, setRaw] = useState('');
  const [output, setOutput] = useState('');
  const [mode, setMode] = useState<Mode>('beautify');
  const [status, setStatus] = useState<StatusMsg | null>(null);

  // Auto-run as the user types — no button to press. Debounced so a partly typed
  // (temporarily invalid) document doesn't flash errors on every keystroke.
  useEffect(() => {
    const src = raw.trim();
    if (!src) {
      setOutput('');
      setStatus(null);
      return;
    }
    const t = setTimeout(() => {
      if (mode === 'extract') {
        const res = extractReport(src);
        setOutput(res.out);
        setStatus(res.status);
        return;
      }
      const res = formatJson(src, mode === 'minify');
      setOutput(res.ok ? res.out : '');
      setStatus(res.status);
    }, 300);
    return () => clearTimeout(t);
  }, [raw, mode]);

  function reset() {
    setRaw('');
    setOutput('');
    setStatus(null);
  }

  const lineCount = raw.split('\n').filter(s => s.trim()).length;
  const isExtract = mode === 'extract';
  const inputLabel = isExtract
    ? 'Input — paste any text, JSON, or logs'
    : 'Input — JSON or JSON log (NDJSON supported)';
  const outputLabel = isExtract ? 'Extracted IOCs' : 'Output';
  const outputPlaceholder = isExtract
    ? 'IPs, domains, URLs, hashes & emails appear here…'
    : 'Formatted JSON appears here…';

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>JSON Beautifier</h2>
        {lineCount > 0 && <span className="line-count">{lineCount} lines</span>}
        <div className="tab-actions tab-actions--inline">
          {MODES.map(m => (
            <button
              key={m.id}
              type="button"
              className={`btn btn-sm ${mode === m.id ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setMode(m.id)}
              aria-pressed={mode === m.id}
            >
              {m.label}
            </button>
          ))}
          <button className="btn btn-sm btn-ghost" onClick={reset} disabled={!raw && !output}>
            Reset
          </button>
        </div>
      </div>

      {status && (
        <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />
      )}

      <div className="formatter-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="raw-json">
            {inputLabel}
          </label>
          <textarea
            id="raw-json"
            className="form-textarea"
            placeholder={'{"level":"info","msg":"login ok","user":"charlie","ts":1717000000}'}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            rows={16}
            spellCheck={false}
          />
        </div>

        <div className="form-group">
          <label className="form-label">{outputLabel}</label>
          <OutputBox value={output} placeholder={outputPlaceholder} rows={16} />
        </div>
      </div>
    </div>
  );
}
