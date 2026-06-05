import { useState } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';

interface StatusMsg {
  type: 'success' | 'error' | 'warning' | 'info';
  text: string;
}

type IndentMode = '2' | '4' | 'tab';

function indentValue(mode: IndentMode): string | number {
  if (mode === 'tab') return '\t';
  return mode === '4' ? 4 : 2;
}

// Build a friendly, localized error. V8 usually embeds "position N" (and newer
// engines also "line L column C"); we surface line/column either way.
function describeJsonError(err: unknown, src: string): string {
  const msg = err instanceof Error ? err.message : String(err);
  if (/line \d+/i.test(msg)) return `JSON tidak valid: ${msg}`;
  const m = /position (\d+)/i.exec(msg);
  if (m) {
    const pos = Number(m[1]);
    const upTo = src.slice(0, pos);
    const line = upTo.split('\n').length;
    const col = pos - upTo.lastIndexOf('\n');
    return `JSON tidak valid: ${msg} (baris ${line}, kolom ${col}).`;
  }
  return `JSON tidak valid: ${msg}`;
}

// Logs are often NDJSON — one JSON object per line. Only treat as NDJSON when
// there are ≥2 lines and EVERY non-empty line parses on its own.
function tryNdjson(
  src: string,
  minify: boolean,
  indent: string | number
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
    .map(p => (minify ? JSON.stringify(p) : JSON.stringify(p, null, indent)))
    .join(minify ? '\n' : '\n\n');
  return { ok: true, out, count: parsed.length };
}

export function JsonTab() {
  const [raw, setRaw] = useState('');
  const [output, setOutput] = useState('');
  const [indentMode, setIndentMode] = useState<IndentMode>('2');
  const [status, setStatus] = useState<StatusMsg | null>(null);

  function run(minify: boolean) {
    setStatus(null);
    setOutput('');
    const src = raw.trim();
    if (!src) {
      setStatus({ type: 'error', text: 'Input JSON tidak boleh kosong!' });
      return;
    }

    const indent = indentValue(indentMode);
    try {
      const parsed = JSON.parse(src);
      setOutput(minify ? JSON.stringify(parsed) : JSON.stringify(parsed, null, indent));
      setStatus({ type: 'success', text: `JSON valid — ${minify ? 'diminify' : 'dirapikan'}.` });
    } catch (err) {
      // Fallback: maybe it's a log stream (NDJSON), not one JSON document.
      const nd = tryNdjson(src, minify, indent);
      if (nd.ok) {
        setOutput(nd.out);
        setStatus({
          type: 'success',
          text: `${nd.count} baris JSON ${minify ? 'diminify' : 'dirapikan'} (NDJSON log).`,
        });
        return;
      }
      setStatus({ type: 'error', text: describeJsonError(err, src) });
    }
  }

  function reset() {
    setRaw('');
    setOutput('');
    setStatus(null);
  }

  const lineCount = raw.split('\n').filter(s => s.trim()).length;

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>JSON Beautifier</h2>
        {lineCount > 0 && <span className="line-count">{lineCount} baris</span>}
      </div>

      {status && (
        <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />
      )}

      <div className="json-indent" role="group" aria-label="Indentasi">
        <span className="form-label" style={{ margin: 0 }}>Indentasi:</span>
        {([['2', '2 spasi'], ['4', '4 spasi'], ['tab', 'Tab']] as [IndentMode, string][]).map(
          ([mode, label]) => (
            <button
              key={mode}
              type="button"
              className={`btn btn-sm ${indentMode === mode ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setIndentMode(mode)}
              aria-pressed={indentMode === mode}
            >
              {label}
            </button>
          )
        )}
      </div>

      <div className="formatter-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="raw-json">
            Input — JSON atau JSON log (NDJSON didukung)
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
          <label className="form-label">Output</label>
          <OutputBox value={output} placeholder="Hasil JSON rapi muncul di sini…" rows={16} />
        </div>
      </div>

      <div className="tab-actions">
        <button className="btn btn-primary" onClick={() => run(false)} disabled={!raw.trim()}>
          Rapikan
        </button>
        <button className="btn btn-ghost" onClick={() => run(true)} disabled={!raw.trim()}>
          Minify
        </button>
        <button className="btn btn-ghost" onClick={reset} disabled={!raw && !output}>
          Reset
        </button>
      </div>
    </div>
  );
}
