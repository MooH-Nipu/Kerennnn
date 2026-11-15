import { useMemo, useState } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';
import { legend, newSalt, redact } from '../lib/redact.mjs';

const MAX_INPUT_CHARS = 262144;

interface Stats { [cat: string]: number }

export function RedactTab() {
  const [raw, setRaw] = useState('');
  const [out, setOut] = useState('');
  const [stats, setStats] = useState<Stats>({});
  const [strict, setStrict] = useState(false);
  const [withLegend, setWithLegend] = useState(true);
  const [entities, setEntities] = useState('');
  const [terms, setTerms] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  // Stable for the session so the same value keeps one token across runs.
  const [salt] = useState(() => newSalt());

  const lines = useMemo(() => raw.split(/\r?\n/).filter(l => l.trim()).length, [raw]);
  const summary = useMemo(
    () => Object.entries(stats).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k} ${v}`).join(' · '),
    [stats],
  );

  async function run() {
    setError('');
    if (raw.length > MAX_INPUT_CHARS) {
      setError(`Input exceeds ${MAX_INPUT_CHARS.toLocaleString()} characters; nothing processed.`);
      return;
    }
    setBusy(true);
    try {
      const result = await redact(raw, salt, {
        strict,
        entities: entities.split('\n').map(s => s.trim()).filter(Boolean),
        terms: terms.split('\n').map(s => s.trim()).filter(Boolean),
      });
      setStats(result.stats);
      setOut(withLegend ? legend() + result.text : result.text);
    } catch (err) {
      setOut('');
      setStats({});
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  function clear() {
    setRaw('');
    setOut('');
    setStats({});
    setError('');
  }

  const redacted = Object.keys(stats).length > 0;

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>Redact for LLM</h2>
        {lines > 0 && <span className="line-count">{lines} lines</span>}
      </div>

      <p className="redact-help">
        Replaces credentials, PII and identifiers with <code>«CATEGORY_hash»</code> tokens so the text can be
        pasted into a model prompt. The same value always maps to the same token, so correlation survives and
        nothing is reversible. Runs in this browser tab — nothing is uploaded.
      </p>

      <div className="formatter-grid redact-pair">
        <div className="form-group">
          <label className="form-label" htmlFor="redact-input">Raw log — untrusted, may contain secrets</label>
          <textarea
            id="redact-input"
            className="form-textarea"
            rows={14}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            spellCheck={false}
            placeholder="Paste the log, stack trace or incident evidence you want to send to a model…"
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="redact-output">Safe to paste</label>
          <OutputBox value={out} rows={14} ariaLabel="Redacted output" placeholder="Redacted text appears here…" />
        </div>
      </div>

      <div className="redact-options">
        <label className="redact-toggle">
          <input type="checkbox" checked={strict} onChange={e => setStrict(e.target.checked)} />
          <span>Strict — also redact UUID, IPv6, internal FQDN, ARN, 12-digit account ID, k8s names</span>
        </label>
        <label className="redact-toggle">
          <input type="checkbox" checked={withLegend} onChange={e => setWithLegend(e.target.checked)} />
          <span>Prepend token legend so the model does not invent values</span>
        </label>
      </div>

      <div className="formatter-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="redact-entities">Known agent / device names</label>
          <textarea
            id="redact-entities"
            className="form-textarea"
            rows={4}
            value={entities}
            onChange={e => setEntities(e.target.value)}
            spellCheck={false}
            placeholder={'Agent-Zephyr\nMBP-Rian'}
          />
          <p className="redact-hint">
            One per line. Names that follow no naming convention are <strong>not</strong> caught by any
            pattern — an empty list means they stay in the output.
          </p>
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="redact-terms">Extra terms to redact</label>
          <textarea
            id="redact-terms"
            className="form-textarea"
            rows={4}
            value={terms}
            onChange={e => setTerms(e.target.value)}
            spellCheck={false}
            placeholder={'customer names\ncodenames\nblocklist vocabulary'}
          />
        </div>
      </div>

      <div className="tab-actions">
        <button type="button" className="btn btn-primary" onClick={run} disabled={!raw.trim() || busy}>
          {busy ? 'Redacting…' : 'Redact'}
        </button>
        <button type="button" className="btn btn-ghost" onClick={clear} disabled={!raw && !out}>
          Clear
        </button>
        {redacted && <span className="redact-stats">{summary}</span>}
      </div>

      {error && <StatusMessage type="error" message={error} onDismiss={() => setError('')} />}
    </div>
  );
}
