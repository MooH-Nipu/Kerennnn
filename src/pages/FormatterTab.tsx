import { useState } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';

interface StatusMsg {
  type: 'success' | 'error' | 'warning' | 'info';
  text: string;
}

export function FormatterTab() {
  const [raw, setRaw] = useState('');
  const [output, setOutput] = useState('');
  const [status, setStatus] = useState<StatusMsg | null>(null);

  function process() {
    setStatus(null);
    setOutput('');
    const ips = raw.split('\n').map(s => s.trim()).filter(Boolean);
    const unique = [...new Set(ips)];
    if (!unique.length) {
      setStatus({ type: 'error', text: 'IP list cannot be empty!' });
      return;
    }
    setOutput(unique.join('; '));
    const dupes = ips.length - unique.length;
    setStatus({
      type: 'success',
      text: `${unique.length} IPs formatted${dupes > 0 ? ` — ${dupes} duplicates removed` : ''}.`,
    });
  }

  const lineCount = raw.split('\n').filter(s => s.trim()).length;

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>IP Formatter</h2>
        {lineCount > 0 && <span className="line-count">{lineCount} lines</span>}
      </div>

      {status && (
        <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />
      )}

      <div className="formatter-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="raw-ips">
            Input — one IP per line
          </label>
          <textarea
            id="raw-ips"
            className="form-textarea"
            placeholder={'192.168.1.1\n10.0.0.2\n172.16.0.1'}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            rows={14}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Output — semicolon separated</label>
          <OutputBox
            value={output}
            placeholder="Formatted result appears here…"
            rows={14}
          />
        </div>
      </div>

      <div className="tab-actions">
        <button className="btn btn-primary" onClick={process} disabled={!raw.trim()}>
          Format
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => { setRaw(''); setOutput(''); setStatus(null); }}
          disabled={!raw && !output}
        >
          Reset
        </button>
      </div>
    </div>
  );
}
