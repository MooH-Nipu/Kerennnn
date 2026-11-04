import { useState } from 'react';
import { JsonTab } from './JsonTab';
import { SyslogTab } from './SyslogTab';
import { MAX_SYSLOG_CHARS } from '../lib/syslog.mjs';

export function LogFormatterTab() {
  const [input, setInput] = useState('');
  // JSON-looking input stays JSON even when incomplete; never hide syntax errors.
  const syslog = input.split(/\r?\n/).some(line => /^(?:<|[A-Za-z_][\w.-]*=)/.test(line.trimStart())) && !/^\s*[[{"0-9-]/.test(input);
  return <div className="tab-content">
    <div className="section-header"><h2>Log Formatter</h2><span>{input.trim() ? (syslog ? 'Syslog / key-value detected' : 'JSON / NDJSON') : 'Auto-detect'}</span></div>
    <label htmlFor="log-input">Log input</label>
    <textarea id="log-input" className="form-textarea" rows={8} value={input} onChange={event => setInput(event.target.value)} spellCheck={false} placeholder="Paste JSON, NDJSON, RFC syslog or FortiGate logs…" />
    {input.length > MAX_SYSLOG_CHARS ? <p role="alert">Input exceeds {MAX_SYSLOG_CHARS} characters; nothing processed.</p> : syslog
      ? <SyslogTab input={input} onInput={setInput} />
      : <JsonTab input={input} onInput={setInput} />}
  </div>;
}
