import { useState, useEffect } from 'react';
import { MAX_SYSLOG_CHARS, MAX_SYSLOG_LINES, parseSyslogInput, syslogReadable, type SyslogRecord } from '../lib/syslog.mjs';
import './syslog.css';
import { extractReport } from '../lib/ioc-report';
import { OutputBox } from '../components/shared/OutputBox';

const examples = {
  'RFC 3164': '<34>Oct 11 22:14:15 router01 sshd[1234]: Failed password for admin from 192.0.2.10',
  'RFC 5424': '<165>1 2026-10-27T10:14:15.003+07:00 fw01 firewall 412 DENY [origin ip="192.0.2.10"][event@32473 action="blocked" rule="edge"] Connection denied',
  'FortiGate': '<45>date=2026-10-27 time=13:39:17 devname="fw01" devid="FGT001" eventtime=1793089157000000000 logid="0000000020" action="accept" vwlquality="Seq_num(1 wan2 virtual-wan-link), alive, selected"',
};

export function SyslogTab({ input: sharedInput, onInput }: { input?: string; onInput?: (value: string) => void } = {}) {
  const [iocOutput, setIocOutput] = useState('');
  const [localInput, setLocalInput] = useState('');
  const input = sharedInput ?? localInput;
  const setInput = onInput ?? setLocalInput;
  useEffect(() => {
    if (sharedInput === undefined) return;
    setRecords([]); setIocOutput(''); setStatus(''); setError('');
    if (!sharedInput.trim()) return;
    const timer = setTimeout(() => {
      try {
        const next = parseSyslogInput(sharedInput);
        setRecords(next);
        setStatus(`${next.filter(record => record.valid).length} valid · ${next.filter(record => !record.valid).length} invalid · ${next.length} records`);
      } catch (error) { setError(error instanceof Error ? error.message : 'Formatting failed.'); }
    }, 300);
    return () => clearTimeout(timer);
  }, [sharedInput]);
  const [records, setRecords] = useState<SyslogRecord[]>([]);
  const [status, setStatus] = useState('');
  const [error, setError] = useState('');
  const readable = syslogReadable(records);
  const json = JSON.stringify(records, null, 2);
  function edit(value: string) { setIocOutput(''); setInput(value); setRecords([]); setStatus(''); setError(''); }
  function format() {
    try {
      const next = parseSyslogInput(input);
      setRecords(next);
      setError('');
      setStatus(next.length ? `${next.filter(r => r.valid).length} valid · ${next.filter(r => !r.valid).length} invalid · ${next.length} records` : 'Paste at least one syslog record.');
    } catch (err) { setRecords([]); setStatus(''); setError(err instanceof Error ? err.message : 'Formatting failed.'); }
  }
  async function copy(value: string) {
    try { await navigator.clipboard.writeText(value); setStatus('Copied to clipboard.'); setError(''); }
    catch { setError('Clipboard unavailable. Select output text manually or download JSON.'); }
  }
  function download() {
    const url = URL.createObjectURL(new Blob([json], { type: 'application/json' }));
    const link = document.createElement('a');
    link.href = url; link.download = 'syslog.json'; link.click();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
    setStatus('JSON download started.');
  }
  return <div className="tab-content syslog-tab">
    <div className="section-header"><h2>Syslog Formatter</h2><span className="line-count">FortiGate / key-value / RFC</span></div>
    <p id="syslog-help" className="syslog-help">Auto-detect FortiGate/key=value (optional &lt;PRI&gt;), RFC 3164 and RFC 5424 per line. Quoted spaces, escaped quotes and duplicate keys preserved; values stay strings. Vendor fields are not validated as an RFC envelope. Local only; no logs uploaded. Up to {MAX_SYSLOG_LINES} lines / {MAX_SYSLOG_CHARS.toLocaleString()} characters; 16,384 characters per record. RFC 3164: 1,024 bytes. Blank lines ignored. No transport framing or multiline messages.</p>
    <div className="syslog-actions" aria-label="Example records">
      {Object.entries(examples).map(([label, value]) => <button type="button" className="btn btn-sm btn-ghost" key={label} onClick={() => edit(value)}>Example {label}</button>)}
      <button type="button" className="btn btn-sm btn-ghost" onClick={() => edit(Object.values(examples).join('\n'))}>Example mixed</button>
    </div>
    <div hidden={sharedInput !== undefined}>
    <label htmlFor="syslog-input">Syslog input</label>
    <textarea id="syslog-input" rows={7} value={input} onChange={e => edit(e.target.value)} aria-describedby="syslog-help" spellCheck={false} placeholder="Paste one or more syslog records, one per line…" />
    </div>
    <div className="syslog-actions">
      <button type="button" className="btn btn-sm btn-primary" onClick={format} disabled={!input.trim()}>Format</button>
      <button type="button" className="btn btn-sm btn-ghost" onClick={() => copy(readable)} disabled={!records.length}>Copy text</button>
      <button type="button" className="btn btn-sm btn-ghost" onClick={() => copy(json)} disabled={!records.length}>Copy JSON</button>
      <button type="button" className="btn btn-sm btn-ghost" onClick={download} disabled={!records.length}>Download JSON</button>
    </div>
    <button type="button" className="btn btn-sm btn-ghost" disabled={!input.trim()} onClick={() => {
      if (input.length > MAX_SYSLOG_CHARS) { setError(`Input exceeds ${MAX_SYSLOG_CHARS} characters; nothing processed.`); return; }
      const result = extractReport(input); setIocOutput(result.out); setStatus(result.status.text); setError('');
    }}>Extract IOCs</button>
    {iocOutput && <section aria-label="Syslog extracted IOCs"><h3>Extracted IOCs</h3><OutputBox value={iocOutput} rows={8} /></section>}
    <div role="status" className="syslog-status">{status}</div>
    {error && <div role="alert" className="syslog-error">{error}</div>}
    {records.length > 0 && <section aria-label="Formatted syslog" className="syslog-results">
      {records.map(record => <article key={record.line} className={`syslog-record ${record.valid ? '' : 'syslog-record--invalid'}`}>
        <h3>Line {record.line} · {record.format ?? 'Unknown format'} · {record.valid ? 'VALID' : 'INVALID'}</h3>
        <button type="button" className="btn btn-sm btn-ghost" onClick={() => copy(syslogReadable([record]))}>Copy hasil</button>
        {record.error && <p className="syslog-error">{record.error}</p>}
        {record.valid && <pre tabIndex={0}>{syslogReadable([record]).split('\n').slice(1, -1).join('\n')}</pre>}
        <details><summary>Original / raw record</summary><pre tabIndex={0}>{record.raw}</pre></details>
      </article>)}
    </section>}
  </div>;
}
