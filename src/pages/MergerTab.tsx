import { useState } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';

interface StatusMsg {
  type: 'success' | 'error' | 'warning' | 'info';
  text: string;
}

function looksLikeIp(s: string): boolean {
  s = String(s ?? '').trim();
  if (!s) return false;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true;
  if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) return true;
  return false;
}

function ipScore(terms: Record<string, unknown[]>, key: string): number {
  return (terms[key] as unknown[]).slice(0, 50).filter(item => looksLikeIp(String(item))).length;
}

const PREFERRED_KEYS = ['data.real_ip', 'source.ip'];

export function MergerTab() {
  const [oldQuery, setOldQuery] = useState('');
  const [newIps, setNewIps] = useState('');
  const [output, setOutput] = useState('');
  const [status, setStatus] = useState<StatusMsg | null>(null);

  function process() {
    setStatus(null);
    setOutput('');

    if (!oldQuery.trim()) {
      setStatus({ type: 'error', text: 'Query lama tidak boleh kosong!' });
      return;
    }
    const newIpList = [...new Set(newIps.split('\n').map(s => s.trim()).filter(Boolean))];
    if (!newIpList.length) {
      setStatus({ type: 'error', text: 'List IP baru tidak boleh kosong!' });
      return;
    }

    let obj: Record<string, unknown>;
    try {
      obj = JSON.parse(oldQuery);
    } catch (e) {
      setStatus({ type: 'error', text: `JSON tidak valid: ${(e as Error).message}` });
      return;
    }

    const query = obj?.query as Record<string, unknown> | undefined;
    const terms = query?.terms as Record<string, unknown[]> | undefined;
    if (!terms) {
      setStatus({ type: 'error', text: 'Struktur harus: query > terms' });
      return;
    }

    const arrayKeys = Object.keys(terms).filter(k => Array.isArray(terms[k]));
    if (!arrayKeys.length) {
      setStatus({ type: 'error', text: 'Struktur harus: query > terms > <key> (array)' });
      return;
    }

    const preferredKey = PREFERRED_KEYS.find(k => arrayKeys.includes(k));
    const sortedByScore = arrayKeys.slice().sort((a, b) => {
      const sc = ipScore(terms, b) - ipScore(terms, a);
      if (sc !== 0) return sc;
      const la = terms[a].length;
      const lb = terms[b].length;
      if (lb !== la) return lb - la;
      return a.localeCompare(b);
    });

    const ipKey = preferredKey ?? sortedByScore[0];
    const existing = terms[ipKey] as string[];
    const combined = [...new Set([...existing, ...newIpList])];
    terms[ipKey] = combined;

    setOutput(JSON.stringify(obj, null, 2));

    const added = combined.length - existing.length;
    const note = arrayKeys.length > 1 ? ` (${arrayKeys.length} key terdeteksi, menggunakan "${ipKey}")` : '';
    setStatus({ type: 'success', text: `${added} IP ditambahkan. Total: ${combined.length}${note}` });
  }

  return (
    <div className="tab-content merger-tab">
      <div className="section-header">
        <h2>JSON Merger</h2>
      </div>

      {status && (
        <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />
      )}

      <div className="merger-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="old-query">Query JSON lama</label>
          <textarea
            id="old-query"
            className="form-textarea"
            placeholder={'{"query":{"terms":{"source.ip":["1.2.3.4"]}}}'}
            value={oldQuery}
            onChange={e => setOldQuery(e.target.value)}
            rows={12}
          />
        </div>

        <div className="form-group">
          <label className="form-label" htmlFor="new-ips">IP baru — satu per baris</label>
          <textarea
            id="new-ips"
            className="form-textarea"
            placeholder={'5.6.7.8\n9.10.11.12'}
            value={newIps}
            onChange={e => setNewIps(e.target.value)}
            rows={12}
          />
        </div>

        <div className="form-group merger-output-col">
          <label className="form-label">Output JSON</label>
          <OutputBox
            value={output}
            placeholder="Hasil merge muncul di sini…"
            rows={12}
          />
        </div>
      </div>

      <div className="tab-actions">
        <button
          className="btn btn-primary"
          onClick={process}
          disabled={!oldQuery.trim() || !newIps.trim()}
        >
          Merge
        </button>
        <button
          className="btn btn-ghost"
          onClick={() => { setOldQuery(''); setNewIps(''); setOutput(''); setStatus(null); }}
          disabled={!oldQuery && !newIps && !output}
        >
          Reset
        </button>
      </div>
    </div>
  );
}
