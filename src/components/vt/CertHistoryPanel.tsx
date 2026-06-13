import { useState, useEffect } from 'react';
import { api } from '../../lib/api';
import { Spinner } from '../shared/Spinner';
import type { CrtShResponse } from '../../types/api';

// Module-level cache keyed by domain — survives card collapse/expand remounts.
const cache = new Map<string, CrtShResponse>();

export function CertHistoryPanel({ domain }: { domain: string }) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [data, setData] = useState<CrtShResponse | null>(cache.get(domain) ?? null);

  useEffect(() => {
    if (!open || data !== null) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.scan.crtsh(domain)
      .then(r => { if (!cancelled) { cache.set(domain, r); setData(r); } })
      .catch(e => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [open, domain, data]);

  return (
    <div className="pivot-panel">
      <button type="button" className="pivot-panel__toggle" onClick={() => setOpen(o => !o)}>
        <span className={`pivot-chevron${open ? ' open' : ''}`}>›</span>
        Certificate History{data ? ` (${data.total})` : ''}
      </button>
      {open && (
        <div className="pivot-panel__body">
          {loading && <div className="pivot-loading"><Spinner size={12} /> Querying crt.sh…</div>}
          {error && <div className="pivot-error">⚠ {error}</div>}
          {data && data.certs.length === 0 && !loading && (
            <div className="pivot-empty">No certificates found.</div>
          )}
          {data && data.subdomains.length > 0 && (
            <div className="pivot-subdomains">
              <div className="pivot-subdomains__label">{data.subdomains.length} subdomains seen</div>
              <div className="pivot-subdomains__list">
                {data.subdomains.slice(0, 50).map(s => (
                  <span key={s} className="pivot-subdomain">{s}</span>
                ))}
              </div>
            </div>
          )}
          {data && data.certs.length > 0 && (
            <table className="pivot-table">
              <thead>
                <tr><th>Issuer</th><th>Valid from</th><th>Valid to</th><th>Names</th></tr>
              </thead>
              <tbody>
                {data.certs.slice(0, 50).map((c, i) => (
                  <tr key={i}>
                    <td>{c.issuer}</td>
                    <td>{c.not_before ? c.not_before.slice(0, 10) : '—'}</td>
                    <td>{c.not_after ? c.not_after.slice(0, 10) : '—'}</td>
                    <td>{c.names.join(', ')}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}
    </div>
  );
}
