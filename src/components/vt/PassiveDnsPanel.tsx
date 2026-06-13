import { useState, useEffect } from 'react';
import { api } from '../../lib/api';
import { Spinner } from '../shared/Spinner';
import type { PassiveDnsRecord } from '../../types/api';

// Module-level cache keyed by ioc — survives card collapse/expand remounts so
// re-opening the panel never re-hits the (rate-limited) upstream.
const cache = new Map<string, { records: PassiveDnsRecord[]; note?: string }>();

interface Props {
  ioc: string;
  type: 'ip' | 'domain';
}

export function PassiveDnsPanel({ ioc, type }: Props) {
  const [open, setOpen] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const cached = cache.get(ioc);
  const [data, setData] = useState<{ records: PassiveDnsRecord[]; note?: string } | null>(cached ?? null);

  useEffect(() => {
    if (!open || data !== null) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    api.scan.passiveDns(ioc)
      .then(r => {
        if (cancelled) return;
        const next = { records: r.records, note: r.note };
        cache.set(ioc, next);
        setData(next);
      })
      .catch(e => { if (!cancelled) setError(e instanceof Error ? e.message : String(e)); })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [open, ioc, data]);

  const count = data?.records.length;
  const isDomain = type === 'domain';

  return (
    <div className="pivot-panel">
      <button type="button" className="pivot-panel__toggle" onClick={() => setOpen(o => !o)}>
        <span className={`pivot-chevron${open ? ' open' : ''}`}>›</span>
        Passive DNS{count !== undefined ? ` (${count})` : ''}
      </button>
      {open && (
        <div className="pivot-panel__body">
          {loading && <div className="pivot-loading"><Spinner size={12} /> Resolving…</div>}
          {error && <div className="pivot-error">⚠ {error}</div>}
          {data && data.records.length === 0 && !loading && (
            <div className="pivot-empty">{data.note || 'No passive DNS records found.'}</div>
          )}
          {data && data.records.length > 0 && (
            <table className="pivot-table">
              <thead>
                <tr>
                  <th>{isDomain ? 'Subdomain' : 'Hostname'}</th>
                  {isDomain && <th>IP</th>}
                </tr>
              </thead>
              <tbody>
                {data.records.map((r, i) => (
                  <tr key={i}>
                    <td>{r.host}</td>
                    {isDomain && <td>{r.ip || '—'}</td>}
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
