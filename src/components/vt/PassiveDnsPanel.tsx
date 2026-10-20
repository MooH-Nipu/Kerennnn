import { useState, useEffect } from 'react';
import { api } from '../../lib/api';
import { Spinner } from '../shared/Spinner';
import type { PassiveDnsRecord, PassiveDnsResponse } from '../../types/api';
import { resolutionEdges, reverseCandidates } from '../../lib/sample-relationships.mjs';

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
  const [relations, setRelations] = useState<Array<{ domain: string; ip: string }> | null>(null);
  const [relationLoading, setRelationLoading] = useState(false);
  const [relationError, setRelationError] = useState<string | null>(null);

  async function loadRelationships() {
    if (relationLoading) return;
    setRelationLoading(true);
    setRelationError(null);
    try {
      let responses: PassiveDnsResponse[];
      if (type === 'domain') {
        responses = [data ? { ...data, ok: true, ioc, type: 'domain' as const } : await api.scan.passiveDns(ioc)];
      } else {
        const reverse = data ? { ...data, ok: true, ioc, type: 'ip' as const } : await api.scan.passiveDns(ioc);
        const candidates = reverseCandidates(reverse).slice(0, 2);
        const settled = await Promise.allSettled(candidates.map(candidate => api.scan.passiveDns(candidate)));
        const failed = settled.find(result => result.status === 'rejected');
        if (failed?.status === 'rejected') throw new Error(`DNS relationships incomplete: ${failed.reason instanceof Error ? failed.reason.message : 'Candidate lookup failed.'}`);
        responses = settled.flatMap((result, index) => result.status === 'fulfilled' && result.value.ioc === candidates[index] && result.value.type === 'domain'
          ? [result.value] : []);
      }
      setRelations(resolutionEdges(ioc, type, responses));
    } catch (e) {
      setRelations(null);
      setRelationError(e instanceof Error ? e.message : 'Cannot load relationships.');
    } finally {
      setRelationLoading(false);
    }
  }

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
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => { void loadRelationships(); }} disabled={relationLoading || relations !== null} aria-label={`Load one-hop observed DNS relationships for ${ioc}`}>Load one-hop relationships</button>
          <p className="form-hint">Observed domain-to-IPv4 resolutions only; up to 12 pairs. IP lookup verifies up to 2 reverse candidates. No inferred links.</p>
          {relationLoading && <div role="status">Loading relationships…</div>}
          {relationError && <div role="alert" className="pivot-error">{relationError}</div>}
          {relations && !relationLoading && !relationError && (relations.length ?
            <ul aria-label="Observed DNS resolution edges">{relations.map(edge => <li key={`${edge.domain}:${edge.ip}`}>{edge.domain} resolves to {edge.ip}</li>)}</ul> :
            <p>No verified observed resolution edges found.</p>)}
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
