import { useState, useEffect, useCallback, FormEvent } from 'react';
import { api } from '../lib/api';
import { fmtWhen, fmtDate } from '../lib/utils';
import type { RecentIp } from '../types/api';
import { Spinner } from '../components/shared/Spinner';

interface Props {
  onScanIp?: (ip: string) => void;
}

function verdictBadge(v: string | null): string {
  const s = (v ?? '').toLowerCase();
  if (s === 'malicious')  return 'badge badge--danger badge--soft';
  if (s === 'suspicious') return 'badge badge--warning badge--soft';
  if (s === 'clean')      return 'badge badge--success badge--soft';
  return 'badge badge--soft';
}

export function DashboardTab({ onScanIp }: Props) {
  const [items, setItems] = useState<RecentIp[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const [quickInput, setQuickInput] = useState('');

  const fetchRecent = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.ipCache.recent(50);
      setItems(res.items ?? []);
      setLastRefreshed(new Date());
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchRecent(); }, [fetchRecent]);

  const malCount   = items.filter(i => i.vt_verdict === 'malicious').length;
  const susCount   = items.filter(i => i.vt_verdict === 'suspicious').length;
  const cleanCount = items.filter(i => i.vt_verdict === 'clean').length;
  const unknownCount = items.length - malCount - susCount - cleanCount;

  function handleQuickScan(e: FormEvent) {
    e.preventDefault();
    if (quickInput.trim()) onScanIp?.(quickInput.trim());
    else onScanIp?.('');
    setQuickInput('');
  }

  return (
    <div className="tab-content" style={{ display: 'block' }}>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-foreground)' }}>Dashboard</h2>
        {lastRefreshed && (
          <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)' }}>
            Updated {fmtWhen(lastRefreshed.toISOString())}
          </span>
        )}
        <button
          className="button button--ghost button--sm"
          onClick={fetchRecent}
          disabled={loading}
          style={{ marginLeft: 'auto' }}
        >
          {loading ? <Spinner size={12} /> : '↻ Refresh'}
        </button>
      </div>

      {/* Quick Scan */}
      <form onSubmit={handleQuickScan} style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem' }}>
        <input
          type="text"
          className="input"
          placeholder="Quick scan an IP, domain, or hash…"
          value={quickInput}
          onChange={e => setQuickInput(e.target.value)}
          style={{ flex: 1 }}
        />
        <button type="submit" className="button button--primary button--sm" disabled={!quickInput.trim()}>
          Scan
        </button>
      </form>

      {/* Stat cards — pure Stisla */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(160px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <div className="card__body" style={{ textAlign: 'center', padding: '1.25rem 1rem' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-foreground)' }}>{items.length}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Total Scanned</div>
          </div>
        </div>
        <div className="card" style={{ borderColor: 'var(--color-danger)' }}>
          <div className="card__body" style={{ textAlign: 'center', padding: '1.25rem 1rem' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-danger)' }}>{malCount}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Malicious</div>
          </div>
        </div>
        <div className="card" style={{ borderColor: 'var(--color-warning)' }}>
          <div className="card__body" style={{ textAlign: 'center', padding: '1.25rem 1rem' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-warning)' }}>{susCount}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Suspicious</div>
          </div>
        </div>
        <div className="card" style={{ borderColor: 'var(--color-success)' }}>
          <div className="card__body" style={{ textAlign: 'center', padding: '1.25rem 1rem' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-success)' }}>{cleanCount}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Clean</div>
          </div>
        </div>
        <div className="card">
          <div className="card__body" style={{ textAlign: 'center', padding: '1.25rem 1rem' }}>
            <div style={{ fontSize: '1.75rem', fontWeight: 700, color: 'var(--color-muted-foreground)' }}>{unknownCount}</div>
            <div style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px' }}>Unknown</div>
          </div>
        </div>
      </div>

      {/* Table — pure Stisla .table with hover + striped */}
      <div className="table-responsive">
        <table className="table table--hover table--striped">
          <thead>
            <tr>
              <th style={{ width: '36%' }}>IP Address</th>
              <th style={{ width: '16%' }}>Verdict</th>
              <th style={{ width: '14%' }}>Confidence</th>
              <th style={{ width: '34%' }}>First Scanned</th>
            </tr>
          </thead>
          <tbody>
            {items.map(item => (
              <tr
                key={item.ip}
                data-state={item.vt_verdict === 'malicious' ? 'active' : undefined}
                onClick={() => onScanIp?.(item.ip)}
                title={`Click to re-scan ${item.ip}`}
                style={{ cursor: 'pointer' }}
              >
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-foreground)' }}>{item.ip}</td>
                <td>
                  <span className={verdictBadge(item.vt_verdict)}>
                    {(item.vt_verdict ?? 'unknown').toUpperCase()}
                  </span>
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', color: 'var(--color-muted-foreground)' }}>
                  {item.corr_confidence !== null ? `${item.corr_confidence}%` : '—'}
                </td>
                <td style={{ color: 'var(--color-muted-foreground)', fontSize: '0.8rem' }}>
                  <span title={fmtDate(item.first_scanned_at)}>{fmtWhen(item.first_scanned_at)}</span>
                </td>
              </tr>
            ))}

            {/* Empty state — Stisla .empty-state */}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={4} style={{ padding: 0, borderBottom: 'none' }}>
                  <div className="empty-state">
                    <div className="empty-state__media">
                      <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                        <circle cx="11" cy="11" r="8" />
                        <path d="m21 21-4.3-4.3" />
                      </svg>
                    </div>
                    <p className="empty-state__title">No data yet</p>
                    <p className="empty-state__text">Scan an IOC to populate the dashboard.</p>
                    <div className="empty-state__action">
                      <button
                        className="button button--primary button--sm"
                        onClick={() => onScanIp?.('')}
                      >
                        Scan Now
                      </button>
                    </div>
                  </div>
                </td>
              </tr>
            )}

            {/* Loading — Stisla .placeholder skeletons */}
            {loading && items.length === 0 && (
              <>
                {[0, 1, 2, 3, 4].map(i => (
                  <tr key={i}>
                    <td><span className="placeholder placeholder--glow" style={{ width: '60%', height: '0.875rem' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '40%', height: '0.875rem' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '30%', height: '0.875rem' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '50%', height: '0.875rem' }}>&nbsp;</span></td>
                  </tr>
                ))}
              </>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
