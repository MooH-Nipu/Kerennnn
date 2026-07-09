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
  if (s === 'malicious')  return 'badge badge--danger';
  if (s === 'suspicious') return 'badge badge--warning';
  if (s === 'clean')      return 'badge badge--success';
  return 'badge';
}

export function DashboardTab({ onScanIp }: Props) {
  const [items, setItems] = useState<RecentIp[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  // Quick scan input
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
    <div className="tab-content dashboard-tab">
      <div className="section-header">
        <h2>Dashboard</h2>
        {lastRefreshed && (
          <span className="line-count">Updated {fmtWhen(lastRefreshed.toISOString())}</span>
        )}
        <button
          className="btn btn-ghost"
          onClick={fetchRecent}
          disabled={loading}
          style={{ marginLeft: 'auto', padding: '0.25rem 0.75rem', fontSize: '0.78rem' }}
        >
          {loading ? <Spinner size={12} /> : '↻ Refresh'}
        </button>
      </div>

      {/* Quick Scan */}
      <form className="dash-quick-scan" onSubmit={handleQuickScan}>
        <input
          type="text"
          className="form-input"
          placeholder="Quick scan an IP, domain, or hash…"
          value={quickInput}
          onChange={e => setQuickInput(e.target.value)}
          style={{ flex: 1 }}
        />
        <button type="submit" className="btn btn-primary btn-sm" style={{ padding: '0.4rem 1rem' }}>
          Scan
        </button>
      </form>

      {/* Stat cards — using Stisla .card pattern */}
      <div className="dash-stats">
        <div className="card" style={{ padding: '1rem', gap: '0.25rem', boxShadow: 'none', borderColor: 'var(--border)' }}>
          <span className="dash-stat__value">{items.length}</span>
          <span className="dash-stat__label">Total Scanned</span>
        </div>
        <div className="card" style={{ padding: '1rem', gap: '0.25rem', boxShadow: 'none', borderColor: 'var(--color-danger)' }}>
          <span className="dash-stat__value" style={{ color: 'var(--color-danger)' }}>{malCount}</span>
          <span className="dash-stat__label">Malicious</span>
        </div>
        <div className="card" style={{ padding: '1rem', gap: '0.25rem', boxShadow: 'none', borderColor: 'var(--color-warning)' }}>
          <span className="dash-stat__value" style={{ color: 'var(--color-warning)' }}>{susCount}</span>
          <span className="dash-stat__label">Suspicious</span>
        </div>
        <div className="card" style={{ padding: '1rem', gap: '0.25rem', boxShadow: 'none', borderColor: 'var(--color-success)' }}>
          <span className="dash-stat__value" style={{ color: 'var(--color-success)' }}>{cleanCount}</span>
          <span className="dash-stat__label">Clean</span>
        </div>
        <div className="card" style={{ padding: '1rem', gap: '0.25rem', boxShadow: 'none' }}>
          <span className="dash-stat__value">{unknownCount}</span>
          <span className="dash-stat__label">Unknown</span>
        </div>
      </div>

      {/* Table — Stisla .table with .table--hover */}
      <div className="dash-table-wrap">
        <table className="table table--hover">
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
                <td className="mono" style={{ color: 'var(--text-primary, #e8f0fe)' }}>{item.ip}</td>
                <td>
                  <span className={verdictBadge(item.vt_verdict)}>
                    {(item.vt_verdict ?? 'unknown').toUpperCase()}
                  </span>
                </td>
                <td className="mono" style={{ color: 'var(--text-secondary, #a3b3cc)' }}>
                  {item.corr_confidence !== null ? `${item.corr_confidence}%` : '—'}
                </td>
                <td style={{ color: 'var(--text-muted, #6b7f9a)', fontSize: '0.8rem' }}>
                  <span title={fmtDate(item.first_scanned_at)}>{fmtWhen(item.first_scanned_at)}</span>
                </td>
              </tr>
            ))}

            {/* Empty state — Stisla .empty-state */}
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={4} style={{ padding: 0 }}>
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
                        className="btn btn-primary btn-sm"
                        onClick={() => onScanIp?.('')}
                        style={{ padding: '0.25rem 0.75rem', fontSize: '0.78rem' }}
                      >
                        Scan Now
                      </button>
                    </div>
                  </div>
                </td>
              </tr>
            )}

            {/* Loading state — Stisla .placeholder skeletons */}
            {loading && items.length === 0 && (
              <>
                {[0, 1, 2, 3].map(i => (
                  <tr key={i}>
                    <td><span className="placeholder placeholder--glow" style={{ width: '60%' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '40%' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '30%' }}>&nbsp;</span></td>
                    <td><span className="placeholder placeholder--glow" style={{ width: '50%' }}>&nbsp;</span></td>
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
