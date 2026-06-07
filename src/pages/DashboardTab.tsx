import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { fmtWhen, fmtDate } from '../lib/utils';
import type { RecentIp } from '../types/api';
import { Spinner } from '../components/shared/Spinner';

interface Props {
  onScanIp?: (ip: string) => void;
}

function verdictCls(v: string | null): string {
  const s = (v ?? '').toLowerCase();
  if (s === 'malicious')  return 'dash-pill malicious';
  if (s === 'suspicious') return 'dash-pill suspicious';
  if (s === 'clean')      return 'dash-pill clean';
  return 'dash-pill unknown';
}

export function DashboardTab({ onScanIp }: Props) {
  const [items, setItems] = useState<RecentIp[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

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

      {items.length > 0 && (
        <div className="dash-summary">
          <div className="dash-pill malicious">{malCount} Malicious</div>
          <div className="dash-pill suspicious">{susCount} Suspicious</div>
          <div className="dash-pill clean">{cleanCount} Clean</div>
        </div>
      )}

      <div className="dash-table-wrap">
        <table className="dash-table">
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
                className="dash-row"
                onClick={() => onScanIp?.(item.ip)}
                title={`Click to re-scan ${item.ip}`}
              >
                <td className="mono" style={{ color: 'var(--text-primary, #e8f0fe)' }}>{item.ip}</td>
                <td>
                  <span className={verdictCls(item.vt_verdict)}>
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
            {!loading && items.length === 0 && (
              <tr>
                <td colSpan={4} className="dash-empty">
                  No data yet. Scan an IP to see history.
                </td>
              </tr>
            )}
            {loading && items.length === 0 && (
              <tr>
                <td colSpan={4} className="dash-empty">
                  <Spinner size={16} />
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
