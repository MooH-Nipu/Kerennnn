import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { useAutoRefresh } from '../hooks/useAutoRefresh';
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
  const [autoRefresh, setAutoRefresh] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const fetchRecent = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.ipCache.recent(50);
      setItems(res.data ?? []);
      setLastRefreshed(new Date());
    } catch { /* ignore */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { fetchRecent(); }, [fetchRecent]);

  useAutoRefresh(fetchRecent, 60_000, autoRefresh);

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
      </div>

      <div className="dash-controls">
        <button className="btn btn-ghost" onClick={fetchRecent} disabled={loading}>
          {loading ? <Spinner size={14} /> : '↻'} Refresh
        </button>
        <label className="dash-toggle">
          <input
            type="checkbox"
            checked={autoRefresh}
            onChange={e => setAutoRefresh(e.target.checked)}
          />
          Auto-refresh (60s)
        </label>
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
              <th>IP Address</th>
              <th>Verdict</th>
              <th>Confidence</th>
              <th>First Scanned</th>
            </tr>
          </thead>
          <tbody>
            {items.map(item => (
              <tr
                key={item.ip}
                className="dash-row"
                onClick={() => onScanIp?.(item.ip)}
                title={`Klik untuk scan ${item.ip}`}
              >
                <td className="dash-ip">
                  <span className="mono">{item.ip}</span>
                </td>
                <td>
                  <span className={verdictCls(item.vt_verdict)}>
                    {(item.vt_verdict ?? 'unknown').toUpperCase()}
                  </span>
                </td>
                <td>
                  {item.corr_confidence !== null
                    ? <span className="mono">{item.corr_confidence}%</span>
                    : <span className="text-muted">—</span>
                  }
                </td>
                <td className="dash-when">
                  <span title={fmtDate(item.first_scanned_at)}>{fmtWhen(item.first_scanned_at)}</span>
                </td>
              </tr>
            ))}
            {!loading && items.length === 0 && (
              <tr><td colSpan={4} className="dash-empty">Belum ada data. Scan IP untuk melihat riwayat.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
