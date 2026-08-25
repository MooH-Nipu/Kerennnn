import { lazy, Suspense, useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { fmtWhen } from '../lib/utils';
import { aggregateUserScans } from '../lib/dashboard-data';
import { Spinner } from '../components/shared/Spinner';
import { StatusMessage } from '../components/shared/StatusMessage';
import type { RecentIp, ApiUsageResponse, IpScanAnalyticsResponse, VtQuotaResponse } from '../types/api';

const DashboardCharts = lazy(() => import('../components/dashboard/DashboardCharts'));

interface Props {
  onScanIp?: (ip: string) => void;
}

const RANGE_HOURS: Record<string, number> = {
  '15m': 0.25,
  '1h': 1,
  '6h': 6,
  '24h': 24,
  '7d': 168,
  '30d': 720,
};

function outcomeLabel(o: string) {
  if (o === 'rate_limited') return 'Rate-limited';
  if (o === 'error') return 'Error';
  if (o === 'ok') return 'OK';
  return o;
}

function toLocalDatetime(d: Date) {
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function verdictBadge(v: string | null): string {
  const s = (v ?? '').toLowerCase();
  if (s === 'malicious')  return 'badge badge--danger badge--soft';
  if (s === 'suspicious') return 'badge badge--warning badge--soft';
  if (s === 'clean')      return 'badge badge--success badge--soft';
  return 'badge badge--soft';
}

function DashboardChartSkeleton({ section }: { section: 'analysis' | 'usage' }) {
  if (section === 'usage') {
    return (
      <div className="card dash-usage-slot" aria-busy="true">
        <div className="card__header"><h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>TI usage over time</h3></div>
        <div className="card__body dash-chart-body"><Spinner size={16} /></div>
      </div>
    );
  }
  return (
    <div className="dash-analysis-grid dash-analysis-grid--stable" aria-busy="true">
      {['IP scans over time', 'IP scans per user'].map(title => (
        <div className="card" key={title}>
          <div className="card__header"><h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>{title}</h3></div>
          <div className="card__body dash-chart-body"><Spinner size={16} /></div>
        </div>
      ))}
    </div>
  );
}

export function DashboardTab({ onScanIp }: Props) {
  /* ── IP cache state ─────────────────────────────────────── */
  const [items, setItems] = useState<RecentIp[]>([]);
  const [scanTimeline, setScanTimeline] = useState<Array<{ time: string; scans: number; source?: string }>>([]);
  const [scanTimelineBucket, setScanTimelineBucket] = useState<string | null>(null);
  const [totalIps, setTotalIps] = useState(0);
  const [verdictCounts, setVerdictCounts] = useState({ malicious: 0, suspicious: 0, clean: 0 });
  const [ipLoading, setIpLoading] = useState(false);
  const [ipError, setIpError] = useState<string | null>(null);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const fetchRecent = useCallback(async (f?: string, t?: string) => {
    setIpLoading(true);
    setIpError(null);
    try {
      const fromISO = f ? new Date(f).toISOString() : undefined;
      const toISO = t ? new Date(t).toISOString() : undefined;
      const res = await api.ipCache.recent(50, fromISO, toISO);
      setItems(res.items ?? []);
      setTotalIps(res.total ?? (res.items ?? []).length);
      setVerdictCounts({
        malicious: res.malicious ?? 0,
        suspicious: res.suspicious ?? 0,
        clean: res.clean ?? 0,
      });
      setLastRefreshed(new Date());
    } catch (error) {
      setIpError(error instanceof Error ? error.message : String(error));
    }
    finally { setIpLoading(false); }
  }, []);

  /* ── Usage state ────────────────────────────────────────── */
  const now = new Date();
  const [from, setFrom] = useState(() => toLocalDatetime(new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)));
  const [to, setTo] = useState(() => toLocalDatetime(now));
  const [activePreset, setActivePreset] = useState('7d');
  const [usageLoading, setUsageLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [usageData, setUsageData] = useState<ApiUsageResponse | null>(null);
  const [ipScanData, setIpScanData] = useState<IpScanAnalyticsResponse | null>(null);
  const [vtQuota, setVtQuota] = useState<VtQuotaResponse | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);

  const fetchUsage = useCallback((f: string, t: string, isRefresh: boolean) => {
    if (isRefresh) setRefreshing(true); else setUsageLoading(true);
    setUsageError(null);
    const fromISO = new Date(f).toISOString();
    const toISO   = new Date(t).toISOString();
    Promise.allSettled([
      api.admin.usage({ from: fromISO, to: toISO }),
      api.admin.ipScans(fromISO, toISO),
      api.admin.vtQuota(),
    ])
      .then(([usageResult, ipScansResult, quotaResult]) => {
        const errors: string[] = [];
        if (usageResult.status === 'fulfilled') {
          const usage = usageResult.value;
          setUsageData({ ...usage, byUser: usage.byUser ?? [], byOutcome: usage.byOutcome ?? [], byDay: usage.byDay ?? [], recent: usage.recent ?? [] });
        } else errors.push(`Usage: ${usageResult.reason instanceof Error ? usageResult.reason.message : String(usageResult.reason)}`);
        if (ipScansResult.status === 'fulfilled') {
          const ipScans = ipScansResult.value;
          const safeIpScans = { ...ipScans, byUser: ipScans.byUser ?? [], timeline: ipScans.timeline ?? [] };
          setIpScanData(safeIpScans);
          setScanTimeline(safeIpScans.timeline);
          setScanTimelineBucket(safeIpScans.bucket ?? null);
        } else errors.push(`IP scans: ${ipScansResult.reason instanceof Error ? ipScansResult.reason.message : String(ipScansResult.reason)}`);
        if (quotaResult.status === 'fulfilled') {
          const quota = quotaResult.value;
          setVtQuota({ ...quota, keys: quota.keys ?? [], services: (quota.services ?? []).map(service => ({ ...service, keys: service.keys ?? [] })) });
        } else errors.push(`Quota: ${quotaResult.reason instanceof Error ? quotaResult.reason.message : String(quotaResult.reason)}`);
        setUsageError(errors.length ? errors.join(' | ') : null);
      })
      .catch(err => setUsageError(err instanceof Error ? err.message : String(err)))
      .finally(() => { setUsageLoading(false); setRefreshing(false); });
  }, []);

  useEffect(() => {
    fetchRecent(from, to);
    fetchUsage(from, to, false);
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  function applyQuickRange(label: string, hoursBack: number) {
    setActivePreset(label);
    const t = new Date();
    const f = new Date(t.getTime() - hoursBack * 60 * 60 * 1000);
    const fStr = toLocalDatetime(f);
    const tStr = toLocalDatetime(t);
    setFrom(fStr); setTo(tStr);
    fetchRecent(fStr, tStr);
    fetchUsage(fStr, tStr, true);
  }

  function refreshDashboard() {
    const hoursBack = RANGE_HOURS[activePreset];
    if (hoursBack) {
      applyQuickRange(activePreset, hoursBack);
      return;
    }
    fetchRecent(from, to);
    fetchUsage(from, to, true);
  }

  function applyCustomRange() {
    if (!from || !to || new Date(from) >= new Date(to)) return;
    fetchRecent(from, to);
    fetchUsage(from, to, true);
  }

  /* ── Derived ────────────────────────────────────────────── */

  const usageTotals = usageData
    ? usageData.byOutcome.reduce((acc, o) => { acc[o.outcome] = o.total; return acc; }, {} as Record<string, number>)
    : {};
  const userScanChartData = aggregateUserScans(ipScanData?.byUser ?? []);

  const loading = ipLoading || usageLoading || refreshing;
  const chartsLoading = usageLoading && !usageData && !ipScanData;

  return (
    <div className="tab-content dashboard-tab">
      {/* ── Header ──────────────────────────────────────────── */}
      <div className="section-header">
        <h2>Dashboard</h2>
        {lastRefreshed && (
          <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)' }}>
            Updated {fmtWhen(lastRefreshed.toISOString())}
          </span>
        )}
        <button
          className="button button--ghost button--sm"
          onClick={refreshDashboard}
          disabled={loading}
          style={{ marginLeft: 'auto' }}
        >
          {loading ? <Spinner size={12} /> : '↻ Refresh'}
        </button>
      </div>

      {ipError && <StatusMessage type="error" message={`IP cache unavailable: ${ipError}`} onDismiss={() => setIpError(null)} />}


      {/* ── Unified stat cards ─────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(130px, 1fr))', gap: '0.75rem', marginBottom: '1.5rem' }}>
        {[
          { label: 'Unique IPs Cached', value: totalIps, color: 'var(--color-foreground)' },
          { label: 'Malicious',   value: verdictCounts.malicious,     color: 'var(--color-danger)' },
          { label: 'Suspicious',  value: verdictCounts.suspicious,    color: 'var(--color-warning)' },
          { label: 'Clean',       value: verdictCounts.clean,         color: 'var(--color-success)' },
          { label: 'API Calls',   value: usageData ? usageData.total.toLocaleString() : '—', color: 'var(--color-primary)' },
          { label: 'Errors',      value: usageTotals.error || 0, color: 'var(--color-muted-foreground)' },
        ].map(stat => (
          <div key={stat.label} className="card" style={{ boxShadow: 'none' }}>
            <div className="card__body" style={{ textAlign: 'center', padding: '1.1rem 0.75rem' }}>
              <div style={{ fontSize: '1.5rem', fontWeight: 700, color: stat.color, lineHeight: 1.2 }}>{stat.value}</div>
              <div style={{ fontSize: '0.7rem', color: 'var(--color-muted-foreground)', textTransform: 'uppercase', letterSpacing: '0.5px', marginTop: '0.25rem' }}>{stat.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* ── Usage time range ───────────────────────────────── */}
      <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap' }}>
        <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)', fontWeight: 600, marginRight: '0.25rem' }}>Range:</span>
        {[{l:'15m',h:0.25},{l:'1h',h:1},{l:'6h',h:6},{l:'24h',h:24},{l:'7d',h:168},{l:'30d',h:720}].map(r => (
          <button
            key={r.l}
            onClick={() => applyQuickRange(r.l, r.h)}
            disabled={loading}
            style={{
              padding: '0.3rem 0.65rem',
              fontSize: '0.75rem',
              fontWeight: 600,
              border: '1px solid ' + (activePreset === r.l ? 'var(--color-primary)' : 'var(--color-border)'),
              borderRadius: 'var(--radius-sm)',
              background: activePreset === r.l ? 'var(--color-primary)' : 'transparent',
              color: activePreset === r.l ? 'var(--color-primary-foreground)' : 'var(--color-muted-foreground)',
              cursor: loading ? 'not-allowed' : 'pointer',
              transition: 'all 0.15s ease',
            }}
          >
            {r.l}
          </button>
        ))}
        <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)', margin: '0 0.25rem' }}>|</span>
        <input aria-label="Dashboard range start" type="datetime-local" value={from} onChange={e => { setFrom(e.target.value); setActivePreset(''); }} disabled={loading}
          style={{ fontSize: '0.75rem', padding: '0.3rem 0.5rem', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-surface)', color: 'var(--color-foreground)' }} />
        <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)' }}>→</span>
        <input aria-label="Dashboard range end" type="datetime-local" value={to} onChange={e => { setTo(e.target.value); setActivePreset(''); }} disabled={loading}
          style={{ fontSize: '0.75rem', padding: '0.3rem 0.5rem', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-surface)', color: 'var(--color-foreground)' }} />
        <button type="button" className="button button--primary button--sm" onClick={applyCustomRange} disabled={loading || !from || !to || new Date(from) >= new Date(to)}>Apply</button>
      </div>

      {/* ── Error ──────────────────────────────────────────── */}
      {usageError && (
        <div className="alert alert--danger" style={{ marginBottom: '1rem' }}>
          <span>{usageError}</span>
        </div>
      )}

      {/* Keep chart and analytics geometry stable while data and chart runtime load. */}
      {chartsLoading ? <DashboardChartSkeleton section="analysis" /> : (
        <Suspense fallback={<DashboardChartSkeleton section="analysis" />}>
          <DashboardCharts
            section="analysis"
            scanTimeline={scanTimeline}
            scanTimelineBucket={scanTimelineBucket}
            userScanChartData={userScanChartData}
            usageData={usageData}
          />
        </Suspense>
      )}

      <div className="card dash-quota-slot">
        <div className="card__header">
          <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>API quota tracker</h3>
          {vtQuota && <span style={{ marginLeft: 'auto', fontSize: '0.72rem', color: 'var(--color-muted-foreground)' }}>Resets {new Date(vtQuota.resetAt).toLocaleString()}</span>}
        </div>
        <div className="card__body" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(min(100%, 280px), 1fr))', gap: '1rem' }}>
          {usageLoading && !vtQuota ? <Spinner size={16} /> : (vtQuota?.services ?? (vtQuota ? [{ id: 'virustotal', name: 'VirusTotal', dailyLimit: vtQuota.dailyLimit, keys: vtQuota.keys }] : [])).some(service => service.keys.length > 0) ? (
            (vtQuota?.services ?? [{ id: 'virustotal', name: 'VirusTotal', dailyLimit: vtQuota?.dailyLimit ?? 0, keys: vtQuota?.keys ?? [] }]).map(service => (
              <section key={service.id} style={{ display: 'grid', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '0.8rem' }}>{service.name}</strong>
                  <span className="badge badge--soft">{service.keys.length} key{service.keys.length === 1 ? '' : 's'}</span>
                </div>
                {service.keys.map(key => (
                  <div key={key.prefix}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                      <span>
                        {key.key} <span style={{ color: 'var(--color-muted-foreground)', fontFamily: 'var(--font-mono)' }}>{key.prefix}</span>
                        {key.quotaExhausted ? <span className="badge badge--soft" style={{ marginLeft: '0.4rem' }}>quota exhausted</span> : key.coolingDown ? <span className="badge badge--soft" style={{ marginLeft: '0.4rem' }}>minute cooldown</span> : null}
                      </span>
                      <span>{key.used.toLocaleString()} / {key.limit.toLocaleString()}</span>
                    </div>
                    <div style={{ height: 7, borderRadius: 99, background: 'var(--color-border)', overflow: 'hidden' }}>
                      <div style={{ width: `${key.percent}%`, height: '100%', background: key.percent >= 90 ? 'var(--color-danger)' : key.percent >= 70 ? 'var(--color-warning)' : 'var(--color-primary)', transition: 'width 0.2s ease' }} />
                    </div>
                  </div>
                ))}
              </section>
            ))
          ) : <div className="empty-state"><p className="empty-state__text">No quota data available.</p></div>}
        </div>
      </div>

      {chartsLoading ? <DashboardChartSkeleton section="usage" /> : (
        <Suspense fallback={<DashboardChartSkeleton section="usage" />}>
          <DashboardCharts
            section="usage"
            scanTimeline={scanTimeline}
            scanTimelineBucket={scanTimelineBucket}
            userScanChartData={userScanChartData}
            usageData={usageData}
          />
        </Suspense>
      )}

      {/* ── Two-column tables ──────────────────────────────── */}
      <div className="dash-tables-grid">
        {/* Recent IPs */}
        <div className="card dash-table-card">
          <div className="card__header">
            <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Recent IP Scans</h3>
            <span className="badge badge--soft" style={{ marginLeft: 'auto' }}>{items.length}</span>
          </div>
          <div className="table-responsive">
            <table className="table table--hover table--sm">
              <thead>
                <tr><th>IP Address</th><th>Verdict</th><th>Scanned</th></tr>
              </thead>
              <tbody>
                {items.slice(0, 15).map(item => (
                  <tr key={item.ip} data-state={item.vt_verdict === 'malicious' ? 'active' : undefined}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>
                      <button type="button" className="dash-ip-action" onClick={() => onScanIp?.(item.ip)}>{item.ip}</button>
                    </td>
                    <td><span className={verdictBadge(item.vt_verdict)}>{(item.vt_verdict ?? 'unknown').toUpperCase()}</span></td>
                    <td style={{ color: 'var(--color-muted-foreground)', fontSize: '0.75rem' }}>{fmtWhen(item.first_scanned_at)}</td>
                  </tr>
                ))}
                {!ipLoading && items.length === 0 && (
                  <tr><td colSpan={3} style={{ padding: 0, borderBottom: 'none' }}>
                    <div className="empty-state">
                      <div className="empty-state__media"><svg width="28" height="28" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></div>
                      <p className="empty-state__text">No IPs scanned yet</p>
                    </div>
                  </td></tr>
                )}
                {ipLoading && items.length === 0 && (
                  [0,1,2].map(i => (
                    <tr key={i}>
                      <td><span className="placeholder placeholder--glow" style={{ width: '60%', height: '0.75rem' }}>&nbsp;</span></td>
                      <td><span className="placeholder placeholder--glow" style={{ width: '40%', height: '0.75rem' }}>&nbsp;</span></td>
                      <td><span className="placeholder placeholder--glow" style={{ width: '50%', height: '0.75rem' }}>&nbsp;</span></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent API calls */}
        <div className="card dash-table-card">
          <div className="card__header">
            <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>Recent API Calls</h3>
            <span className="badge badge--soft" style={{ marginLeft: 'auto' }}>{usageData?.recent.length || 0}</span>
          </div>
          <div className="table-responsive">
            <table className="table table--hover table--sm">
              <thead>
                <tr><th>Time</th><th>User</th><th>Service</th><th>Outcome</th></tr>
              </thead>
              <tbody>
                {(usageData?.recent || []).slice(0, 15).map((r, i) => (
                  <tr key={i}>
                    <td style={{ fontSize: '0.75rem', color: 'var(--color-muted-foreground)' }}>{new Date(r.created_at).toLocaleString()}</td>
                    <td style={{ fontSize: '0.8rem' }}>{r.username || '—'}</td>
                    <td style={{ fontSize: '0.8rem' }}>{r.service}</td>
                    <td>
                      <span className={`badge badge--soft badge--${r.outcome === 'ok' ? 'success' : r.outcome === 'rate_limited' ? 'warning' : 'danger'}`}>
                        {outcomeLabel(r.outcome)}
                      </span>
                    </td>
                  </tr>
                ))}
                {!loading && (!usageData || usageData.recent.length === 0) && (
                  <tr><td colSpan={4} style={{ padding: 0, borderBottom: 'none' }}>
                    <div className="empty-state"><p className="empty-state__text">No API calls in this window</p></div>
                  </td></tr>
                )}
                {usageLoading && !usageData && (
                  [0,1,2].map(i => (
                    <tr key={i}>
                      <td><span className="placeholder placeholder--glow" style={{ width: '50%', height: '0.75rem' }}>&nbsp;</span></td>
                      <td><span className="placeholder placeholder--glow" style={{ width: '40%', height: '0.75rem' }}>&nbsp;</span></td>
                      <td><span className="placeholder placeholder--glow" style={{ width: '40%', height: '0.75rem' }}>&nbsp;</span></td>
                      <td><span className="placeholder placeholder--glow" style={{ width: '30%', height: '0.75rem' }}>&nbsp;</span></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
