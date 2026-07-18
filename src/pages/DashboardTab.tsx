import { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer,
  BarChart, Bar,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';
import { api } from '../lib/api';
import { fmtWhen } from '../lib/utils';
import { Spinner } from '../components/shared/Spinner';
import type { RecentIp, ApiUsageResponse, IpScanAnalyticsResponse, VtQuotaResponse } from '../types/api';

interface Props {
  onScanIp?: (ip: string) => void;
}

/* ── Usage helpers ─────────────────────────────────────────── */
const SERVICE_COLORS: Record<string, string> = {
  'VirusTotal':     'var(--color-primary)',
  'AbuseIPDB':      'var(--color-danger)',
  'Abuse.ch':       'var(--color-warning)',
  'AlienVault OTX': '#a78bfa',
  'URLScan.io':     'var(--color-success)',
  'Enrichment':     'var(--color-info)',
  'Passive DNS':    '#fb923c',
  'crt.sh':         '#a3e635',
};
const FALLBACK_PALETTE = ['var(--color-primary)', 'var(--color-danger)', 'var(--color-warning)', '#a78bfa', 'var(--color-success)', 'var(--color-info)', '#fb923c', '#a3e635', '#c084fc', '#f472b6'];

const TOOLTIP_STYLE = {
  background: 'var(--color-surface)',
  border: '1px solid var(--color-border)',
  borderRadius: 8,
  color: 'var(--color-foreground)',
  fontSize: 12,
};
const AXIS_STYLE = { fill: 'var(--color-muted-foreground)', fontSize: 11 };

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

export function DashboardTab({ onScanIp }: Props) {
  /* ── IP cache state ─────────────────────────────────────── */
  const [items, setItems] = useState<RecentIp[]>([]);
  const [scanTimeline, setScanTimeline] = useState<Array<{ time: string; scans: number; source?: string }>>([]);
  const [scanTimelineBucket, setScanTimelineBucket] = useState<string | null>(null);
  const [totalIps, setTotalIps] = useState(0);
  const [verdictCounts, setVerdictCounts] = useState({ malicious: 0, suspicious: 0, clean: 0 });
  const [ipLoading, setIpLoading] = useState(false);
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null);

  const fetchRecent = useCallback(async (f?: string, t?: string) => {
    setIpLoading(true);
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
    } catch { /* ignore */ }
    finally { setIpLoading(false); }
  }, []);

  /* ── Usage state ────────────────────────────────────────── */
  const now = new Date();
  const [from, setFrom] = useState(() => toLocalDatetime(new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)));
  const [to, setTo] = useState(() => toLocalDatetime(now));
  const [activePreset, setActivePreset] = useState('7d');
  const [usageLoading, setUsageLoading] = useState(true);
  const [, setRefreshing] = useState(false);
  const [usageData, setUsageData] = useState<ApiUsageResponse | null>(null);
  const [ipScanData, setIpScanData] = useState<IpScanAnalyticsResponse | null>(null);
  const [vtQuota, setVtQuota] = useState<VtQuotaResponse | null>(null);
  const [usageError, setUsageError] = useState<string | null>(null);

  const fetchUsage = useCallback((f: string, t: string, isRefresh: boolean) => {
    if (isRefresh) setRefreshing(true); else setUsageLoading(true);
    setUsageError(null);
    const fromISO = new Date(f).toISOString();
    const toISO   = new Date(t).toISOString();
    Promise.all([
      api.admin.usage({ from: fromISO, to: toISO }),
      api.admin.ipScans(fromISO, toISO),
      api.admin.vtQuota(),
    ])
      .then(([usage, ipScans, quota]) => {
        // Older deployments and partially applied migrations can omit aggregates.
        setUsageData({ ...usage, byUser: usage.byUser ?? [], byOutcome: usage.byOutcome ?? [], byDay: usage.byDay ?? [], recent: usage.recent ?? [] });
        const safeIpScans = { ...ipScans, byUser: ipScans.byUser ?? [], timeline: ipScans.timeline ?? [] };
        setIpScanData(safeIpScans);
        setScanTimeline(safeIpScans.timeline);
        setScanTimelineBucket(safeIpScans.bucket ?? null);
        setVtQuota({ ...quota, keys: quota.keys ?? [] });
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

  /* ── Derived ────────────────────────────────────────────── */

  const usageTotals = usageData
    ? usageData.byOutcome.reduce((acc, o) => { acc[o.outcome] = o.total; return acc; }, {} as Record<string, number>)
    : {};

  const loading = ipLoading || usageLoading;

  return (
    <div className="tab-content" style={{ display: 'block' }}>
      {/* ── Header ──────────────────────────────────────────── */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
        <h2 style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-foreground)' }}>Dashboard</h2>
        {lastRefreshed && (
          <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)' }}>
            Updated {fmtWhen(lastRefreshed.toISOString())}
          </span>
        )}
        <button
          className="button button--ghost button--sm"
          onClick={() => { fetchRecent(from, to); fetchUsage(from, to, true); }}
          disabled={loading}
          style={{ marginLeft: 'auto' }}
        >
          {loading ? <Spinner size={12} /> : '↻ Refresh'}
        </button>
      </div>


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
        <input type="datetime-local" value={from} onChange={e => { setFrom(e.target.value); setActivePreset(''); }} disabled={loading}
          style={{ fontSize: '0.75rem', padding: '0.3rem 0.5rem', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-surface)', color: 'var(--color-foreground)' }} />
        <span style={{ fontSize: '0.78rem', color: 'var(--color-muted-foreground)' }}>→</span>
        <input type="datetime-local" value={to} onChange={e => { setTo(e.target.value); setActivePreset(''); }} disabled={loading}
          style={{ fontSize: '0.75rem', padding: '0.3rem 0.5rem', border: '1px solid var(--color-border)', borderRadius: 'var(--radius-sm)', background: 'var(--color-surface)', color: 'var(--color-foreground)' }} />
      </div>

      {/* ── Error ──────────────────────────────────────────── */}
      {usageError && (
        <div className="alert alert--danger" style={{ marginBottom: '1rem' }}>
          <span>{usageError}</span>
        </div>
      )}

      {/* ── Loading skeleton ───────────────────────────────── */}
      {loading && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card__body" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '1.5rem' }}>
            <Spinner size={16} />
            <span style={{ color: 'var(--color-muted-foreground)', fontSize: '0.85rem' }}>Loading dashboard data…</span>
          </div>
        </div>
      )}

      {/* ── Scan activity + outcome quality ────────────────── */}
      {!loading && (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1rem', marginBottom: '1rem' }}>
          <div className="card">
            <div className="card__header">
              <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>IP scans over time</h3>
              <span className="badge badge--soft" style={{ marginLeft: 'auto' }}>{scanTimelineBucket ?? '—'} buckets</span>
            </div>
            <div className="card__body" style={{ padding: 0, overflow: 'hidden' }}>
              {scanTimeline.length > 0 ? (
                <div style={{ padding: '0 1rem 0.5rem 0.25rem' }}>
                  <ResponsiveContainer width="100%" height={220}>
                    <AreaChart data={scanTimeline} margin={{ top: 4, right: 18, bottom: 4, left: 0 }}>
                      <defs><linearGradient id="scan-timeline-gradient" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" stopColor="var(--color-primary)" stopOpacity={0.45} /><stop offset="100%" stopColor="var(--color-primary)" stopOpacity={0} /></linearGradient></defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                      <XAxis dataKey="time" tick={AXIS_STYLE} stroke="var(--color-border)" minTickGap={28} />
                      <YAxis tick={AXIS_STYLE} stroke="var(--color-border)" allowDecimals={false} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: 'var(--color-primary)' }} formatter={(value, _name, item) => [value as number, item.payload.source ?? 'tracked scans']} />
                      <Area type="monotone" dataKey="scans" name="IP scans" stroke="var(--color-primary)" strokeWidth={2} fill="url(#scan-timeline-gradient)" />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="empty-state"><p className="empty-state__text">No IP scans in this window.</p></div>}
            </div>
          </div>

          <div className="card">
            <div className="card__header"><h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>IP scans per user</h3></div>
            <div className="card__body" style={{ padding: 0, overflow: 'hidden' }}>
              {ipScanData && ipScanData.byUser.length > 0 ? (
                <div style={{ padding: '0 1rem 0.5rem 0.25rem' }}>
                  <ResponsiveContainer width="100%" height={Math.max(200, ipScanData.byUser.length * 34 + 48)}>
                    <BarChart data={ipScanData.byUser} layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" horizontal={false} />
                      <XAxis type="number" tick={AXIS_STYLE} stroke="var(--color-border)" allowDecimals={false} />
                      <YAxis type="category" dataKey="username" tick={AXIS_STYLE} stroke="var(--color-border)" width={96} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'color-mix(in oklch, var(--color-primary) 8%, transparent)' }} />
                      <Bar dataKey="scans" name="IP scans" fill="var(--color-primary)" radius={[0, 4, 4, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              ) : <div className="empty-state"><p className="empty-state__text">No user IP scans in this window.</p></div>}
            </div>
          </div>
        </div>
      )}

      {vtQuota && (vtQuota.services ?? [{ id: 'virustotal', name: 'VirusTotal', dailyLimit: vtQuota.dailyLimit, keys: vtQuota.keys }]).some(service => service.keys.length > 0) && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card__header">
            <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>API quota tracker</h3>
            <span style={{ marginLeft: 'auto', fontSize: '0.72rem', color: 'var(--color-muted-foreground)' }}>
              Resets {new Date(vtQuota.resetAt).toLocaleString()}
            </span>
          </div>
          <div className="card__body" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
            {(vtQuota.services ?? [{ id: 'virustotal', name: 'VirusTotal', dailyLimit: vtQuota.dailyLimit, keys: vtQuota.keys }]).map(service => (
              <section key={service.id} style={{ display: 'grid', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <strong style={{ fontSize: '0.8rem' }}>{service.name}</strong>
                  <span className="badge badge--soft">{service.keys.length} key{service.keys.length === 1 ? '' : 's'}</span>
                </div>
                {service.keys.map(key => (
                  <div key={key.prefix}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', gap: '0.5rem', fontSize: '0.75rem', marginBottom: '0.25rem' }}>
                      <span>{key.key} <span style={{ color: 'var(--color-muted-foreground)', fontFamily: 'var(--font-mono)' }}>{key.prefix}</span></span>
                      <span>{key.used.toLocaleString()} / {key.limit.toLocaleString()}</span>
                    </div>
                    <div style={{ height: 7, borderRadius: 99, background: 'var(--color-border)', overflow: 'hidden' }}>
                      <div style={{ width: `${key.percent}%`, height: '100%', background: key.percent >= 90 ? 'var(--color-danger)' : key.percent >= 70 ? 'var(--color-warning)' : 'var(--color-primary)', transition: 'width 0.2s ease' }} />
                    </div>
                  </div>
                ))}
              </section>
            ))}
          </div>
        </div>
      )}

      {/* ── TI usage over time (full width) ─────────────────── */}
      {!loading && usageData && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <div className="card__header"><h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>TI usage over time</h3></div>
          <div className="card__body" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '0 1rem 0.5rem 0.25rem' }}>
              {(() => {
                const svcSet = new Set<string>();
                for (const d of usageData.byDay) {
                  for (const k of Object.keys(d)) { if (k !== 'day') svcSet.add(k); }
                }
                const services = [...svcSet].sort();
                if (services.length === 0) return <div className="empty-state"><p className="empty-state__text">No threat-intel calls in this window.</p></div>;
                function svcColor(svc: string, i: number) { return SERVICE_COLORS[svc] || FALLBACK_PALETTE[i % FALLBACK_PALETTE.length]; }
                return (
                  <ResponsiveContainer width="100%" height={260}>
                    <AreaChart data={usageData.byDay} margin={{ top: 4, right: 18, bottom: 4, left: 0 }}>
                      <defs>
                        {services.map(svc => (
                          <linearGradient key={svc} id={`byDay-grad-${svc.replace(/\s+/g, '-')}`} x1="0" y1="0" x2="0" y2="1">
                            <stop offset="0%" stopColor={svcColor(svc, 0)} stopOpacity={0.45} />
                            <stop offset="100%" stopColor={svcColor(svc, 0)} stopOpacity={0} />
                          </linearGradient>
                        ))}
                      </defs>
                      <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                      <XAxis dataKey="day" tick={AXIS_STYLE} stroke="var(--color-border)" />
                      <YAxis tick={AXIS_STYLE} stroke="var(--color-border)" allowDecimals={false} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: 'var(--color-primary)' }} />
                      <Legend wrapperStyle={{ fontSize: 11, color: 'var(--color-muted-foreground)' }} />
                      {services.map((svc, i) => (
                        <Area key={svc} type="monotone" dataKey={svc} name={svc} stroke={svcColor(svc, i)} strokeWidth={2} fill={`url(#byDay-grad-${svc.replace(/\s+/g, '-')})`} />
                      ))}
                    </AreaChart>
                  </ResponsiveContainer>
                );
              })()}
            </div>
          </div>
        </div>
      )}

      {/* ── Two-column tables ──────────────────────────────── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1rem' }}>
        {/* Recent IPs */}
        <div className="card">
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
                  <tr key={item.ip} onClick={() => onScanIp?.(item.ip)} style={{ cursor: 'pointer' }} data-state={item.vt_verdict === 'malicious' ? 'active' : undefined}>
                    <td style={{ fontFamily: 'var(--font-mono)', fontSize: '0.8rem' }}>{item.ip}</td>
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
        <div className="card">
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
                {loading && (
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
