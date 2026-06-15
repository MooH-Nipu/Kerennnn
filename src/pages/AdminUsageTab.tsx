import { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer,
  BarChart, Bar,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import type { ApiUsageResponse } from '../types/api';

const OUTCOME_COLORS: Record<string, string> = {
  ok: '#0fba81',
  rate_limited: '#f5a623',
  error: '#e5484d',
};

// Per-service line colors for the TI usage-over-time chart. Services not
// listed here get assigned from the FALLBACK_PALETTE in order.
const SERVICE_COLORS: Record<string, string> = {
  'VirusTotal':      '#1d6ae5',
  'AbuseIPDB':       '#e5484d',
  'Abuse.ch':        '#f5a623',
  'AlienVault OTX':  '#a78bfa',
  'URLScan.io':      '#0fba81',
  'Enrichment':      '#38bdf8',
  'Passive DNS':     '#fb923c',
  'crt.sh':          '#a3e635',
};
const FALLBACK_PALETTE = ['#1d6ae5', '#e5484d', '#f5a623', '#a78bfa', '#0fba81', '#38bdf8', '#fb923c', '#a3e635', '#c084fc', '#f472b6'];

const RANGES = [
  { days: 1, label: '24h' },
  { days: 7, label: '7d' },
  { days: 30, label: '30d' },
  { days: 90, label: '90d' },
];

// Dark-theme tooltip box matching the rest of the UI.
const TOOLTIP_STYLE = {
  background: '#0e1829',
  border: '1px solid #1e304d',
  borderRadius: 8,
  color: '#d4e4ff',
  fontSize: 12,
};
const AXIS_STYLE = { fill: '#5a7aa8', fontSize: 11 };

function outcomeLabel(o: string) {
  if (o === 'rate_limited') return 'Rate-limited';
  if (o === 'error') return 'Error';
  if (o === 'ok') return 'OK';
  return o;
}

function ChartCard({ title, hint, children }: { title: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="usage-chart-card">
      <div className="usage-chart-card__head">
        <h3>{title}</h3>
        {hint && <span className="usage-chart-card__hint">{hint}</span>}
      </div>
      {children}
    </div>
  );
}

function StatCard({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="usage-stat" style={{ borderTopColor: accent }}>
      <span className="usage-stat__value">{value.toLocaleString()}</span>
      <span className="usage-stat__label">{label}</span>
    </div>
  );
}

export function AdminUsageTab() {
  const [days, setDays] = useState(7);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [status, setStatus] = useState<{ type: 'error' | 'info'; text: string } | null>(null);
  const [data, setData] = useState<ApiUsageResponse | null>(null);

  const load = useCallback((d: number, isRefresh: boolean) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setStatus(null);
    api.admin.usage(d)
      .then(r => setData(r))
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => { setLoading(false); setRefreshing(false); });
  }, []);

  useEffect(() => { load(days, false); }, [days, load]);

  const totals = data
    ? data.byOutcome.reduce(
        (acc, o) => { acc[o.outcome] = o.total; return acc; },
        {} as Record<string, number>,
      )
    : {};

  // Height grows with the number of users so horizontal bars stay readable.
  const perUserHeight = data ? Math.max(200, data.byUser.length * 34 + 48) : 200;

  return (
    <div className="tab-content formatter-tab usage-tab">
      <div className="section-header">
        <h2>API Usage</h2>
        <span className="form-hint">Per-user threat-intel API consumption</span>
      </div>

      <div className="usage-toolbar">
        <div className="usage-range" role="group" aria-label="Time range">
          {RANGES.map(r => (
            <button
              key={r.days}
              type="button"
              className={`usage-range__btn ${days === r.days ? 'usage-range__btn--active' : ''}`}
              onClick={() => setDays(r.days)}
              disabled={loading || refreshing}
            >
              {r.label}
            </button>
          ))}
        </div>
        <button
          type="button"
          className="usage-refresh"
          onClick={() => load(days, true)}
          disabled={loading || refreshing}
          title="Refresh"
        >
          <span className={`usage-refresh__icon ${refreshing ? 'is-spinning' : ''}`} aria-hidden="true">↻</span>
          {refreshing ? 'Refreshing' : 'Refresh'}
        </button>
      </div>

      {status && <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />}

      {loading && <div className="usage-loading"><Spinner size={16} /> Loading usage…</div>}

      {!loading && data && (
        <>
          <div className="usage-stats">
            <StatCard label="Total calls" value={data.total} accent="#1d6ae5" />
            <StatCard label="OK" value={totals.ok || 0} accent="#0fba81" />
            <StatCard label="Rate-limited" value={totals.rate_limited || 0} accent="#f5a623" />
            <StatCard label="Errors" value={totals.error || 0} accent="#e5484d" />
            <StatCard label="Users" value={data.byUser.length} accent="#a78bfa" />
          </div>

          {data.capped && (
            <StatusMessage
              type="info"
              message={`Showing the most recent ${data.total.toLocaleString()} calls (cap reached) — figures may undercount older activity in this window.`}
            />
          )}

          {data.total === 0 ? (
            <div className="usage-empty">No API usage recorded in the last {data.rangeDays} day(s).</div>
          ) : (
            <div className="usage-grid">
              <ChartCard title="Calls per user" hint="All threat-intel sources combined">
                <ResponsiveContainer width="100%" height={perUserHeight}>
                  <BarChart data={data.byUser} layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" horizontal={false} />
                    <XAxis type="number" tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                    <YAxis type="category" dataKey="username" tick={AXIS_STYLE} stroke="#1e304d" width={96} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} />
                    <Bar dataKey="total" name="Total calls" fill="#1d6ae5" radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="Outcomes per user" hint="OK vs rate-limited vs error">
                <ResponsiveContainer width="100%" height={perUserHeight}>
                  <BarChart data={data.byUser} layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" horizontal={false} />
                    <XAxis type="number" tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                    <YAxis type="category" dataKey="username" tick={AXIS_STYLE} stroke="#1e304d" width={96} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} formatter={(v, n) => [v as number, outcomeLabel(String(n))]} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#5a7aa8' }} formatter={(v) => outcomeLabel(String(v))} />
                    <Bar dataKey="ok" stackId="o" fill={OUTCOME_COLORS.ok} radius={[0, 0, 0, 0]} />
                    <Bar dataKey="rate_limited" stackId="o" fill={OUTCOME_COLORS.rate_limited} radius={[0, 0, 0, 0]} />
                    <Bar dataKey="error" stackId="o" fill={OUTCOME_COLORS.error} radius={[0, 4, 4, 0]} />
                  </BarChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="TI usage over time" hint="Calls per day by threat-intel source">
                {data.byDay.length === 0 ? (
                  <div className="usage-empty usage-empty--sm">No threat-intel calls in this window.</div>
                ) : (
                  (() => {
                    // Collect every service key from all days (keys other than "day").
                    const svcSet = new Set<string>();
                    for (const d of data.byDay) {
                      for (const k of Object.keys(d)) {
                        if (k !== 'day') svcSet.add(k);
                      }
                    }
                    const services = [...svcSet].sort();
                    if (services.length === 0) {
                      return <div className="usage-empty usage-empty--sm">No threat-intel calls in this window.</div>;
                    }
                    function svcColor(svc: string, i: number) {
                      return SERVICE_COLORS[svc] || FALLBACK_PALETTE[i % FALLBACK_PALETTE.length];
                    }
                    return (
                      <ResponsiveContainer width="100%" height={260}>
                        <AreaChart data={data.byDay} margin={{ top: 4, right: 18, bottom: 4, left: 0 }}>
                          <defs>
                            {services.map(svc => (
                              <linearGradient key={svc} id={`byDay-grad-${svc.replace(/\s+/g, '-')}`} x1="0" y1="0" x2="0" y2="1">
                                <stop offset="0%" stopColor={svcColor(svc, 0)} stopOpacity={0.45} />
                                <stop offset="100%" stopColor={svcColor(svc, 0)} stopOpacity={0} />
                              </linearGradient>
                            ))}
                          </defs>
                          <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" vertical={false} />
                          <XAxis dataKey="day" tick={AXIS_STYLE} stroke="#1e304d" />
                          <YAxis tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                          <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: '#2a5298' }} />
                          <Legend wrapperStyle={{ fontSize: 11, color: '#5a7aa8' }} />
                          {services.map((svc, i) => (
                            <Area
                              key={svc}
                              type="monotone"
                              dataKey={svc}
                              name={svc}
                              stroke={svcColor(svc, i)}
                              strokeWidth={2}
                              fill={`url(#byDay-grad-${svc.replace(/\s+/g, '-')})`}
                            />
                          ))}
                        </AreaChart>
                      </ResponsiveContainer>
                    );
                  })()
                )}
              </ChartCard>
            </div>
          )}

          {data.recent.length > 0 && (
            <div className="usage-recent">
              <h3>Recent calls <span className="usage-recent__note">(last {data.recent.length})</span></h3>
              <div className="usage-recent__scroll">
                <table className="usage-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>User</th>
                      <th>Service</th>
                      <th>IOC type</th>
                      <th>Outcome</th>
                      <th>Key</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.recent.map((r, i) => (
                      <tr key={i}>
                        <td className="usage-table__time">{new Date(r.created_at).toLocaleString()}</td>
                        <td>{r.username || '—'}</td>
                        <td>{r.service}</td>
                        <td>{r.ioc_type || '—'}</td>
                        <td>
                          <span className={`usage-outcome usage-outcome--${r.outcome}`}>
                            {outcomeLabel(r.outcome)}
                          </span>
                        </td>
                        <td className="usage-table__key">{r.api_key || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  );
}
