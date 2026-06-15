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
  // Time window state: from/to ISO strings for the datetime-local inputs.
  const now = new Date();
  const [from, setFrom] = useState(() => new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000).toISOString().slice(0, 16));
  const [to, setTo] = useState(() => now.toISOString().slice(0, 16));
  const [activePreset, setActivePreset] = useState('7d');
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [status, setStatus] = useState<{ type: 'error' | 'info'; text: string } | null>(null);
  const [data, setData] = useState<ApiUsageResponse | null>(null);

  const load = useCallback((f: string, t: string, isRefresh: boolean) => {
    if (isRefresh) setRefreshing(true); else setLoading(true);
    setStatus(null);
    api.admin.usage({ from: new Date(f).toISOString(), to: new Date(t).toISOString() })
      .then(r => setData(r))
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => { setLoading(false); setRefreshing(false); });
  }, []);

  useEffect(() => { load(from, to, false); }, [from, to, load]);

  function setQuickRange(label: string, hoursBack: number) {
    setActivePreset(label);
    const t = new Date();
    const f = new Date(t.getTime() - hoursBack * 60 * 60 * 1000);
    setFrom(f.toISOString().slice(0, 16));
    setTo(t.toISOString().slice(0, 16));
  }

  function handleFromToChange() {
    setActivePreset('');
    load(from, to, true);
  }

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
        <div className="usage-range" role="group" aria-label="Quick time range">
          {[{l:'15m',h:0.25},{l:'1h',h:1},{l:'6h',h:6},{l:'24h',h:24},{l:'7d',h:168},{l:'30d',h:720}].map(r => (
            <button
              key={r.l}
              type="button"
              className={`usage-range__btn ${activePreset === r.l ? 'usage-range__btn--active' : ''}`}
              onClick={() => setQuickRange(r.l, r.h)}
              disabled={loading || refreshing}
            >
              {r.l}
            </button>
          ))}
        </div>
        <div className="usage-datetime-row">
          <label className="usage-dt-label">
            From
            <input
              type="datetime-local"
              className="usage-datetime"
              value={from}
              onChange={e => { setFrom(e.target.value); setActivePreset(''); }}
              onBlur={handleFromToChange}
              disabled={loading || refreshing}
            />
          </label>
          <label className="usage-dt-label">
            To
            <input
              type="datetime-local"
              className="usage-datetime"
              value={to}
              onChange={e => { setTo(e.target.value); setActivePreset(''); }}
              onBlur={handleFromToChange}
              disabled={loading || refreshing}
            />
          </label>
          <button
            type="button"
            className="usage-refresh"
            onClick={() => load(from, to, true)}
            disabled={loading || refreshing}
            title="Refresh"
          >
            <span className={`usage-refresh__icon ${refreshing ? 'is-spinning' : ''}`} aria-hidden="true">↻</span>
            {refreshing ? 'Refreshing' : 'Refresh'}
          </button>
        </div>
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
            <div className="usage-empty">No API usage recorded in this time window.</div>
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

              <ChartCard title="TI usage over time" hint={data.bucket === '30m' ? 'per 30 min' : data.bucket === '1w' ? 'per week' : 'per day'}>
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
