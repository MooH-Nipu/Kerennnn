import { useState, useEffect, useCallback } from 'react';
import {
  ResponsiveContainer,
  BarChart, Bar,
  PieChart, Pie, Cell,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import type { ApiUsageResponse } from '../types/api';

// Chart palette — pulled from the app theme (styles.css :root).
const PALETTE = ['#1d6ae5', '#0fba81', '#a78bfa', '#38bdf8', '#fb923c', '#f5a623', '#e5484d', '#2f7ef7', '#7eb3ff'];
const OUTCOME_COLORS: Record<string, string> = {
  ok: '#0fba81',
  rate_limited: '#f5a623',
  error: '#e5484d',
};

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

function colorFor(i: number) {
  return PALETTE[i % PALETTE.length];
}

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

  return (
    <div className="tab-content formatter-tab usage-tab">
      <div className="section-header">
        <h2>API Usage</h2>
        <span className="form-hint">Per-user threat-intel API consumption</span>
      </div>

      <div className="usage-toolbar">
        <div className="usage-range">
          {RANGES.map(r => (
            <button
              key={r.days}
              className={`btn btn-sm ${days === r.days ? 'btn-primary' : 'btn-ghost'}`}
              onClick={() => setDays(r.days)}
              disabled={loading || refreshing}
            >
              {r.label}
            </button>
          ))}
        </div>
        <button
          className="btn btn-ghost btn-sm"
          onClick={() => load(days, true)}
          disabled={loading || refreshing}
        >
          {refreshing ? 'Refreshing…' : '↻ Refresh'}
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
              <ChartCard title="Calls per user, by service" hint="Stacked by upstream service">
                <ResponsiveContainer width="100%" height={Math.max(220, data.perUserService.length * 38 + 40)}>
                  <BarChart
                    data={data.perUserService}
                    layout="vertical"
                    margin={{ top: 4, right: 16, bottom: 4, left: 8 }}
                  >
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" horizontal={false} />
                    <XAxis type="number" tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                    <YAxis type="category" dataKey="username" tick={AXIS_STYLE} stroke="#1e304d" width={90} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} />
                    <Legend wrapperStyle={{ fontSize: 11, color: '#5a7aa8' }} />
                    {data.services.map((svc, i) => (
                      <Bar key={svc} dataKey={svc} stackId="svc" fill={colorFor(i)} radius={[0, 0, 0, 0]} />
                    ))}
                  </BarChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="Outcomes" hint="OK vs rate-limited vs error">
                <ResponsiveContainer width="100%" height={240}>
                  <PieChart>
                    <Pie
                      data={data.byOutcome}
                      dataKey="total"
                      nameKey="outcome"
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={90}
                      paddingAngle={2}
                      label={({ name }) => outcomeLabel(String(name ?? ''))}
                    >
                      {data.byOutcome.map(o => (
                        <Cell key={o.outcome} fill={OUTCOME_COLORS[o.outcome] || '#5a7aa8'} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={TOOLTIP_STYLE} formatter={(value, name) => [value as number, outcomeLabel(String(name))]} />
                  </PieChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="Calls by service" hint="Total per upstream API">
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={data.byService} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" vertical={false} />
                    <XAxis dataKey="service" tick={AXIS_STYLE} stroke="#1e304d" interval={0} angle={-20} textAnchor="end" height={56} />
                    <YAxis tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} />
                    <Bar dataKey="total" radius={[4, 4, 0, 0]}>
                      {data.byService.map((s, i) => <Cell key={s.service} fill={colorFor(i)} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </ChartCard>

              <ChartCard title="VirusTotal key usage" hint="Calls per rotated VT API key">
                {data.byVtKey.length === 0 ? (
                  <div className="usage-empty usage-empty--sm">No VirusTotal key usage in this window.</div>
                ) : (
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={data.byVtKey} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" vertical={false} />
                      <XAxis dataKey="vt_key" tick={AXIS_STYLE} stroke="#1e304d" interval={0} />
                      <YAxis tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} />
                      <Bar dataKey="total" radius={[4, 4, 0, 0]} fill="#38bdf8" />
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </ChartCard>

              <ChartCard title="Calls over time" hint="Daily volume">
                <ResponsiveContainer width="100%" height={240}>
                  <AreaChart data={data.byDay} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
                    <defs>
                      <linearGradient id="usageArea" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#1d6ae5" stopOpacity={0.5} />
                        <stop offset="100%" stopColor="#1d6ae5" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" vertical={false} />
                    <XAxis dataKey="day" tick={AXIS_STYLE} stroke="#1e304d" />
                    <YAxis tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: '#2a5298' }} />
                    <Area type="monotone" dataKey="total" stroke="#1d6ae5" strokeWidth={2} fill="url(#usageArea)" />
                  </AreaChart>
                </ResponsiveContainer>
              </ChartCard>

              {data.byIocType.length > 0 && (
                <ChartCard title="Calls by IOC type" hint="ip / domain / hash / etc.">
                  <ResponsiveContainer width="100%" height={240}>
                    <BarChart data={data.byIocType} margin={{ top: 4, right: 16, bottom: 4, left: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="#1e304d" vertical={false} />
                      <XAxis dataKey="ioc_type" tick={AXIS_STYLE} stroke="#1e304d" interval={0} />
                      <YAxis tick={AXIS_STYLE} stroke="#1e304d" allowDecimals={false} />
                      <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(29,106,229,0.08)' }} />
                      <Bar dataKey="total" radius={[4, 4, 0, 0]}>
                        {data.byIocType.map((s, i) => <Cell key={s.ioc_type} fill={colorFor(i + 2)} />)}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </ChartCard>
              )}
            </div>
          )}

          {data.recent.length > 0 && (
            <div className="usage-recent">
              <h3>Recent calls</h3>
              <div className="usage-recent__scroll">
                <table className="usage-table">
                  <thead>
                    <tr>
                      <th>Time</th>
                      <th>User</th>
                      <th>Service</th>
                      <th>IOC type</th>
                      <th>Outcome</th>
                      <th>VT key</th>
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
                        <td className="usage-table__key">{r.vt_key || '—'}</td>
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

function StatCard({ label, value, accent }: { label: string; value: number; accent: string }) {
  return (
    <div className="usage-stat" style={{ borderTopColor: accent }}>
      <span className="usage-stat__value">{value.toLocaleString()}</span>
      <span className="usage-stat__label">{label}</span>
    </div>
  );
}
