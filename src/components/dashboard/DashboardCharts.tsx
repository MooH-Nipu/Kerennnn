import {
  ResponsiveContainer,
  BarChart, Bar,
  AreaChart, Area,
  XAxis, YAxis, CartesianGrid, Tooltip, Legend,
} from 'recharts';
import type { ApiUsageResponse } from '../../types/api';

interface Props {
  section: 'analysis' | 'usage';
  scanTimeline: Array<{ time: string; scans: number; source?: string }>;
  scanTimelineBucket: string | null;
  userScanChartData: Array<{ username: string; scans: number }>;
  usageData: ApiUsageResponse | null;
}

const SERVICE_COLORS: Record<string, string> = {
  VirusTotal: 'var(--color-primary)',
  AbuseIPDB: 'var(--color-danger)',
  'Abuse.ch': 'var(--color-warning)',
  MalwareBazaar: '#f472b6',
  'AlienVault OTX': '#a78bfa',
  'URLScan.io': 'var(--color-success)',
  Enrichment: 'var(--color-info)',
  'Passive DNS': '#fb923c',
  'crt.sh': '#a3e635',
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

export default function DashboardCharts({ section, scanTimeline, scanTimelineBucket, userScanChartData, usageData }: Props) {
  const services = [...new Set((usageData?.byDay ?? []).flatMap(day => Object.keys(day).filter(key => key !== 'day' && key !== 'Unknown')))].sort();
  const serviceColor = (service: string, index: number) => SERVICE_COLORS[service] || FALLBACK_PALETTE[index % FALLBACK_PALETTE.length];

  return (
    <>
      {section === 'analysis' && <div className="dash-analysis-grid dash-analysis-grid--stable">
        <div className="card">
          <div className="card__header">
            <h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>IP scans over time</h3>
            <span className="badge badge--soft" style={{ marginLeft: 'auto' }}>{scanTimelineBucket ?? '—'} buckets</span>
          </div>
          <div className="card__body dash-chart-body">
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
          <div className="card__body dash-chart-body">
            {userScanChartData.length > 0 ? (
              <div style={{ padding: '0 1rem 0.5rem 0.25rem' }}>
                <ResponsiveContainer width="100%" height={Math.max(200, userScanChartData.length * 34 + 48)}>
                  <BarChart data={userScanChartData} layout="vertical" margin={{ top: 4, right: 18, bottom: 4, left: 8 }}>
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
      </div>}

      {section === 'usage' && <div className="card dash-usage-slot">
        <div className="card__header"><h3 className="card__title" style={{ fontSize: '0.85rem', fontWeight: 600 }}>TI usage over time</h3></div>
        <div className="card__body" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '0 1rem 0.5rem 0.25rem' }}>
            {services.length > 0 && usageData ? (
              <ResponsiveContainer width="100%" height={260}>
                <AreaChart data={usageData.byDay} margin={{ top: 4, right: 18, bottom: 4, left: 0 }}>
                  <defs>
                    {services.map((service, index) => (
                      <linearGradient key={service} id={`byDay-grad-${service.replace(/\s+/g, '-')}`} x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor={serviceColor(service, index)} stopOpacity={0.45} />
                        <stop offset="100%" stopColor={serviceColor(service, index)} stopOpacity={0} />
                      </linearGradient>
                    ))}
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--color-border)" vertical={false} />
                  <XAxis dataKey="day" tick={AXIS_STYLE} stroke="var(--color-border)" />
                  <YAxis tick={AXIS_STYLE} stroke="var(--color-border)" allowDecimals={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ stroke: 'var(--color-primary)' }} />
                  <Legend wrapperStyle={{ fontSize: 11, color: 'var(--color-muted-foreground)' }} />
                  {services.map((service, index) => (
                    <Area key={service} type="monotone" dataKey={service} name={service} stroke={serviceColor(service, index)} strokeWidth={2} fill={`url(#byDay-grad-${service.replace(/\s+/g, '-')})`} />
                  ))}
                </AreaChart>
              </ResponsiveContainer>
            ) : <div className="empty-state"><p className="empty-state__text">No threat-intel calls in this window.</p></div>}
          </div>
        </div>
      </div>}
    </>
  );
}
