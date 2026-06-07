import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api';
import { calcVerdict, countryFlag, confLabel, confClass, hashLabel } from '../lib/ioc';
import { DetectionBar } from '../components/vt/DetectionBar';
import { CorrelationPanel } from '../components/vt/CorrelationPanel';
import { Spinner } from '../components/shared/Spinner';
import '../styles/ui-improvements.css';

type IocType = 'ip' | 'domain' | 'hash';

interface CacheRow {
  ip?: string;           // present on legacy vt_ip_cache rows
  ioc?: string;          // present on vt_ioc_cache rows; by-id also backfills it for IPs
  ioc_type?: IocType;    // 'ip' for vt_ip_cache rows (backfilled by the endpoint)
  vt_verdict: string | null;
  vt_stats: Record<string, number> | null;
  vt_payload: Record<string, unknown> | null;
  corr_confidence: number | null;
  corr_payload: Record<string, unknown> | null;
  first_scanned_at: string;
}

// The persisted correlation payload (api/correlate.js response shape).
interface CorrPayload {
  confidence?: number;
  baselineConfidence?: number | null;
  floor?: number;
  bonus?: number;
  sources?: Array<{ source: string; meta?: Record<string, string | number> }>;
  riskFactors?: unknown[];
}

const TYPE_NOUN: Record<IocType, string> = { ip: 'IP', domain: 'Domain', hash: 'File' };
const VT_PATH: Record<IocType, string> = { ip: 'ip-address', domain: 'domain', hash: 'file' };

function buildTakeaway(type: IocType): Record<string, { title: string; body: string }> {
  const noun = TYPE_NOUN[type];
  const subject = type === 'hash' ? 'This file' : `This ${noun}`;
  return {
    malicious: {
      title: `${subject} is flagged as malicious`,
      body: `More than 3 AV engines flagged this indicator as malicious. We recommend blocking it and investigating any related connections or activity.`,
    },
    suspicious: {
      title: `${subject} looks suspicious`,
      body: `This indicator shows signs of suspicious activity. Investigate further before taking any blocking action.`,
    },
    clean: {
      title: `${subject} appears clean`,
      body: `No AV engine flagged this indicator as harmful. Stay alert and keep monitoring related activity.`,
    },
  };
}

const fmtUnix = (u: unknown) =>
  typeof u === 'number' ? new Date(u * 1000).toLocaleDateString('en-GB') : '—';

/** Per-type meta grid rows: [label, value, colorClass]. */
function buildMetaRows(
  type: IocType,
  stats: Record<string, number>,
  attrs: Record<string, unknown>,
  flag: string,
  ctry: string,
): Array<[string, string, string]> {
  const mal = stats.malicious ?? 0;
  const sus = stats.suspicious ?? 0;
  const common: Array<[string, string, string]> = [
    ['Malicious', String(mal), mal > 0 ? 'red' : 'green'],
    ['Suspicious', String(sus), sus > 0 ? 'yellow' : ''],
    ['Undetected', String(stats.undetected ?? 0), ''],
  ];
  const rep = attrs.reputation !== undefined ? String(attrs.reputation) : '—';

  if (type === 'domain') {
    const cats =
      Object.values((attrs.categories as Record<string, string>) ?? {}).slice(0, 3).join(', ') || '—';
    return [
      ...common,
      ['Registrar', String(attrs.registrar ?? '—'), 'purple'],
      ['Created', fmtUnix(attrs.creation_date), 'cyan'],
      ['Updated', fmtUnix(attrs.last_update_date), ''],
      ['Categories', cats, ''],
      ['Reputation', rep, ''],
    ];
  }

  if (type === 'hash') {
    const names = ((attrs.names as string[] | undefined) ?? []).slice(0, 3).join(', ') || '—';
    const size = typeof attrs.size === 'number' ? (attrs.size / 1024).toFixed(1) + ' KB' : '—';
    const ftype = String(attrs.type_description ?? attrs.magic ?? '—');
    return [
      ...common,
      ['File Type', ftype, 'purple'],
      ['Size', size, ''],
      ['File Names', names, ''],
      ['First Seen', fmtUnix(attrs.first_submission_date), 'cyan'],
      ['Last Scan', fmtUnix(attrs.last_analysis_date), ''],
    ];
  }

  // ip
  return [
    ...common,
    ['Country', (flag ? flag + ' ' : '') + (ctry || '—'), 'cyan'],
    ['ASN', attrs.asn ? 'AS' + String(attrs.asn) : '—', 'purple'],
    ['AS Owner', String(attrs.as_owner ?? '—'), ''],
    ['Network', String(attrs.network ?? '—'), ''],
    ['Reputation', rep, ''],
  ];
}

export function ResultPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CacheRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) { setError('Invalid ID.'); setLoading(false); return; }
    api.ipCache.byId(id)
      .then(res => {
        // by-id returns { ok, item }
        const row = (res as { item?: CacheRow }).item ?? null;
        if (!row) throw new Error('Data not found.');
        setData(row);
      })
      .catch(err => setError(err instanceof Error ? err.message : String(err)))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: 'var(--bg-base,#080d17)', color: 'var(--text-muted,#6b7f9a)' }}>
      <Spinner size={32} />
    </div>
  );

  if (error || !data) return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', background: 'var(--bg-base,#080d17)', color: 'var(--text-muted,#6b7f9a)', gap: '1rem' }}>
      <div style={{ color: '#f87171', fontSize: '1rem' }}>{error ?? 'Data not found.'}</div>
      <Link to="/" style={{ color: 'var(--accent,#3b82f6)', textDecoration: 'none', fontSize: '0.85rem' }}>← Back to app</Link>
    </div>
  );

  const type: IocType = data.ioc_type ?? 'ip';
  const iocValue = data.ioc ?? data.ip ?? '';

  const stats = data.vt_stats ?? {};
  const mal = stats.malicious ?? 0;
  const sus = stats.suspicious ?? 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const v = calcVerdict(mal, sus, total);
  const vKey = v.label.toLowerCase();
  const takeaway = buildTakeaway(type)[vKey] ?? buildTakeaway(type).clean;

  // vt_payload is stored FLAT (the attribute subset), not nested under data.attributes.
  const vtAttrs = (data.vt_payload as Record<string, unknown> | null) ?? {};
  const flag = type === 'ip' ? countryFlag(String(vtAttrs.country ?? '')) : '';
  const ctry = type === 'ip' ? String(vtAttrs.country ?? '') : '';
  const metaRows = buildMetaRows(type, stats, vtAttrs, flag, ctry);

  const badgeCls = type === 'ip' ? 'badge-ip' : type === 'domain' ? 'badge-domain' : 'badge-hash';
  const badgeLabel = type === 'ip' ? 'IP ADDRESS' : type === 'domain' ? 'DOMAIN' : hashLabel(iocValue.length);

  // Persisted correlation breakdown (sources + risk factors + scoring math).
  const corr = (data.corr_payload && typeof data.corr_payload === 'object')
    ? data.corr_payload as CorrPayload
    : null;
  const hasCorr = !!corr && (typeof corr.confidence === 'number' || (Array.isArray(corr.sources) && corr.sources.length > 0));
  const enrichment = corr?.sources?.find(s => s.source === 'Enrichment')?.meta ?? null;

  // Fallback for legacy rows scanned before correlation was persisted.
  const corrConf = data.corr_confidence;
  const corrLabel = confLabel(corrConf ?? null);
  const corrCls = confClass(corrConf ?? null);

  return (
    <div style={{ minHeight: '100vh', background: 'var(--bg-base,#080d17)', padding: '2rem 1rem' }}>
      <div style={{ maxWidth: 780, margin: '0 auto' }}>
        {/* Back link */}
        <Link to="/" style={{ color: 'var(--text-muted,#6b7f9a)', textDecoration: 'none', fontSize: '0.8rem', display: 'inline-block', marginBottom: '1.5rem' }}>
          ← Charlie kerennnn
        </Link>

        {/* IOC header */}
        <div className="vt-card" style={{ marginBottom: '0.75rem' }}>
          <div className="vt-card-header" style={{ cursor: 'default' }}>
            <span className={`vt-type-badge ${badgeCls}`}>{badgeLabel}</span>
            <span className="vt-ioc-val">{iocValue}</span>
            {flag && <span className="ctry-badge">{flag} {ctry}</span>}
            <span className={`verdict ${v.cls}`}>● {v.label}</span>
          </div>
          <div className="vt-card-body">
            <DetectionBar malicious={mal} suspicious={sus} total={total} />

            <div className="meta-grid" style={{ marginTop: '0.75rem' }}>
              {metaRows.map(([k, val, cls], i) => (
                <div className="meta-item" key={i}>
                  <div className="mk">{k}</div>
                  <div className={`mv${cls ? ' ' + cls : ''}`}>{val}</div>
                </div>
              ))}
            </div>

            <a className="vt-open-link" href={`https://www.virustotal.com/gui/${VT_PATH[type]}/${iocValue}`} target="_blank" rel="noopener">
              ↗ Open in VirusTotal
            </a>
          </div>
        </div>

        {/* Threat intel — full breakdown (sources + why this verdict) + scoring math */}
        {hasCorr ? (
          <div className="vt-card" style={{ marginBottom: '0.75rem' }}>
            <div className="vt-card-body" style={{ borderTop: 'none' }}>
              <CorrelationPanel loading={false} data={corr as Parameters<typeof CorrelationPanel>[0]['data']} />

              {typeof corr!.confidence === 'number' && (
                <div className="score-breakdown">
                  <div className="score-breakdown-title">Score Breakdown</div>
                  <div className="score-breakdown-grid">
                    <div className="sb-item"><span className="sb-k">Baseline</span><span className="sb-v">{corr!.baselineConfidence ?? '—'}%</span></div>
                    <div className="sb-item"><span className="sb-k">Risk floor</span><span className="sb-v">{corr!.floor ?? 0}</span></div>
                    <div className="sb-item"><span className="sb-k">Factor bonus</span><span className="sb-v">+{corr!.bonus ?? 0}</span></div>
                    <div className="sb-item"><span className="sb-k">Final</span><span className="sb-v sb-final">{corr!.confidence}%</span></div>
                  </div>
                  <div className="score-breakdown-formula">
                    Final = min(100, max(baseline {corr!.baselineConfidence ?? 0}, floor {corr!.floor ?? 0}) + bonus {corr!.bonus ?? 0})
                  </div>
                </div>
              )}
            </div>
          </div>
        ) : corrConf !== null && (
          <div className="vt-card" style={{ marginBottom: '0.75rem' }}>
            <div className="vt-card-body" style={{ borderTop: 'none' }}>
              <div className="corr-header">
                <span className="corr-title">Threat Intelligence</span>
                <span className={`corr-badge ${corrCls}`}>{corrLabel}</span>
                <span className="corr-score">{corrConf}%</span>
              </div>
              <div className="corr-bar-bg" style={{ marginBottom: 0 }}>
                <div className="corr-bar-fill" style={{
                  width: `${Math.min(corrConf, 100)}%`,
                  background: corrConf >= 70 ? 'var(--red)' : corrConf >= 40 ? 'var(--orange)' : corrConf >= 15 ? 'var(--yellow)' : 'var(--green)',
                }} />
              </div>
            </div>
          </div>
        )}

        {/* Enrichment highlight (RDAP / GeoIP) */}
        {enrichment && Object.keys(enrichment).length > 0 && (
          <div className="vt-card" style={{ marginBottom: '0.75rem' }}>
            <div className="vt-card-body" style={{ borderTop: 'none' }}>
              <div className="score-breakdown-title">Enrichment · RDAP / GeoIP</div>
              <div className="meta-grid" style={{ marginTop: '0.5rem' }}>
                {Object.entries(enrichment).filter(([k]) => k !== 'GeoSource').map(([k, val]) => (
                  <div className="meta-item" key={k}>
                    <div className="mk">{k}</div>
                    <div className="mv">{String(val)}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Educational takeaway */}
        <div className="vt-card">
          <div className="vt-card-body" style={{ borderTop: 'none' }}>
            <div style={{ fontSize: '0.75rem', fontFamily: 'Syne,sans-serif', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted,#6b7f9a)', marginBottom: '0.5rem' }}>
              Recommendation
            </div>
            <div style={{ fontFamily: 'Syne,sans-serif', fontWeight: 700, fontSize: '0.95rem', color: 'var(--text-primary,#e8f0fe)', marginBottom: '0.375rem' }}>
              {takeaway.title}
            </div>
            <div style={{ fontSize: '0.82rem', color: 'var(--text-secondary,#a3b3cc)', lineHeight: 1.6 }}>
              {takeaway.body}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
