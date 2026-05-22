import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import { api } from '../lib/api';
import { calcVerdict, countryFlag, confLabel, confClass } from '../lib/ioc';
import { DetectionBar } from '../components/vt/DetectionBar';
import { Spinner } from '../components/shared/Spinner';
import '../styles/ui-improvements.css';

interface CacheRow {
  ip: string;
  vt_verdict: string | null;
  vt_stats: Record<string, number> | null;
  vt_payload: Record<string, unknown> | null;
  corr_confidence: number | null;
  corr_payload: Record<string, unknown> | null;
  first_scanned_at: string;
}

const TAKEAWAY: Record<string, { title: string; body: string }> = {
  malicious: {
    title: 'IP ini terdeteksi berbahaya',
    body: 'Lebih dari 3 engine AV mendeteksi IP ini sebagai malicious. Disarankan untuk memblokir IP ini di firewall dan menginvestigasi koneksi terkait.',
  },
  suspicious: {
    title: 'IP ini mencurigakan',
    body: 'IP ini menunjukkan tanda-tanda aktivitas mencurigakan. Lakukan investigasi lebih lanjut sebelum mengambil tindakan blokir.',
  },
  clean: {
    title: 'IP ini tampak bersih',
    body: 'Tidak ada engine AV yang mendeteksi IP ini sebagai berbahaya. Tetap waspada dan pantau aktivitas terkait.',
  },
};

export function ResultPage() {
  const { id } = useParams<{ id: string }>();
  const [data, setData] = useState<CacheRow | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!id) { setError('ID tidak valid.'); setLoading(false); return; }
    api.ipCache.byId(id)
      .then(res => {
        const row = (res as { data?: CacheRow }).data ?? null;
        if (!row) throw new Error('Data tidak ditemukan.');
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
      <div style={{ color: '#f87171', fontSize: '1rem' }}>{error ?? 'Data tidak ditemukan.'}</div>
      <Link to="/" style={{ color: 'var(--accent,#3b82f6)', textDecoration: 'none', fontSize: '0.85rem' }}>← Kembali ke app</Link>
    </div>
  );

  const stats = data.vt_stats ?? {};
  const mal = stats.malicious ?? 0;
  const sus = stats.suspicious ?? 0;
  const total = Object.values(stats).reduce((a, b) => a + b, 0);
  const v = calcVerdict(mal, sus, total);
  const vKey = v.label.toLowerCase() as keyof typeof TAKEAWAY;
  const takeaway = TAKEAWAY[vKey] ?? TAKEAWAY.clean;

  const vtAttrs = ((data.vt_payload as Record<string, unknown> | null)?.data as Record<string, unknown> | undefined)?.attributes as Record<string, unknown> | undefined;
  const flag = countryFlag(String(vtAttrs?.country ?? ''));
  const ctry = String(vtAttrs?.country ?? '');

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

        {/* IP header */}
        <div className="vt-card" style={{ marginBottom: '0.75rem' }}>
          <div className="vt-card-header" style={{ cursor: 'default' }}>
            <span className="vt-type-badge badge-ip">IP ADDRESS</span>
            <span className="vt-ioc-val">{data.ip}</span>
            {flag && <span className="ctry-badge">{flag} {ctry}</span>}
            <span className={`verdict ${v.cls}`}>● {v.label}</span>
          </div>
          <div className="vt-card-body">
            <DetectionBar malicious={mal} suspicious={sus} total={total} />

            <div className="meta-grid" style={{ marginTop: '0.75rem' }}>
              {[
                ['Malicious', mal, mal > 0 ? 'red' : 'green'],
                ['Suspicious', sus, sus > 0 ? 'yellow' : ''],
                ['Undetected', stats.undetected ?? 0, ''],
                ['Country', (flag ? flag + ' ' : '') + (ctry || '—'), 'cyan'],
                ['ASN', vtAttrs?.asn ? 'AS' + String(vtAttrs.asn) : '—', 'purple'],
                ['AS Owner', String(vtAttrs?.as_owner ?? '—'), ''],
                ['Network', String(vtAttrs?.network ?? '—'), ''],
                ['Reputation', String(vtAttrs?.reputation ?? '—'), ''],
              ].map(([k, val, cls], i) => (
                <div className="meta-item" key={i}>
                  <div className="mk">{k}</div>
                  <div className={`mv${cls ? ' ' + cls : ''}`}>{String(val)}</div>
                </div>
              ))}
            </div>

            <a className="vt-open-link" href={`https://www.virustotal.com/gui/ip-address/${data.ip}`} target="_blank" rel="noopener">
              ↗ Open in VirusTotal
            </a>
          </div>
        </div>

        {/* Threat intel */}
        {corrConf !== null && (
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

        {/* Educational takeaway */}
        <div className="vt-card">
          <div className="vt-card-body" style={{ borderTop: 'none' }}>
            <div style={{ fontSize: '0.75rem', fontFamily: 'Syne,sans-serif', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted,#6b7f9a)', marginBottom: '0.5rem' }}>
              Rekomendasi
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
