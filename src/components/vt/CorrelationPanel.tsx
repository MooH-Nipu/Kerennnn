import { useState } from 'react';
import { confClass, confLabel } from '../../lib/ioc';
import { Spinner } from '../shared/Spinner';

interface Source {
  source: string;
  verdict?: string;
  skipped?: boolean;
  error?: string;
  detail?: string;
  weight?: number;
  score?: number;
  meta?: Record<string, string | number>;
}

interface CorrData {
  confidence: number;
  verdict?: string;
  sources?: Source[];
  error?: string;
}

interface Props {
  loading: boolean;
  data: CorrData | null;
}

function sourceVerdict(s: Source): string {
  if (s.verdict) return s.verdict;
  if (s.skipped) return 'skipped';
  if (s.error)   return 'error';
  return 'unknown';
}

export function CorrelationPanel({ loading, data }: Props) {
  const [expandedSources, setExpandedSources] = useState<Set<string>>(new Set());

  const toggleSource = (name: string) => {
    setExpandedSources(prev => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name); else next.add(name);
      return next;
    });
  };

  if (loading) {
    return (
      <div className="corr-panel">
        <div className="corr-loading">
          <Spinner size={14} /> Memuat threat intel…
        </div>
      </div>
    );
  }

  if (!data) return null;

  if (data.error) {
    return (
      <div className="corr-panel">
        <div className="corr-loading" style={{ color: 'var(--red)' }}>⚠ {data.error}</div>
      </div>
    );
  }

  const cls = confClass(data.confidence);
  const label = confLabel(data.confidence);
  const barColor =
    data.confidence >= 70 ? 'var(--red)' :
    data.confidence >= 40 ? 'var(--orange)' :
    data.confidence >= 15 ? 'var(--yellow)' :
    'var(--green)';

  return (
    <div className="corr-panel">
      <div className="corr-header">
        <span className="corr-title">Threat Intelligence</span>
        <span className={`corr-badge ${cls}`}>{label}</span>
        <span className="corr-score">{data.confidence}%</span>
      </div>

      <div className="corr-bar-bg">
        <div
          className="corr-bar-fill"
          style={{ width: `${Math.min(data.confidence, 100)}%`, background: barColor }}
        />
      </div>

      {(data.sources ?? []).map((src, i) => {
        const verdict = sourceVerdict(src);
        const expanded = expandedSources.has(src.source);
        const hasMeta = !!src.meta && Object.keys(src.meta).length > 0;
        const isExpandable = !src.skipped && !src.error && hasMeta;

        return (
          <div className="source-row" key={i}>
            <div
              className={`source-row-main${isExpandable ? ' source-row-main--clickable' : ''}`}
              onClick={isExpandable ? () => toggleSource(src.source) : undefined}
            >
              {isExpandable
                ? <span className={`source-chevron${expanded ? ' open' : ''}`}>›</span>
                : <span className="source-chevron-placeholder" />
              }
              <span className="source-name">{src.source}</span>
              <span className={`source-verdict sv-${verdict.toLowerCase().replace(/[^a-z]/g, '_')}`}>
                {verdict.toUpperCase()}
              </span>
            </div>
            {expanded && hasMeta && (
              <div className="source-meta">
                {Object.entries(src.meta!).map(([k, v]) => (
                  <div key={k} className="source-meta-item">
                    <span className="source-meta-key">{k}</span>
                    <span className="source-meta-val">{v}</span>
                  </div>
                ))}
              </div>
            )}
            {src.detail && !expanded && (
              <div className="source-detail">{src.detail}</div>
            )}
          </div>
        );
      })}
    </div>
  );
}
