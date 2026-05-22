import { confClass, confLabel } from '../../lib/ioc';
import { Spinner } from '../shared/Spinner';

interface Source {
  source: string;
  verdict?: string;
  skipped?: boolean;
  error?: string;
  detail?: string;
  weight?: number;
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

      {(data.sources ?? []).map((src, i) => (
        <div className="source-row" key={i}>
          <div className="source-row-main">
            <span className="source-name">{src.source}</span>
            <span className={`source-verdict sv-${sourceVerdict(src).toLowerCase().replace(/[^a-z]/g, '_')}`}>
              {sourceVerdict(src).toUpperCase()}
            </span>
          </div>
          {src.detail && (
            <div className="source-detail">{src.detail}</div>
          )}
        </div>
      ))}
    </div>
  );
}
