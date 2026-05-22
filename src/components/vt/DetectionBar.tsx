interface Props {
  malicious: number;
  suspicious: number;
  total: number;
}

function fillCls(ratio: number): string {
  if (!ratio)      return 'fill-clean';
  if (ratio < 0.1) return 'fill-low';
  if (ratio < 0.3) return 'fill-high';
  return 'fill-critical';
}

export function DetectionBar({ malicious, suspicious, total }: Props) {
  const n = malicious + suspicious;
  const pct = total ? Math.round(n / total * 100) : 0;
  const fc = fillCls(total ? n / total : 0);
  const dc = malicious > 0 ? 'red' : suspicious > 0 ? 'yellow' : 'green';

  return (
    <div className="det-bar-wrap">
      <div className="det-bar-label">
        <span className="dl">Detection ratio</span>
        <span className={`mv ${dc}`} style={{ fontSize: '0.74rem' }}>
          {n}/{total}&nbsp;({pct}%)
        </span>
      </div>
      <div className="det-bar-bg">
        <div className={`det-bar-fill ${fc}`} style={{ width: `${Math.min(pct, 100)}%` }} />
      </div>
    </div>
  );
}
