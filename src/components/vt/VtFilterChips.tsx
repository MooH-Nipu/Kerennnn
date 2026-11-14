import type { ScanFilters } from '../../hooks/useVtScan';

interface Props {
  filters: ScanFilters;
  onToggle: (key: keyof ScanFilters, value: boolean) => void;
}

// PRIVATE has its own chip; CLEAN keeps one too so clean results stay
// hideable like every other verdict.
const CHIPS: Array<{ key: keyof ScanFilters; label: string; cls: string }> = [
  { key: 'malicious',  label: 'Malicious',  cls: 'chip-malicious' },
  { key: 'suspicious', label: 'Suspicious', cls: 'chip-suspicious' },
  { key: 'lowrisk',    label: 'Low Risk',   cls: 'chip-lowrisk' },
  { key: 'clean',      label: 'Clean',      cls: 'chip-clean' },
  { key: 'unknown',    label: 'Unknown',    cls: 'chip-unknown' },
  { key: 'private',    label: 'Private',    cls: 'chip-private' },
];

export function VtFilterChips({ filters, onToggle }: Props) {
  return (
    <div className="vt-filter-chips">
      {CHIPS.map(c => (
        <button
          key={c.key}
          className={`vt-chip ${c.cls} ${filters[c.key] ? 'on' : ''}`}
          onClick={() => onToggle(c.key, !filters[c.key])}
        >
          {c.label}
        </button>
      ))}
    </div>
  );
}
