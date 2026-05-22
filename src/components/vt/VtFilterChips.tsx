import type { ScanFilters } from '../../hooks/useVtScan';

interface Props {
  filters: ScanFilters;
  onToggle: (key: keyof ScanFilters, value: boolean) => void;
}

const CHIPS: Array<{ key: keyof ScanFilters; label: string; cls: string }> = [
  { key: 'malicious',  label: 'Malicious',  cls: 'chip-malicious' },
  { key: 'suspicious', label: 'Suspicious', cls: 'chip-suspicious' },
  { key: 'clean',      label: 'Clean',      cls: 'chip-clean' },
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
