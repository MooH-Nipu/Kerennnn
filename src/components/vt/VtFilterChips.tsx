import type { ScanFilters } from '../../hooks/useVtScan';

interface Props {
  filters: ScanFilters;
  onToggle: (key: keyof ScanFilters, value: boolean) => void;
}

// Private takes Clean's slot: a private IOC can never be CLEAN any more, so the
// chip that used to hide clean traffic now hides private traffic.
// CLEAN-verdict items keep filters.clean (default on) and have no chip.
const CHIPS: Array<{ key: keyof ScanFilters; label: string; cls: string }> = [
  { key: 'malicious',  label: 'Malicious',  cls: 'chip-malicious' },
  { key: 'suspicious', label: 'Suspicious', cls: 'chip-suspicious' },
  { key: 'lowrisk',    label: 'Low Risk',   cls: 'chip-lowrisk' },
  { key: 'private',    label: 'Private',    cls: 'chip-private' },
  { key: 'unknown',    label: 'Unknown',    cls: 'chip-unknown' },
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
