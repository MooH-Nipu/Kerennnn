import { countryFlag } from '../../lib/ioc';

interface Props {
  countries: Array<{ code: string; count: number }>;
  value: string;
  onChange: (code: string) => void;
}

export function CountryFilter({ countries, value, onChange }: Props) {
  // Nothing to filter (e.g. only domains/hashes scanned) — hide the control.
  if (countries.length === 0) return null;

  return (
    <div className="vt-country-filter">
      <span className="vt-country-filter__icon" aria-hidden="true">🌐</span>
      <select
        className="vt-country-filter__select"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label="Filter berdasarkan negara"
        title="Filter berdasarkan negara"
      >
        <option value="">Semua negara</option>
        {countries.map((c) => (
          <option key={c.code} value={c.code}>
            {countryFlag(c.code)} {c.code} ({c.count})
          </option>
        ))}
      </select>
      {value && (
        <button
          type="button"
          className="vt-country-filter__clear"
          onClick={() => onChange('')}
          aria-label="Hapus filter negara"
          title="Hapus filter negara"
        >
          ×
        </button>
      )}
    </div>
  );
}
