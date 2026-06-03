import { useState } from 'react';
import { countryFlag } from '../../lib/ioc';
import type { CountryFilterEntry } from '../../hooks/useVtScan';

interface Props {
  countries: Array<{ code: string; count: number }>;
  filters: CountryFilterEntry[];
  onChange: (filters: CountryFilterEntry[]) => void;
}

// Kibana-style country filter: pick a country to add it (defaults to "include"),
// click the badge to flip include ↔ exclude, × to remove. Include filters act as
// an OR allowlist; exclude filters are a denylist (applied in useVtScan).
export function CountryFilter({ countries, filters, onChange }: Props) {
  const [pick, setPick] = useState('');

  // Nothing to filter (e.g. only domains/hashes scanned) — hide the control.
  if (countries.length === 0) return null;

  const active = new Set(filters.map(f => f.code));
  const countMap = new Map(countries.map(c => [c.code, c.count]));

  function addCountry(code: string) {
    setPick('');
    if (!code || active.has(code)) return;
    onChange([...filters, { code, mode: 'include' }]);
  }

  function toggleMode(code: string) {
    onChange(filters.map(f =>
      f.code === code ? { ...f, mode: f.mode === 'include' ? 'exclude' : 'include' } : f
    ));
  }

  function remove(code: string) {
    onChange(filters.filter(f => f.code !== code));
  }

  return (
    <div className="vt-country-filter-wrap">
      <div className="vt-country-filter">
        <span className="vt-country-filter__icon" aria-hidden="true">🌐</span>
        <select
          className="vt-country-filter__select"
          value={pick}
          onChange={(e) => addCountry(e.target.value)}
          aria-label="Tambah filter negara"
          title="Tambah filter negara (include / exclude)"
        >
          <option value="">+ Negara…</option>
          {countries
            .filter(c => !active.has(c.code))
            .map(c => (
              <option key={c.code} value={c.code}>
                {countryFlag(c.code)} {c.code} ({c.count})
              </option>
            ))}
        </select>
      </div>

      {filters.map(f => (
        <span key={f.code} className={`vt-country-pill vt-country-pill--${f.mode}`}>
          <button
            type="button"
            className="vt-country-pill__mode"
            onClick={() => toggleMode(f.code)}
            title={f.mode === 'include' ? 'Include — klik untuk Exclude' : 'Exclude — klik untuk Include'}
            aria-label={f.mode === 'include' ? 'Include' : 'Exclude'}
          >
            {f.mode === 'include' ? '✓' : '⊘'}
          </button>
          <span className="vt-country-pill__label">
            {countryFlag(f.code)} {f.code}{countMap.has(f.code) ? ` (${countMap.get(f.code)})` : ''}
          </span>
          <button
            type="button"
            className="vt-country-pill__remove"
            onClick={() => remove(f.code)}
            aria-label={`Hapus filter ${f.code}`}
            title="Hapus"
          >
            ×
          </button>
        </span>
      ))}

      {filters.length > 1 && (
        <button
          type="button"
          className="vt-country-filter__clearall"
          onClick={() => onChange([])}
          title="Hapus semua filter negara"
        >
          Hapus semua
        </button>
      )}
    </div>
  );
}
