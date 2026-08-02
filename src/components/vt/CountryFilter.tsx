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
  const [mode, setMode] = useState<CountryFilterEntry['mode']>('include');

  // Nothing to filter (e.g. only domains/hashes scanned) — hide the control.
  if (countries.length === 0) return null;

  const active = new Set(filters.map(f => f.code));
  const countMap = new Map(countries.map(c => [c.code, c.count]));

  function addCountry(code: string) {
    setPick('');
    if (!code || active.has(code)) return;
    onChange([...filters, { code, mode }]);
  }

  function remove(code: string) {
    onChange(filters.filter(f => f.code !== code));
  }

  return (
    <div className="vt-country-filter-wrap">
      <div className="vt-country-filter">
        <span className="vt-country-filter__icon" aria-hidden="true">🌐</span>
        <select
          className="vt-country-filter__select vt-country-filter__mode"
          value={mode}
          onChange={(e) => setMode(e.target.value as CountryFilterEntry['mode'])}
          aria-label="Country filter mode"
        >
          <option value="include">Include</option>
          <option value="exclude">Exclude</option>
        </select>
        <select
          className="vt-country-filter__select"
          value={pick}
          onChange={(e) => addCountry(e.target.value)}
          aria-label="Add country filter"
          title="Add country filter (include / exclude)"
        >
          <option value="">+ Country…</option>
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
          <span className="vt-country-pill__mode" aria-label={f.mode}>
            {f.mode === 'include' ? '✓' : '−'}
          </span>
          <span className="vt-country-pill__label">
            {countryFlag(f.code)} {f.code}{countMap.has(f.code) ? ` (${countMap.get(f.code)})` : ''}
          </span>
          <button
            type="button"
            className="vt-country-pill__remove"
            onClick={() => remove(f.code)}
            aria-label={`Remove ${f.code} filter`}
            title="Remove"
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
          title="Clear all country filters"
        >
          Clear all
        </button>
      )}
    </div>
  );
}
