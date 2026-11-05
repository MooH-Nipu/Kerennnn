import { useMemo, useState } from 'react';
import { OutputBox } from '../components/shared/OutputBox';
import { StatusMessage } from '../components/shared/StatusMessage';
import { extractPairs, toTsv } from '../lib/pair-extract.mjs';

export function PairsTab() {
  const [raw, setRaw] = useState('');
  const { rows, skipped } = useMemo(() => extractPairs(raw), [raw]);
  const output = toTsv(rows);

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>Excel Converter</h2>
        {rows.length > 0 && <span className="line-count">{rows.length} rows</span>}
      </div>

      {raw.trim() && !rows.length && (
        <StatusMessage type="error" message="No label + count pairs found." />
      )}
      {rows.length > 0 && skipped > 0 && (
        <StatusMessage type="warning" message={`${skipped} line(s) had no matching count and were skipped.`} />
      )}

      <div className="formatter-grid">
        <div className="form-group">
          <label className="form-label" htmlFor="pairs-raw">
            Input — paste any IP / URL / path with its count
          </label>
          <textarea
            id="pairs-raw"
            className="form-textarea"
            placeholder={'110.239.64.54\nRow: 1; Column: 1\n155,373\nRow: 1; Column: 2'}
            value={raw}
            onChange={e => setRaw(e.target.value)}
            rows={14}
          />
        </div>

        <div className="form-group">
          <label className="form-label">Output — tab separated, paste into Excel</label>
          <OutputBox value={output} placeholder="Converted rows appear here…" rows={14} />
        </div>
      </div>
    </div>
  );
}
