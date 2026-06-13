import { useState, FormEvent } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { CopyButton } from '../components/shared/CopyButton';
import type { CveResult } from '../types/api';

function severityClass(sev: string | null): string {
  switch ((sev || '').toUpperCase()) {
    case 'CRITICAL': return 'cve-sev--critical';
    case 'HIGH':     return 'cve-sev--high';
    case 'MEDIUM':   return 'cve-sev--medium';
    case 'LOW':      return 'cve-sev--low';
    default:         return 'cve-sev--none';
  }
}

function CveCard({ cve }: { cve: CveResult }) {
  const score = cve.cvss?.score;
  const sev = cve.cvss?.severity ?? (score == null ? null : 'UNKNOWN');
  return (
    <div className="cve-card">
      <div className="cve-card__head">
        <a
          className="cve-card__id"
          href={`https://nvd.nist.gov/vuln/detail/${cve.id}`}
          target="_blank"
          rel="noopener noreferrer"
        >
          {cve.id}
        </a>
        {cve.cvss && (
          <span className={`cve-sev ${severityClass(sev)}`}>
            <span className="cve-sev__score">{score ?? '—'}</span>
            <span className="cve-sev__label">{sev} · CVSS {cve.cvss.version}</span>
          </span>
        )}
        <CopyButton text={cve.id} label="Copy ID" labelDone="✓" className="btn btn-ghost btn-sm" />
      </div>

      <p className="cve-card__desc">{cve.description}</p>

      <div className="cve-card__meta">
        {cve.published && <span>Published {cve.published.slice(0, 10)}</span>}
        {cve.lastModified && <span>Updated {cve.lastModified.slice(0, 10)}</span>}
        {cve.cvss?.vector && <span className="cve-card__vector">{cve.cvss.vector}</span>}
      </div>

      {cve.references.length > 0 && (
        <details className="cve-card__refs">
          <summary>{cve.references.length} reference{cve.references.length > 1 ? 's' : ''}</summary>
          <ul>
            {cve.references.map((r, i) => (
              <li key={i}>
                <a href={r} target="_blank" rel="noopener noreferrer">{r}</a>
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
}

export function CveTab() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<{ type: 'error' | 'info'; text: string } | null>(null);
  const [results, setResults] = useState<CveResult[] | null>(null);

  function search(e: FormEvent) {
    e.preventDefault();
    const term = query.trim();
    if (!term) return;
    setLoading(true);
    setStatus(null);
    setResults(null);
    api.cve.lookup(term)
      .then(r => {
        setResults(r.results);
        if (r.results.length === 0) setStatus({ type: 'info', text: `No CVEs found for "${term}".` });
        else if (r.total > r.results.length) setStatus({ type: 'info', text: `Showing ${r.results.length} of ${r.total} matches — refine your search to narrow down.` });
      })
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => setLoading(false));
  }

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>CVE Lookup</h2>
        <span className="form-hint">NVD · National Vulnerability Database</span>
      </div>

      <form onSubmit={search} className="cve-search">
        <input
          type="text"
          className="form-input"
          placeholder="CVE-2024-3094  or  keyword (e.g. openssl heap overflow)"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <button type="submit" className="btn btn-primary" disabled={!query.trim() || loading}>
          {loading ? 'Searching…' : 'Search'}
        </button>
      </form>

      {status && <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />}

      {loading && <div className="cve-loading"><Spinner size={16} /> Querying NVD…</div>}

      {results && results.length > 0 && (
        <div className="cve-results">
          {results.map(cve => <CveCard key={cve.id} cve={cve} />)}
        </div>
      )}
    </div>
  );
}
