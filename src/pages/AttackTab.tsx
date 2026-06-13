import { useState, FormEvent } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { CopyButton } from '../components/shared/CopyButton';
import type { AttackTechnique } from '../types/api';

function TacticChips({ tactics }: { tactics: string[] }) {
  if (!tactics.length) return null;
  return (
    <div className="attack-tactics">
      {tactics.map(t => (
        <span key={t} className="attack-tactic">{t.replace(/-/g, ' ')}</span>
      ))}
    </div>
  );
}

function TechniqueCard({ t }: { t: AttackTechnique }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="attack-card">
      <div className="attack-card__head">
        <a className="attack-card__id" href={t.url} target="_blank" rel="noopener noreferrer">{t.id}</a>
        <span className="attack-card__name">{t.name}</span>
        {t.isSubtechnique && <span className="attack-card__sub">sub-technique</span>}
        <CopyButton text={t.id} label="Copy" labelDone="✓" className="btn btn-ghost btn-sm" />
      </div>

      <TacticChips tactics={t.tactics} />

      <p className="attack-card__desc">
        {expanded ? t.description : t.description.slice(0, 280)}
        {t.description.length > 280 && (
          <button className="attack-card__more" onClick={() => setExpanded(e => !e)}>
            {expanded ? ' show less' : '… show more'}
          </button>
        )}
      </p>

      {t.platforms.length > 0 && (
        <div className="attack-card__meta"><strong>Platforms:</strong> {t.platforms.join(', ')}</div>
      )}

      {t.detection && (
        <details className="attack-card__detection">
          <summary>Detection guidance</summary>
          <p>{t.detection}</p>
        </details>
      )}
    </div>
  );
}

export function AttackTab() {
  const [query, setQuery] = useState('');
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState<{ type: 'error' | 'info'; text: string } | null>(null);
  const [results, setResults] = useState<AttackTechnique[] | null>(null);

  function search(e: FormEvent) {
    e.preventDefault();
    const term = query.trim();
    if (!term) return;
    setLoading(true);
    setStatus(null);
    setResults(null);
    api.attack.search(term)
      .then(r => {
        setResults(r.results);
        if (r.results.length === 0) setStatus({ type: 'info', text: `No techniques matched "${term}".` });
        else if (r.total > r.results.length) setStatus({ type: 'info', text: `Showing ${r.results.length} of ${r.total} matches.` });
      })
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => setLoading(false));
  }

  return (
    <div className="tab-content formatter-tab">
      <div className="section-header">
        <h2>MITRE ATT&amp;CK</h2>
        <span className="form-hint">Enterprise techniques · search by ID or keyword</span>
      </div>

      <form onSubmit={search} className="cve-search">
        <input
          type="text"
          className="form-input"
          placeholder="T1059  or  keyword (e.g. powershell, phishing, credential dumping)"
          value={query}
          onChange={e => setQuery(e.target.value)}
        />
        <button type="submit" className="btn btn-primary" disabled={!query.trim() || loading}>
          {loading ? 'Searching…' : 'Search'}
        </button>
      </form>

      {status && <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />}

      {loading && <div className="cve-loading"><Spinner size={16} /> Loading ATT&amp;CK data (first search may take a few seconds)…</div>}

      {results && results.length > 0 && (
        <div className="attack-results">
          {results.map(t => <TechniqueCard key={t.id} t={t} />)}
        </div>
      )}
    </div>
  );
}
