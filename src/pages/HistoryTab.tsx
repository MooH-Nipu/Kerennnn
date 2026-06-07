import { useState, useCallback, useEffect } from 'react';
import { useScanHistory } from '../hooks/useScanHistory';
import { VtCard } from '../components/vt/VtCard';
import { CopyButton } from '../components/shared/CopyButton';
import { fmtWhen } from '../lib/utils';

interface Props {
  onReScan?: (ioc: string) => void;
}

export function HistoryTab({ onReScan }: Props) {
  const { entries, search, setSearch, removeEntry, clearAll } = useScanHistory();
  const [selected, setSelected] = useState<string | null>(null);
  const [checkedIds, setCheckedIds] = useState<Set<string>>(new Set());

  const activeEntry = entries.find(e => e.id === selected) ?? null;

  // Reset selection when switching entries
  useEffect(() => { setCheckedIds(new Set()); }, [selected]);

  const toggleCheck = useCallback((id: string) => {
    setCheckedIds(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const selectAll = useCallback(() => {
    if (!activeEntry) return;
    const ids = activeEntry.items.filter(i => !i.pending && !i.error).map(i => i.id);
    setCheckedIds(prev => {
      const allOn = ids.every(id => prev.has(id));
      return allOn ? new Set() : new Set(ids);
    });
  }, [activeEntry]);

  const selectedText = activeEntry
    ? activeEntry.items.filter(i => checkedIds.has(i.id)).map(i => i.ioc).join('\n')
    : '';

  return (
    <div className="tab-content history-tab">
      <div className="section-header">
        <h2>Scan History</h2>
        {entries.length > 0 && (
          <button className="btn btn-ghost" style={{ marginLeft: 'auto', fontSize: '0.72rem', padding: '0.25rem 0.5rem' }} onClick={clearAll}>
            Clear all
          </button>
        )}
      </div>

      <div className="history-layout">
        <div className="history-sidebar">
          <input
            type="text"
            className="form-input"
            placeholder="Search IOC…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ marginBottom: '0.5rem', fontSize: '0.78rem', padding: '0.375rem 0.625rem' }}
          />

          {entries.length === 0 && (
            <div className="history-empty">
              No history yet.{' '}
              <span className="text-muted">Run a scan in the IoC Scan tab.</span>
            </div>
          )}

          {entries.map(entry => (
            <div
              key={entry.id}
              className={`history-item ${entry.id === selected ? 'history-item--active' : ''}`}
              onClick={() => setSelected(entry.id)}
            >
              <div className="history-item__meta">
                <span className="history-item__count">{entry.count} IOC</span>
                <span className="history-item__time">{fmtWhen(entry.ts)}</span>
              </div>
              <div className="history-item__preview">
                {entry.input.split('\n').slice(0, 2).join(', ')}
                {entry.input.split('\n').length > 2 && '…'}
              </div>
              <button
                className="history-item__del"
                onClick={e => { e.stopPropagation(); removeEntry(entry.id); if (selected === entry.id) setSelected(null); }}
                title="Delete this entry"
              >
                ×
              </button>
            </div>
          ))}
        </div>

        <div className="history-main">
          {!activeEntry && (
            <div className="history-placeholder">
              Select a history entry to view scan results.
            </div>
          )}

          {activeEntry && (
            <>
              <div className="history-entry-header">
                <span className="history-entry-ts">{new Date(activeEntry.ts).toLocaleString('en-US', { timeZone: 'Asia/Jakarta' })}</span>
                {onReScan && (
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: '0.72rem', padding: '0.25rem 0.625rem' }}
                    onClick={() => onReScan(activeEntry.input)}
                  >
                    ↩ Re-scan in IoC Scan
                  </button>
                )}
              </div>

              <div className="ioc-multi-bar">
                <label className="ioc-multi-selectall">
                  <input
                    type="checkbox"
                    checked={checkedIds.size > 0 && activeEntry.items.filter(i => !i.pending && !i.error).every(i => checkedIds.has(i.id))}
                    onChange={selectAll}
                  />
                  Select all
                </label>
                <span className="ioc-multi-count">{checkedIds.size} selected</span>
                <div className="ioc-multi-actions">
                  <CopyButton
                    text={selectedText}
                    label="Copy"
                    labelDone="✓ Copied"
                    className="btn btn-ghost btn-sm"
                  />
                  {checkedIds.size > 0 && (
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setCheckedIds(new Set())}>
                      Clear
                    </button>
                  )}
                </div>
              </div>

              <div className="vt-cards">
                {activeEntry.items.map(item => (
                  <VtCard
                    key={item.id}
                    item={item}
                    selected={checkedIds.has(item.id)}
                    onToggleSelect={() => toggleCheck(item.id)}
                  />
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
