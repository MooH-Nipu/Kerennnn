import { useState, useEffect, useRef, FormEvent, useCallback, useMemo } from 'react';
import { useVtScan } from '../hooks/useVtScan';
import { useScanHistory } from '../hooks/useScanHistory';
import { VtCard } from '../components/vt/VtCard';
import { VtFilterChips } from '../components/vt/VtFilterChips';
import { CountryFilter } from '../components/vt/CountryFilter';
import { CopyButton } from '../components/shared/CopyButton';
import { MAX_BULK_INPUT_CHARS, MAX_BULK_IOCS, MAX_SELECTED_DOMAINS, parseBulkIocs, type BulkIocRow } from '../lib/bulk-ioc.mjs';

interface Props {
  pendingIoc?: string;
  onIocConsumed?: () => void;
}

export function IocScanTab({ pendingIoc, onIocConsumed }: Props) {
  const [input, setInput] = useState('');
  const [inputFormat, setInputFormat] = useState<'text' | 'csv' | 'json'>('text');
  const [rowSelection, setRowSelection] = useState<Record<string, boolean>>({});
  const [fileTruncated, setFileTruncated] = useState(false);
  const { visibleItems, items, filters, countryFilters, availableCountries, scanning, progress, statusMsg, statusType, runScan, setFilter, setCountryFilters } = useVtScan();
  const { addEntry } = useScanHistory();
  const resultsRef = useRef<HTMLDivElement>(null);
  const fileRef = useRef<HTMLInputElement>(null);

  // Selection state for multi-copy
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Expand/collapse all: null = per-card, true = all expanded, false = all collapsed.
  const [expandAll, setExpandAll] = useState<boolean | null>(null);



  // Track the input that started the current scan so we can persist it on completion
  const lastScanInputRef = useRef<string>('');
  const persistedScanRef = useRef<string | null>(null);

  // Consume pendingIoc from header quick-scan
  useEffect(() => {
    if (pendingIoc) {
      setInput(pendingIoc);
      onIocConsumed?.();
      setTimeout(() => handleScan(pendingIoc), 50);
    }
  }, [pendingIoc]); // eslint-disable-line react-hooks/exhaustive-deps

  // Persist completed scan to history (only once per scan)
  useEffect(() => {
    if (!scanning && statusType === 'success' && items.length > 0) {
      const key = `${lastScanInputRef.current}::${items.length}`;
      if (persistedScanRef.current !== key) {
        persistedScanRef.current = key;
        addEntry(lastScanInputRef.current, items);
      }
    }
  }, [scanning, statusType, items, addEntry]);

  const previewRows = useMemo(() => parseBulkIocs(input, inputFormat), [input, inputFormat]);
  const isSelected = useCallback((row: BulkIocRow) => rowSelection[row.id] ?? row.selected, [rowSelection]);
  const selectedPreviewRows = previewRows.filter(row => isSelected(row) && row.valid && !row.duplicate);
  const selectedDomainCount = selectedPreviewRows.filter(row => row.type === 'domain' || row.type === 'url').length;
  const selectionFull = selectedPreviewRows.length >= 100;
  const domainSelectionFull = selectedDomainCount >= MAX_SELECTED_DOMAINS;

  async function handleFile(file?: File) {
    if (!file) return;
    const name = file.name.toLowerCase();
    setInputFormat(name.endsWith('.json') ? 'json' : name.endsWith('.csv') ? 'csv' : 'text');
    setFileTruncated(file.size > MAX_BULK_INPUT_CHARS);
    setInput(await file.slice(0, MAX_BULK_INPUT_CHARS).text());
    setRowSelection({});
  }

  function handleScan(rawInput?: string) {
    const val = rawInput ?? selectedPreviewRows.map(row => row.normalized).join('\n');
    if (!val.trim()) return;
    lastScanInputRef.current = val;
    persistedScanRef.current = null;
    setSelected(new Set());
    runScan(val);
    setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    handleScan();
  }

  function handleKeyDown(e: React.KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleScan();
    }
  }

  const toggleSelect = useCallback((id: string) => {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  }, []);

  const selectAllVisible = useCallback(() => {
    const ids = visibleItems.filter(i => !i.pending && !i.error).map(i => i.id);
    setSelected(prev => {
      const allSelected = ids.every(id => prev.has(id));
      if (allSelected) return new Set();
      return new Set(ids);
    });
  }, [visibleItems]);

  const selectedIocsText = items
    .filter(it => selected.has(it.id))
    .map(it => it.ioc)
    .join('\n');

  const lineCount = selectedPreviewRows.length;
  const hasResults = items.length > 0;
  const selectedCount = selected.size;

  return (
    <div className="tab-content ioc-scan-tab">
      <div className="section-header">
        <h2>IoC Scan</h2>
        {lineCount > 0 && !scanning && <span className="line-count">{lineCount} IOC</span>}
        {scanning && <span className="line-count">{progress.done}/{progress.total} done</span>}
      </div>

      {scanning && (
        <div className="ioc-progress-bar">
          <div
            className="ioc-progress-bar__fill"
            role="progressbar"
            aria-label="IOC scan progress"
            aria-valuemin={0}
            aria-valuemax={progress.total}
            aria-valuenow={progress.done}
            style={{ width: `${progress.total > 0 ? Math.round((progress.done / progress.total) * 100) : 0}%` }}
          />
        </div>
      )}

      <div className="ioc-scan-layout">
        {/* ── LEFT: input ─────────────────────────────────────── */}
        <aside className="ioc-scan-input">
          <form onSubmit={handleSubmit} className="scan-form">
            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
                <label className="form-label" htmlFor="ioc-input">IOC — one per line</label>
                <span className="form-hint">Ctrl+Enter</span>
              </div>
              <textarea
                id="ioc-input"
                className="form-textarea"
                placeholder={'8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e'}
                value={input}
                onChange={e => { setInput(e.target.value); setInputFormat('text'); setRowSelection({}); setFileTruncated(false); }}
                onKeyDown={handleKeyDown}
                rows={10}
                disabled={scanning}
              />
            </div>

            <input ref={fileRef} type="file" accept=".txt,.csv,.json,text/plain,text/csv,application/json" hidden onChange={e => { void handleFile(e.target.files?.[0]); e.target.value = ''; }} />
            <div className="bulk-ioc-actions">
              <button type="button" className="btn btn-secondary" onClick={() => fileRef.current?.click()} disabled={scanning}>Upload TXT/CSV/JSON</button>
              <button type="submit" className="btn btn-primary" disabled={!selectedPreviewRows.length || scanning}>
                {scanning ? `Scanning… (${progress.done}/${progress.total})` : `Scan ${selectedPreviewRows.length || ''}`.trim()}
              </button>
            </div>

            {previewRows.length > 0 && (
              <div className="bulk-ioc-preview" aria-label="Bulk IOC preview">
                {(fileTruncated || input.length > MAX_BULK_INPUT_CHARS) && <p className="bulk-ioc-limit">Input capped at {MAX_BULK_INPUT_CHARS.toLocaleString()} characters.</p>}
                {previewRows.length === MAX_BULK_IOCS && <p className="bulk-ioc-limit">Preview limit reached. Selectable rows are capped.</p>}
                <div className="bulk-ioc-table-wrap">
                  <table className="bulk-ioc-table">
                    <thead><tr><th><span className="sr-only">Select</span></th><th>Original</th><th>Normalized</th><th>Type</th><th>State</th></tr></thead>
                    <tbody>{previewRows.map(row => (
                      <tr key={row.id} className={!row.valid || row.duplicate ? 'bulk-ioc-row--muted' : ''}>
                        <td><input type="checkbox" aria-label={`Select ${row.original}`} checked={isSelected(row)} disabled={!row.valid || row.duplicate || scanning || (!isSelected(row) && (selectionFull || ((row.type === 'domain' || row.type === 'url') && domainSelectionFull)))} onChange={e => setRowSelection(prev => ({ ...prev, [row.id]: e.target.checked }))} /></td>
                        <td title={row.original}>{row.original}</td><td title={row.normalized}>{row.normalized || '—'}</td><td>{row.type === 'url' ? 'DOMAIN FROM URL' : row.type?.toUpperCase() || '—'}</td>
                        <td>{row.duplicate ? 'Duplicate' : row.valid ? 'Ready' : row.invalidReason}</td>
                      </tr>
                    ))}</tbody>
                  </table>
                </div>
                <div className="bulk-ioc-summary" aria-label="IOC preview summary">
                  <span className="bulk-ioc-summary--selected">{selectedPreviewRows.length} selected</span>
                  <span className="bulk-ioc-summary--duplicate">{previewRows.filter(row => row.duplicate).length} duplicate</span>
                  <span className="bulk-ioc-summary--invalid">{previewRows.filter(row => !row.valid).length} invalid</span>
                </div>
              </div>
            )}


          </form>

          {/* Status lives in the left panel — never pushes the results column */}
          {statusMsg && (
            <div className={`ioc-status-inline ioc-status-inline--${statusType}`} role={statusType === 'error' ? 'alert' : 'status'}>{statusMsg}</div>
          )}
        </aside>

        {/* ── RIGHT: results ──────────────────────────────────── */}
        <section className="ioc-scan-results" ref={resultsRef}>

          {!hasResults && !scanning && (
            <div className="ioc-scan-empty">
              Enter IOCs on the left and click <strong>Scan</strong>.
            </div>
          )}

          {hasResults && (
            <>
              <div className="scan-results-header">
                <span className="scan-results-count">{visibleItems.length} / {items.length} results</span>
                <div className="scan-results-filters">
                  <button
                    type="button"
                    className="btn btn-ghost btn-sm"
                    onClick={() => setExpandAll(prev => prev === null ? true : prev ? false : null)}
                    title={expandAll === null ? 'Expand all cards' : expandAll ? 'Collapse all cards' : 'Reset to per-card view'}
                  >
                    {expandAll === null ? '↕ All' : expandAll ? '↕ Collapse all' : '↕ Per-card'}
                  </button>
                  <VtFilterChips filters={filters} onToggle={setFilter} />
                  <CountryFilter countries={availableCountries} filters={countryFilters} onChange={setCountryFilters} />
                </div>
              </div>

              {/* Multi-select action bar */}
              <div className="ioc-multi-bar">
                <label className="ioc-multi-selectall">
                  <input
                    type="checkbox"
                    checked={selectedCount > 0 && visibleItems.filter(i => !i.pending && !i.error).every(i => selected.has(i.id))}
                    onChange={selectAllVisible}
                  />
                  Select all
                </label>
                <span className="ioc-multi-count">{selectedCount} selected</span>
                <div className="ioc-multi-actions">
                  <CopyButton
                    text={selectedIocsText}
                    label="Copy"
                    labelDone="✓ Copied"
                    className="btn btn-ghost btn-sm"
                  />
                  {selectedCount > 0 && (
                    <button type="button" className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>
                      Clear
                    </button>
                  )}
                </div>
              </div>

              <div className="vt-cards">
                {visibleItems.length === 0 && (
                  <div className="ioc-scan-empty">No results match current filters. Reset filter chips to show all results.</div>
                )}
                {visibleItems.map(item => (
                  <VtCard
                    key={item.id}
                    item={item}
                    selected={selected.has(item.id)}
                    onToggleSelect={() => toggleSelect(item.id)}
                    forceExpanded={expandAll}
                  />
                ))}
              </div>
            </>
          )}
        </section>
      </div>
    </div>
  );
}
