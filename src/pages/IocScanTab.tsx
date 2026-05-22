import { useState, useEffect, useRef, FormEvent, useCallback } from 'react';
import { useVtScan } from '../hooks/useVtScan';
import { useScanHistory } from '../hooks/useScanHistory';
import { VtCard } from '../components/vt/VtCard';
import { VtFilterChips } from '../components/vt/VtFilterChips';
import { parseIocList } from '../lib/ioc';
import { copyToClipboard } from '../lib/utils';

interface Props {
  pendingIoc?: string;
  onIocConsumed?: () => void;
}

export function IocScanTab({ pendingIoc, onIocConsumed }: Props) {
  const [input, setInput] = useState('');
  const { visibleItems, items, filters, scanning, progress, statusMsg, statusType, runScan, clear, setFilter } = useVtScan();
  const { addEntry } = useScanHistory();
  const resultsRef = useRef<HTMLDivElement>(null);

  // Selection state for multi-copy
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [copyFeedback, setCopyFeedback] = useState<string | null>(null);

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

  // Auto-defang on paste
  function handlePaste(e: React.ClipboardEvent<HTMLTextAreaElement>) {
    e.preventDefault();
    const pasted = e.clipboardData.getData('text');
    const cleaned = pasted
      .replace(/hxxps?/gi, 'https')
      .replace(/\[\.\]/g, '.')
      .replace(/\(dot\)/gi, '.');
    const target = e.currentTarget;
    const start = target.selectionStart;
    const end = target.selectionEnd;
    setInput(input.slice(0, start) + cleaned + input.slice(end));
  }

  function handleScan(rawInput?: string) {
    const val = rawInput ?? input;
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

  async function copySelectedAs(filterType?: 'ip' | 'domain' | 'hash') {
    const iocs = items
      .filter(it => selected.has(it.id))
      .filter(it => !filterType || it.type === filterType)
      .map(it => it.ioc);
    if (!iocs.length) {
      setCopyFeedback('Tidak ada IOC cocok untuk disalin.');
      setTimeout(() => setCopyFeedback(null), 2000);
      return;
    }
    const ok = await copyToClipboard(iocs.join('\n'));
    setCopyFeedback(ok ? `✓ ${iocs.length} IOC disalin` : 'Gagal menyalin');
    setTimeout(() => setCopyFeedback(null), 2000);
  }

  const lineCount = parseIocList(input).length;
  const hasResults = items.length > 0;
  const selectedCount = selected.size;

  return (
    <div className="tab-content ioc-scan-tab">
      <div className="section-header">
        <h2>IoC Scan</h2>
        {lineCount > 0 && !scanning && <span className="line-count">{lineCount} IOC</span>}
        {scanning && <span className="line-count">{progress.done}/{progress.total} selesai</span>}
      </div>

      <div className="ioc-scan-layout">
        {/* ── LEFT: input ─────────────────────────────────────── */}
        <aside className="ioc-scan-input">
          <form onSubmit={handleSubmit} className="scan-form">
            <div className="form-group">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
                <label className="form-label" htmlFor="ioc-input">IOC — satu per baris</label>
                <span className="form-hint">Ctrl+Enter</span>
              </div>
              <textarea
                id="ioc-input"
                className="form-textarea"
                placeholder={'8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e'}
                value={input}
                onChange={e => setInput(e.target.value)}
                onPaste={handlePaste}
                onKeyDown={handleKeyDown}
                rows={10}
                disabled={scanning}
              />
            </div>

            <div className="tab-actions">
              <button type="submit" className="btn btn-primary" disabled={!input.trim() || scanning}>
                {scanning ? `Scanning… (${progress.done}/${progress.total})` : 'Scan'}
              </button>
              {hasResults && (
                <button type="button" className="btn btn-ghost" onClick={() => { clear(); setSelected(new Set()); }} disabled={scanning}>
                  Reset
                </button>
              )}
            </div>
          </form>

          {/* Status lives in the left panel — never pushes the results column */}
          {statusMsg && (
            <div className={`ioc-status-inline ioc-status-inline--${statusType}`}>{statusMsg}</div>
          )}
        </aside>

        {/* ── RIGHT: results ──────────────────────────────────── */}
        <section className="ioc-scan-results" ref={resultsRef}>

          {!hasResults && !scanning && (
            <div className="ioc-scan-empty">
              Masukkan IOC di kiri lalu klik <strong>Scan</strong>.
            </div>
          )}

          {hasResults && (
            <>
              <div className="scan-results-header">
                <span className="scan-results-count">{visibleItems.length} / {items.length} hasil</span>
                <VtFilterChips filters={filters} onToggle={setFilter} />
              </div>

              {/* Multi-select action bar */}
              <div className="ioc-multi-bar">
                <label className="ioc-multi-selectall">
                  <input
                    type="checkbox"
                    checked={selectedCount > 0 && visibleItems.filter(i => !i.pending && !i.error).every(i => selected.has(i.id))}
                    onChange={selectAllVisible}
                  />
                  Pilih semua
                </label>
                <span className="ioc-multi-count">{selectedCount} terpilih</span>
                <div className="ioc-multi-actions">
                  <button className="btn btn-ghost btn-sm" disabled={!selectedCount} onClick={() => copySelectedAs()}>Copy IOC</button>
                  <button className="btn btn-ghost btn-sm" disabled={!selectedCount} onClick={() => copySelectedAs('ip')}>Copy IP</button>
                  <button className="btn btn-ghost btn-sm" disabled={!selectedCount} onClick={() => copySelectedAs('hash')}>Copy Hash</button>
                  <button className="btn btn-ghost btn-sm" disabled={!selectedCount} onClick={() => copySelectedAs('domain')}>Copy Domain</button>
                  {selectedCount > 0 && (
                    <button className="btn btn-ghost btn-sm" onClick={() => setSelected(new Set())}>Clear</button>
                  )}
                </div>
                {copyFeedback && <span className="ioc-multi-feedback">{copyFeedback}</span>}
              </div>

              <div className="vt-cards">
                {visibleItems.map(item => (
                  <VtCard
                    key={item.id}
                    item={item}
                    selected={selected.has(item.id)}
                    onToggleSelect={() => toggleSelect(item.id)}
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
