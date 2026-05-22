import { useState, useEffect, useRef, FormEvent } from 'react';
import { useVtScan } from '../hooks/useVtScan';
import { VtCard } from '../components/vt/VtCard';
import { VtFilterChips } from '../components/vt/VtFilterChips';
import { parseIocList } from '../lib/ioc';

interface Props {
  pendingIoc?: string;
  onIocConsumed?: () => void;
}

export function IocScanTab({ pendingIoc, onIocConsumed }: Props) {
  const [input, setInput] = useState('');
  const { visibleItems, items, filters, scanning, progress, statusMsg, statusType, runScan, clear, setFilter } = useVtScan();
  const resultsRef = useRef<HTMLDivElement>(null);

  // Consume pendingIoc from header quick-scan
  useEffect(() => {
    if (pendingIoc) {
      setInput(pendingIoc);
      onIocConsumed?.();
      // Auto-start scan after small delay so input renders
      setTimeout(() => handleScan(pendingIoc), 50);
    }
  }, [pendingIoc]); // eslint-disable-line react-hooks/exhaustive-deps

  // Auto-defang on paste: replace hxxp, [.], etc.
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
    const newVal = input.slice(0, start) + cleaned + input.slice(end);
    setInput(newVal);
  }

  function handleScan(rawInput?: string) {
    const val = rawInput ?? input;
    if (!val.trim()) return;
    runScan(val);
    // Scroll to results
    setTimeout(() => resultsRef.current?.scrollIntoView({ behavior: 'smooth' }), 100);
  }

  function handleSubmit(e: FormEvent) {
    e.preventDefault();
    handleScan();
  }

  // Ctrl+Enter shortcut
  function handleKeyDown(e: React.KeyboardEvent) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      e.preventDefault();
      handleScan();
    }
  }

  const lineCount = parseIocList(input).length;
  const hasResults = items.length > 0;

  return (
    <div className="tab-content ioc-scan-tab">
      <div className="section-header">
        <h2>IoC Scan</h2>
        {lineCount > 0 && !scanning && (
          <span className="line-count">{lineCount} IOC</span>
        )}
        {scanning && (
          <span className="line-count">{progress.done}/{progress.total} selesai</span>
        )}
      </div>

      <form onSubmit={handleSubmit} className="scan-form">
        <div className="form-group">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.375rem' }}>
            <label className="form-label" htmlFor="ioc-input">IOC — satu per baris (IP, domain, hash)</label>
            <span className="form-hint">Ctrl+Enter untuk scan</span>
          </div>
          <textarea
            id="ioc-input"
            className="form-textarea"
            placeholder={'8.8.8.8\nexample.com\nd41d8cd98f00b204e9800998ecf8427e'}
            value={input}
            onChange={e => setInput(e.target.value)}
            onPaste={handlePaste}
            onKeyDown={handleKeyDown}
            rows={6}
            disabled={scanning}
          />
        </div>

        <div className="tab-actions">
          <button type="submit" className="btn btn-primary" disabled={!input.trim() || scanning}>
            {scanning ? `Scanning… (${progress.done}/${progress.total})` : 'Scan'}
          </button>
          {hasResults && (
            <button type="button" className="btn btn-ghost" onClick={clear} disabled={scanning}>
              Reset
            </button>
          )}
        </div>
      </form>

      {statusMsg && (
        <div className={`scan-status scan-status--${statusType}`}>{statusMsg}</div>
      )}

      {hasResults && (
        <div className="scan-results" ref={resultsRef}>
          <div className="scan-results-header">
            <span className="scan-results-count">{visibleItems.length} / {items.length} hasil</span>
            <VtFilterChips filters={filters} onToggle={setFilter} />
          </div>

          <div className="vt-cards">
            {visibleItems.map(item => (
              <VtCard key={item.id} item={item} />
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
