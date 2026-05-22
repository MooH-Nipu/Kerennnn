import { useState } from 'react';
import { useScanHistory } from '../hooks/useScanHistory';
import { VtCard } from '../components/vt/VtCard';
import { fmtWhen } from '../lib/utils';

interface Props {
  onReScan?: (ioc: string) => void;
}

export function HistoryTab({ onReScan }: Props) {
  const { entries, search, setSearch, removeEntry, clearAll } = useScanHistory();
  const [selected, setSelected] = useState<string | null>(null);

  const activeEntry = entries.find(e => e.id === selected) ?? null;

  return (
    <div className="tab-content history-tab">
      <div className="section-header">
        <h2>Riwayat Scan</h2>
        {entries.length > 0 && (
          <button className="btn btn-ghost" style={{ marginLeft: 'auto', fontSize: '0.72rem', padding: '0.25rem 0.5rem' }} onClick={clearAll}>
            Hapus semua
          </button>
        )}
      </div>

      <div className="history-layout">
        <div className="history-sidebar">
          <input
            type="text"
            className="form-input"
            placeholder="Cari IOC…"
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ marginBottom: '0.5rem', fontSize: '0.78rem', padding: '0.375rem 0.625rem' }}
          />

          {entries.length === 0 && (
            <div className="history-empty">
              Belum ada riwayat.{' '}
              <span className="text-muted">Selesaikan scan di tab IoC Scan.</span>
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
                title="Hapus entri ini"
              >
                ×
              </button>
            </div>
          ))}
        </div>

        <div className="history-main">
          {!activeEntry && (
            <div className="history-placeholder">
              Pilih entri riwayat untuk melihat hasil scan.
            </div>
          )}

          {activeEntry && (
            <>
              <div className="history-entry-header">
                <span className="history-entry-ts">{new Date(activeEntry.ts).toLocaleString('id-ID', { timeZone: 'Asia/Jakarta' })}</span>
                {onReScan && (
                  <button
                    className="btn btn-ghost"
                    style={{ fontSize: '0.72rem', padding: '0.25rem 0.625rem' }}
                    onClick={() => onReScan(activeEntry.input)}
                  >
                    ↩ Scan ulang di IoC Scan
                  </button>
                )}
              </div>

              <div className="vt-cards">
                {activeEntry.items.map(item => (
                  <VtCard key={item.id} item={item} />
                ))}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
}
