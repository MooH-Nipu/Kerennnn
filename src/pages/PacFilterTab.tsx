import { useState, useEffect } from 'react';
import { useMergerDb } from '../hooks/useMergerDb';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Modal } from '../components/shared/Modal';
import { Spinner } from '../components/shared/Spinner';

interface Props {
  onCountChange?: (count: number) => void;
}

export function PacFilterTab({ onCountChange }: Props) {
  const {
    items, itemCount, password, savePassword,
    loading, posting, progress, error, statusMsg, setStatusMsg,
    refresh, submitIps, deleteIps,
  } = useMergerDb();

  const [input, setInput] = useState('');
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [viewMode, setViewMode] = useState<'table' | 'json'>('table');
  const [deleteModal, setDeleteModal] = useState(false);
  const [didAutoRefresh, setDidAutoRefresh] = useState(false);

  useEffect(() => {
    if (!didAutoRefresh) {
      setDidAutoRefresh(true);
      refresh();
    }
  }, []); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    onCountChange?.(itemCount);
  }, [itemCount, onCountChange]);

  function toggleSelect(ip: string) {
    setSelected(prev => {
      const next = new Set(prev);
      if (next.has(ip)) next.delete(ip); else next.add(ip);
      return next;
    });
  }

  function toggleAll() {
    if (selected.size === items.length) setSelected(new Set());
    else setSelected(new Set(items.map(i => i.ip)));
  }

  async function handleDelete() {
    const ips = selected.size > 0 ? [...selected] : items.map(i => i.ip);
    await deleteIps(ips);
    setSelected(new Set());
    setDeleteModal(false);
  }

  async function handleSubmit() {
    if (!input.trim()) return;
    await submitIps(input);
    setInput('');
  }

  return (
    <div className="tab-content pac-filter-tab">
      <div className="section-header">
        <h2>PAC Filter</h2>
        {itemCount > 0 && <span className="line-count">{itemCount} IP</span>}
      </div>

      {(error || statusMsg) && (
        <StatusMessage
          type={error ? 'error' : 'success'}
          message={(error || statusMsg)!}
          onDismiss={() => { setStatusMsg(null); }}
        />
      )}

      {/* Password */}
      <div className="pac-controls">
        <input
          type="password"
          className="form-input"
          placeholder="Merger DB password (opsional)"
          value={password}
          onChange={e => savePassword(e.target.value)}
          style={{ maxWidth: 260, fontSize: '0.78rem' }}
        />
        <button className="btn btn-ghost" onClick={refresh} disabled={loading}>
          {loading ? <Spinner size={14} /> : '↻'} Refresh DB
        </button>
        <div className="pac-view-toggle">
          <button className={`btn btn-ghost${viewMode === 'table' ? ' btn-ghost--active' : ''}`} onClick={() => setViewMode('table')}>Tabel</button>
          <button className={`btn btn-ghost${viewMode === 'json' ? ' btn-ghost--active' : ''}`} onClick={() => setViewMode('json')}>JSON</button>
        </div>
      </div>

      {/* Input */}
      <div className="form-group" style={{ marginBottom: '0.75rem' }}>
        <label className="form-label">Tambah IP — satu per baris</label>
        <textarea
          className="form-textarea"
          placeholder={'192.168.1.1\n10.0.0.2'}
          value={input}
          onChange={e => setInput(e.target.value)}
          rows={4}
          disabled={posting}
        />
      </div>

      <div className="tab-actions" style={{ marginBottom: '1rem' }}>
        <button className="btn btn-primary" onClick={handleSubmit} disabled={!input.trim() || posting}>
          {posting && progress ? `Posting… (${progress.done}/${progress.total})` : 'Submit ke DB'}
        </button>
        {selected.size > 0 && (
          <button className="btn btn-danger" onClick={() => setDeleteModal(true)} disabled={loading}>
            Hapus {selected.size} IP
          </button>
        )}
        {items.length > 0 && selected.size === 0 && (
          <button className="btn btn-ghost" onClick={() => setDeleteModal(true)} disabled={loading} style={{ color: '#f87171' }}>
            Hapus semua
          </button>
        )}
      </div>

      {/* Results */}
      {viewMode === 'table' && items.length > 0 && (
        <div className="pac-table-wrap">
          <table className="dash-table">
            <thead>
              <tr>
                <th><input type="checkbox" checked={selected.size === items.length && items.length > 0} onChange={toggleAll} /></th>
                <th>IP Address</th>
                <th>Updated</th>
              </tr>
            </thead>
            <tbody>
              {items.map(item => (
                <tr key={item.ip} className={selected.has(item.ip) ? 'dash-row dash-row--selected' : 'dash-row'}>
                  <td><input type="checkbox" checked={selected.has(item.ip)} onChange={() => toggleSelect(item.ip)} /></td>
                  <td className="mono">{item.ip}</td>
                  <td className="dash-when">{item.updated_at}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {viewMode === 'json' && items.length > 0 && (
        <textarea
          className="form-textarea form-textarea--output"
          readOnly
          value={JSON.stringify(items.map(i => i.ip), null, 2)}
          rows={20}
        />
      )}

      <Modal
        open={deleteModal}
        title="Konfirmasi Hapus"
        message={selected.size > 0
          ? `Hapus ${selected.size} IP dari database PAC Filter?`
          : `Hapus semua ${items.length} IP dari database PAC Filter? Tindakan ini tidak dapat dibatalkan.`
        }
        confirmLabel="Ya, Hapus"
        onConfirm={handleDelete}
        onCancel={() => setDeleteModal(false)}
        danger
      />
    </div>
  );
}
