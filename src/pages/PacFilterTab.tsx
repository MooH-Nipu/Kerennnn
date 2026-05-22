import { useState, useEffect, useMemo } from 'react';
import { useMergerDb } from '../hooks/useMergerDb';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Modal } from '../components/shared/Modal';
import { Spinner } from '../components/shared/Spinner';
import { CopyButton } from '../components/shared/CopyButton';

const PRESET_FIELDS = [
  { label: 'data.real_ip', value: 'data.real_ip' },
  { label: 'source.ip',    value: 'source.ip' },
  { label: 'data.ip',      value: 'data.ip' },
  { label: 'Custom…',      value: '__custom__' },
];

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

  // SIEM query builder state
  const [siemField, setSiemField] = useState('data.real_ip');
  const [customField, setCustomField] = useState('');
  const isCustom = siemField === '__custom__';
  const activeField = isCustom ? customField.trim() : siemField;

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

  // IPs to use in query: selected subset or all
  const queryIps = useMemo(() => {
    const pool = selected.size > 0
      ? items.filter(i => selected.has(i.ip))
      : items;
    return pool.map(i => i.ip);
  }, [items, selected]);

  // Generated SIEM query
  const siemQuery = useMemo(() => {
    if (!activeField || queryIps.length === 0) return '';
    return JSON.stringify(
      { query: { terms: { [activeField]: queryIps } } },
      null,
      2
    );
  }, [activeField, queryIps]);

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

      {/* ── Controls ─────────────────────────────────────────── */}
      <div className="pac-controls">
        <input
          type="password"
          className="form-input"
          placeholder="Merger DB password (opsional)"
          value={password}
          onChange={e => savePassword(e.target.value)}
          style={{ maxWidth: 240, fontSize: '0.78rem' }}
        />
        <button className="btn btn-ghost" onClick={refresh} disabled={loading}>
          {loading ? <Spinner size={14} /> : '↻'} Refresh DB
        </button>
        <div className="pac-view-toggle">
          <button className={`btn btn-ghost${viewMode === 'table' ? ' btn-ghost--active' : ''}`} onClick={() => setViewMode('table')}>Tabel</button>
          <button className={`btn btn-ghost${viewMode === 'json' ? ' btn-ghost--active' : ''}`} onClick={() => setViewMode('json')}>JSON</button>
        </div>
      </div>

      {/* ── Add IP ───────────────────────────────────────────── */}
      <div className="pac-section">
        <div className="pac-section-title">Tambah IP</div>
        <div className="form-group" style={{ marginBottom: '0.5rem' }}>
          <textarea
            className="form-textarea"
            placeholder={'192.168.1.1\n10.0.0.2'}
            value={input}
            onChange={e => setInput(e.target.value)}
            rows={3}
            disabled={posting}
          />
        </div>
        <div className="tab-actions">
          <button className="btn btn-primary" onClick={handleSubmit} disabled={!input.trim() || posting}>
            {posting && progress ? `Posting… (${progress.done}/${progress.total})` : 'Submit ke DB'}
          </button>
          {selected.size > 0 && (
            <button className="btn btn-danger" onClick={() => setDeleteModal(true)} disabled={loading}>
              Hapus {selected.size} terpilih
            </button>
          )}
          {items.length > 0 && selected.size === 0 && (
            <button className="btn btn-ghost" onClick={() => setDeleteModal(true)} disabled={loading} style={{ color: '#f87171' }}>
              Hapus semua
            </button>
          )}
        </div>
      </div>

      {/* ── IP List ──────────────────────────────────────────── */}
      {viewMode === 'table' && items.length > 0 && (
        <div className="pac-section">
          <div className="pac-section-title">
            Daftar IP
            {selected.size > 0 && (
              <span style={{ color: 'var(--accent, #3b82f6)', marginLeft: '0.5rem' }}>
                {selected.size} terpilih
              </span>
            )}
          </div>
          <div className="pac-table-wrap">
            <table className="dash-table">
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input
                      type="checkbox"
                      checked={selected.size === items.length && items.length > 0}
                      onChange={toggleAll}
                    />
                  </th>
                  <th>IP Address</th>
                  <th>Updated</th>
                </tr>
              </thead>
              <tbody>
                {items.map(item => (
                  <tr key={item.ip} className={selected.has(item.ip) ? 'dash-row dash-row--selected' : 'dash-row'}>
                    <td>
                      <input
                        type="checkbox"
                        checked={selected.has(item.ip)}
                        onChange={() => toggleSelect(item.ip)}
                      />
                    </td>
                    <td className="mono" style={{ color: 'var(--text-primary, #e8f0fe)' }}>{item.ip}</td>
                    <td style={{ color: 'var(--text-muted, #6b7f9a)', fontSize: '0.78rem' }}>{item.updated_at}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {viewMode === 'json' && items.length > 0 && (
        <div className="pac-section">
          <div className="pac-section-title">JSON Export</div>
          <textarea
            className="form-textarea form-textarea--output"
            readOnly
            value={JSON.stringify(items.map(i => i.ip), null, 2)}
            rows={12}
          />
        </div>
      )}

      {/* ── SIEM Query Builder ───────────────────────────────── */}
      {items.length > 0 && (
        <div className="pac-section siem-section">
          <div className="pac-section-title">
            SIEM Query
            <span className="pac-section-hint">
              {selected.size > 0
                ? `${selected.size} IP terpilih`
                : `semua ${itemCount} IP`}
            </span>
          </div>

          {/* Field selector */}
          <div className="siem-field-row">
            <span className="siem-field-label">Field</span>
            <div className="siem-field-options">
              {PRESET_FIELDS.map(opt => (
                <label key={opt.value} className="siem-field-option">
                  <input
                    type="radio"
                    name="siem-field"
                    value={opt.value}
                    checked={siemField === opt.value}
                    onChange={() => setSiemField(opt.value)}
                  />
                  <code>{opt.label}</code>
                </label>
              ))}
            </div>
            {isCustom && (
              <input
                type="text"
                className="form-input siem-custom-input"
                placeholder="e.g. destination.ip"
                value={customField}
                onChange={e => setCustomField(e.target.value)}
                autoFocus
              />
            )}
          </div>

          {/* Generated query */}
          {siemQuery ? (
            <>
              <div className="siem-query-header">
                <span className="siem-query-meta">
                  <code className="siem-active-field">{activeField}</code>
                  &nbsp;·&nbsp;{queryIps.length} IP
                </span>
                <CopyButton
                  text={siemQuery}
                  label="Copy Query"
                  labelDone="✓ Tersalin"
                  className="btn btn-primary btn-sm"
                />
              </div>
              <textarea
                className="form-textarea form-textarea--output siem-query-output"
                readOnly
                value={siemQuery}
                rows={12}
              />
            </>
          ) : (
            isCustom && !customField.trim() && (
              <div className="siem-empty">Masukkan nama field untuk generate query.</div>
            )
          )}
        </div>
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
