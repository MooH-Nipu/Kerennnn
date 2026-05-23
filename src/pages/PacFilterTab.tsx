import { useState, useEffect, useMemo } from 'react';
import { useMergerDb } from '../hooks/useMergerDb';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Modal } from '../components/shared/Modal';
import { Spinner } from '../components/shared/Spinner';
import { OutputBox } from '../components/shared/OutputBox';

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
    items, itemCount,
    loading, posting, progress, error, statusMsg, setStatusMsg,
    refresh, submitIps, deleteIps,
  } = useMergerDb();

  const [input, setInput] = useState('');
  const [deleteModal, setDeleteModal] = useState(false);

  const [siemField, setSiemField] = useState('data.real_ip');
  const [customField, setCustomField] = useState('');
  const isCustom = siemField === '__custom__';
  const activeField = isCustom ? customField.trim() : siemField;

  useEffect(() => {
    onCountChange?.(itemCount);
  }, [itemCount, onCountChange]);

  async function handleDelete() {
    await deleteIps(items.map(i => i.ip));
    setDeleteModal(false);
  }

  async function handleSubmit() {
    if (!input.trim()) return;
    await submitIps(input);
    setInput('');
  }

  const queryIps = useMemo(() => items.map(i => i.ip), [items]);

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

      <div className="pac-layout">
        <aside className="pac-input-panel">
          <div className="pac-section-title">Tambah IP</div>
          <div className="form-group" style={{ marginBottom: '0.5rem' }}>
            <textarea
              className="form-textarea"
              placeholder={'192.168.1.1\n10.0.0.2'}
              value={input}
              onChange={e => setInput(e.target.value)}
              rows={12}
              disabled={posting}
            />
          </div>
          <div className="tab-actions">
            <button className="btn btn-primary" onClick={handleSubmit} disabled={!input.trim() || posting}>
              {posting && progress ? `Posting… (${progress.done}/${progress.total})` : 'Submit ke DB'}
            </button>
            <button
              className="btn btn-ghost"
              onClick={refresh}
              disabled={loading || posting}
              title="Refresh DB"
            >
              {loading ? <Spinner size={14} /> : '↻ Refresh'}
            </button>
          </div>
          {items.length > 0 && (
            <button
              type="button"
              className="pac-delete-link"
              onClick={() => setDeleteModal(true)}
              disabled={loading || posting}
            >
              Hapus semua IP di DB
            </button>
          )}
        </aside>

        <section className="pac-siem-panel">
          <div className="pac-section-title">
            SIEM Query
            {itemCount > 0 && (
              <span className="pac-section-hint">semua {itemCount} IP</span>
            )}
          </div>

          {items.length === 0 ? (
            <div className="pac-siem-empty">
              Belum ada IP di database. Tambahkan IP di kiri lalu klik <strong>Submit ke DB</strong>.
            </div>
          ) : (
            <>
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

              {siemQuery ? (
                <>
                  <div className="siem-query-meta">
                    <code className="siem-active-field">{activeField}</code>
                    &nbsp;·&nbsp;{queryIps.length} IP
                  </div>
                  <OutputBox
                    value={siemQuery}
                    rows={16}
                    className="siem-query-output"
                  />
                </>
              ) : (
                isCustom && !customField.trim() && (
                  <div className="siem-empty">Masukkan nama field untuk generate query.</div>
                )
              )}
            </>
          )}
        </section>
      </div>

      <Modal
        open={deleteModal}
        title="Konfirmasi Hapus"
        message={`Hapus semua ${items.length} IP dari database PAC Filter? Tindakan ini tidak dapat dibatalkan.`}
        confirmLabel="Ya, Hapus"
        onConfirm={handleDelete}
        onCancel={() => setDeleteModal(false)}
        danger
      />
    </div>
  );
}
