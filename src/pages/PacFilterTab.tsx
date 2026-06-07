import { useState, useEffect, useMemo } from 'react';
import { useMergerDb } from '../hooks/useMergerDb';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { OutputBox } from '../components/shared/OutputBox';
import { extractIOC, detectType } from '../lib/ioc';

const PRESET_FIELDS = [
  { label: 'data.real_ip', value: 'data.real_ip' },
  { label: 'data.srcip',   value: 'data.srcip' },
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
  const [deleteInput, setDeleteInput] = useState('');

  const [siemField, setSiemField] = useState('data.real_ip');
  const [customField, setCustomField] = useState('');
  const isCustom = siemField === '__custom__';
  const activeField = isCustom ? customField.trim() : siemField;

  useEffect(() => {
    onCountChange?.(itemCount);
  }, [itemCount, onCountChange]);

  async function handleSubmit() {
    if (!input.trim()) return;
    await submitIps(input);
    setInput('');
  }

  async function handleDeleteSelected() {
    if (!toDelete.length) return;
    await deleteIps(toDelete);
    setDeleteInput('');
  }

  const queryIps = useMemo(() => items.map(i => i.ip), [items]);

  // IP preview: parse input and classify each as new vs already in DB
  const existingSet = useMemo(() => new Set(items.map(i => i.ip)), [items]);
  const parsedInputIps = useMemo(() => {
    if (!input.trim()) return [];
    return [...new Set(
      input.split('\n')
        .map(s => extractIOC(s.trim()))
        .filter((s): s is string => !!s && detectType(s) === 'ip')
    )];
  }, [input]);
  const newIps = useMemo(() => parsedInputIps.filter(ip => !existingSet.has(ip)), [parsedInputIps, existingSet]);
  const dupIps = useMemo(() => parsedInputIps.filter(ip => existingSet.has(ip)), [parsedInputIps, existingSet]);

  // Delete preview: classify delete-input IPs as found-in-DB vs not-found
  const parsedDeleteIps = useMemo(() => {
    if (!deleteInput.trim()) return [];
    return [...new Set(
      deleteInput.split('\n')
        .map(s => extractIOC(s.trim()))
        .filter((s): s is string => !!s && detectType(s) === 'ip')
    )];
  }, [deleteInput]);
  const toDelete  = useMemo(() => parsedDeleteIps.filter(ip => existingSet.has(ip)),  [parsedDeleteIps, existingSet]);
  const notInDb   = useMemo(() => parsedDeleteIps.filter(ip => !existingSet.has(ip)), [parsedDeleteIps, existingSet]);

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
        {itemCount > 0 && <span className="line-count">{itemCount} IPs</span>}
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
          <div className="pac-section-title">Add IP</div>
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
          {parsedInputIps.length > 0 && (
            <div className="pac-ip-preview">
              <div className="pac-ip-preview-summary">
                {newIps.length > 0 && <span className="pac-ip-badge pac-ip-badge--new">{newIps.length} new to save</span>}
                {dupIps.length > 0 && <span className="pac-ip-badge pac-ip-badge--dup">{dupIps.length} already in DB</span>}
              </div>
              <div className="pac-ip-chips">
                {newIps.map(ip => (
                  <span key={ip} className="pac-ip-chip pac-ip-chip--new" title="Will be saved">{ip}</span>
                ))}
                {dupIps.map(ip => (
                  <span key={ip} className="pac-ip-chip pac-ip-chip--dup" title="Already in DB">{ip}</span>
                ))}
              </div>
            </div>
          )}

          <div className="tab-actions">
            <button className="btn btn-primary" onClick={handleSubmit} disabled={!input.trim() || posting || newIps.length === 0}>
              {posting && progress ? `Posting… (${progress.done}/${progress.total})` : `Submit ${newIps.length > 0 ? `${newIps.length} IPs` : ''} to DB`}
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
          <div className="pac-delete-section">
            <div className="pac-section-title pac-section-title--danger">Delete IP</div>
            <div className="form-group" style={{ marginBottom: '0.5rem' }}>
              <textarea
                className="form-textarea"
                placeholder={'192.168.1.1\n10.0.0.2\n2001:db8::1'}
                value={deleteInput}
                onChange={e => setDeleteInput(e.target.value)}
                rows={5}
                disabled={loading || posting}
              />
            </div>
            {parsedDeleteIps.length > 0 && (
              <div className="pac-ip-preview">
                <div className="pac-ip-preview-summary">
                  {toDelete.length > 0 && <span className="pac-ip-badge pac-ip-badge--del">{toDelete.length} to delete</span>}
                  {notInDb.length > 0 && <span className="pac-ip-badge pac-ip-badge--dup">{notInDb.length} not in DB</span>}
                </div>
                <div className="pac-ip-chips">
                  {toDelete.map(ip => (
                    <span key={ip} className="pac-ip-chip pac-ip-chip--del" title="Will be deleted">{ip}</span>
                  ))}
                  {notInDb.map(ip => (
                    <span key={ip} className="pac-ip-chip pac-ip-chip--dup" title="Not in DB">{ip}</span>
                  ))}
                </div>
              </div>
            )}
            <button
              type="button"
              className="btn btn-danger"
              onClick={handleDeleteSelected}
              disabled={toDelete.length === 0 || loading || posting}
            >
              {toDelete.length > 0 ? `Delete ${toDelete.length} IPs from DB` : 'Delete from DB'}
            </button>
          </div>
        </aside>

        <section className="pac-siem-panel">
          <div className="pac-section-title">
            SIEM Query
            {itemCount > 0 && (
              <span className="pac-section-hint">all {itemCount} IPs</span>
            )}
          </div>

          {items.length === 0 ? (
            <div className="pac-siem-empty">
              No IPs in the database yet. Add IPs on the left and click <strong>Submit to DB</strong>.
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
                    &nbsp;·&nbsp;{queryIps.length} IPs
                  </div>
                  <OutputBox
                    value={siemQuery}
                    rows={4}
                    className="siem-query-output"
                  />
                </>
              ) : (
                isCustom && !customField.trim() && (
                  <div className="siem-empty">Enter a field name to generate the query.</div>
                )
              )}
            </>
          )}
        </section>
      </div>

    </div>
  );
}
