import { useState, useEffect, useMemo, useRef } from 'react';
import { invalidateMergerDbCache, useMergerDb } from '../hooks/useMergerDb';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';

import { OutputBox } from '../components/shared/OutputBox';
import { extractIOC, detectType } from '../lib/ioc';
import type { CharlieFilterClient, Team } from '../types/api';

const isIPv6 = (ip: string) => ip.includes(':');
const SIEM_PREVIEW_IPS = 100;

const PRESET_FIELDS = [
  { label: 'data.real_ip', value: 'data.real_ip' },
  { label: 'data.srcip',   value: 'data.srcip' },
  { label: 'source.ip',    value: 'source.ip' },
  { label: 'data.ip',      value: 'data.ip' },
  { label: 'Custom…',      value: '__custom__' },
];

interface Props {
  onCountChange?: (count: number) => void;
  team: Team;
  identity: string;
  canManageClients?: boolean;
}

export function PacFilterTab({ onCountChange, team, identity, canManageClients = false }: Props) {
  const [charlieClients, setCharlieClients] = useState<CharlieFilterClient[]>([]);
  const [clientCode, setClientCode] = useState('');
  const [clientLoading, setClientLoading] = useState(team === 'CHARLIE');
  const [clientError, setClientError] = useState<string | null>(null);
  const [newClientCode, setNewClientCode] = useState('');
  const [newClientLabel, setNewClientLabel] = useState('');
  const [clientCreating, setClientCreating] = useState(false);
  const [deleteConfirmation, setDeleteConfirmation] = useState('');
  const [clientDeleting, setClientDeleting] = useState(false);
  const createInFlight = useRef(false);
  const deleteClientInFlight = useRef(false);

  useEffect(() => {
    if (team !== 'CHARLIE') return;
    let cancelled = false;
    setClientLoading(true);
    api.charlieClients.list()
      .then(res => {
        if (cancelled) return;
        const namedClients = res.clients.filter(client => client.code !== 'GENERAL');
        setCharlieClients(namedClients);
        setClientCode(current => namedClients.some(client => client.code === current) ? current : namedClients[0]?.code ?? '');
      })
      .catch(err => { if (!cancelled) setClientError(err instanceof Error ? err.message : String(err)); })
      .finally(() => { if (!cancelled) setClientLoading(false); });
    return () => { cancelled = true; };
  }, [team]); // client selection must not refetch the registry

  const {
    items, itemCount,
    loading, posting, progress, error, statusMsg,
    setStatusMsg, clearStatus,
    refresh, submitIps, deleteIps, hasActiveOperation,
  } = useMergerDb(team, identity, team === 'CHARLIE' ? clientCode : undefined, team !== 'CHARLIE' || !!clientCode);

  async function handleCreateClient() {
    if (hasActiveOperation()) return;
    if (createInFlight.current) return;
    if (deleteClientInFlight.current) return;
    createInFlight.current = true;
    setClientCreating(true);
    try {
      const res = await api.charlieClients.create(newClientCode, newClientLabel);
      const created = { ...res.client, sort_order: res.client.sort_order ?? 100 };
      setCharlieClients(prev => [...prev, created].sort((a, b) => a.sort_order - b.sort_order || a.label.localeCompare(b.label)));
      setClientCode(created.code);
      setNewClientCode('');
      setNewClientLabel('');
      setClientError(null);
    } catch (err) {
      setClientError(err instanceof Error ? err.message : String(err));
    } finally {
      createInFlight.current = false;
      setClientCreating(false);
    }
  }

  async function handleDeleteClient() {
    if (hasActiveOperation()) return;
    if (deleteClientInFlight.current) return;
    if (clientCode === 'GENERAL' || deleteConfirmation !== clientCode) return;
    deleteClientInFlight.current = true;
    setClientDeleting(true);
    try {
      const res = await api.charlieClients.delete(clientCode, deleteConfirmation);
      invalidateMergerDbCache(identity, 'CHARLIE', clientCode);
      setCharlieClients(prev => {
        const remaining = prev.filter(client => client.code !== clientCode);
        setClientCode(remaining[0]?.code ?? '');
        return remaining;
      });
      setDeleteConfirmation('');
      setInput('');
      setDeleteInput('');
      setClientError(null);
      setStatusMsg(`✓ ${res.deleted.code} deleted with ${res.deleted.deleted_ip_count} IPs.`);
    } catch (err) {
      setClientError(err instanceof Error ? err.message : String(err));
    } finally {
      deleteClientInFlight.current = false;
      setClientDeleting(false);
    }
  }

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
    if (deleteClientInFlight.current || !input.trim()) return;
    const submitted = await submitIps(input);
    if (submitted) setInput('');
  }

  async function handleDeleteSelected() {
    if (deleteClientInFlight.current || !toDelete.length) return;
    const deleted = await deleteIps(toDelete);
    if (deleted) setDeleteInput('');
  }

  function handleRefresh() {
    if (deleteClientInFlight.current) return;
    refresh();
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
  const ipv6Ips = useMemo(() => parsedInputIps.filter(isIPv6), [parsedInputIps]);
  const ipv4Only = useMemo(() => parsedInputIps.filter(ip => !isIPv6(ip)), [parsedInputIps]);
  const newIps = useMemo(() => ipv4Only.filter(ip => !existingSet.has(ip)), [ipv4Only, existingSet]);
  const dupIps = useMemo(() => ipv4Only.filter(ip => existingSet.has(ip)), [ipv4Only, existingSet]);

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

  const siemQueryPreview = useMemo(() => {
    if (queryIps.length <= SIEM_PREVIEW_IPS) return siemQuery;
    const preview = JSON.stringify(
      { query: { terms: { [activeField]: queryIps.slice(0, SIEM_PREVIEW_IPS) } } },
      null,
      2
    );
    return `${preview}\n\n... ${queryIps.length - SIEM_PREVIEW_IPS} more IPs hidden from preview. COPY ALL includes all ${queryIps.length} IPs.`;
  }, [activeField, queryIps, siemQuery]);

  return (
    <div className="tab-content pac-filter-tab">
      <div className="section-header">
        <h2>{team} Filter</h2>
        {team === 'CHARLIE' && charlieClients.length > 0 && (
          <label className="pac-client-switcher">
            <span>Client</span>
            <select
              aria-label="Charlie client filter"
              className="form-input pac-client-select"
              value={clientCode}
              onChange={event => {
                setClientCode(event.target.value);
                setInput('');
                setDeleteInput('');
                setDeleteConfirmation('');
                clearStatus();
              }}
              disabled={clientLoading || loading || posting || clientDeleting}
            >
              {charlieClients.map(client => (
                <option key={client.id} value={client.code}>{client.label}</option>
              ))}
            </select>
          </label>
        )}
        {itemCount > 0 && <span className="line-count">{itemCount} IPs</span>}
        <button
          type="button"
          className="pac-refresh-btn"
          onClick={handleRefresh}
          disabled={loading || posting || clientLoading || clientDeleting}
          title="Refresh Team Filter data"
          aria-label="Refresh Team Filter data"
        >
          <span className={`pac-refresh-icon${loading ? ' is-loading' : ''}`} aria-hidden="true">↻</span>
        </button>
      </div>

      {team === 'CHARLIE' && canManageClients && (
        <details className="pac-client-create">
          <summary>Add Charlie client</summary>
          <div className="pac-client-create-row">
            <label>
              <span>Code</span>
              <input
                type="text"
                className="form-input"
                aria-label="New Charlie client code"
                placeholder="CLIENT_CODE"
                maxLength={32}
                value={newClientCode}
                onChange={event => setNewClientCode(event.target.value.toUpperCase())}
              />
            </label>
            <label>
              <span>Name</span>
              <input
                type="text"
                className="form-input"
                aria-label="New Charlie client label"
                placeholder="Client name"
                maxLength={64}
                value={newClientLabel}
                onChange={event => setNewClientLabel(event.target.value)}
              />
            </label>
            <button
              type="button"
              className="btn btn-primary"
              onClick={handleCreateClient}
              disabled={!newClientCode.trim() || !newClientLabel.trim() || loading || posting || clientLoading || clientCreating || clientDeleting}
            >
              Add client
            </button>
          </div>
        </details>
      )}

      {team === 'CHARLIE' && canManageClients && !!clientCode && (
        <details className="pac-client-delete">
          <summary>Delete Charlie client</summary>
          <div className="pac-client-delete-row">
            <div>
              <strong>Delete all IPs and client</strong>
              <span>Type <code>{clientCode}</code> to permanently delete this client and its {itemCount} IPs.</span>
            </div>
            <label>
              <span>Type “{clientCode}” to confirm</span>
              <input
                type="text"
                className="form-input"
                aria-label={`Type ${clientCode} to confirm client deletion`}
                placeholder="Enter client code"
                value={deleteConfirmation}
                onChange={event => setDeleteConfirmation(event.target.value.toUpperCase())}
                disabled={loading || posting || clientDeleting}
              />
            </label>
            <button
              type="button"
              className="btn btn-danger"
              onClick={handleDeleteClient}
              disabled={deleteConfirmation !== clientCode || loading || posting || clientDeleting}
            >
              {clientDeleting ? 'Deleting…' : 'Delete client and all IPs'}
            </button>
          </div>
        </details>
      )}

      {clientError && (
        <StatusMessage type="error" message={clientError} onDismiss={() => setClientError(null)} />
      )}

      {team === 'CHARLIE' && !clientLoading && charlieClients.length === 0 && (
        <div className="empty-state">No named Charlie clients configured.</div>
      )}

      {(error || statusMsg) && (
        <StatusMessage
          type={error ? 'error' : statusMsg?.startsWith('⚠') ? 'warning' : 'success'}
          message={(error || statusMsg)!}
          onDismiss={clearStatus}
        />
      )}

      {(team !== 'CHARLIE' || !!clientCode) && <div className="pac-layout">
        <aside className="pac-input-panel">
          <div className="pac-section-title">Add IP</div>
          <div className="form-group" style={{ marginBottom: '0.5rem' }}>
            <textarea
              aria-label="IP addresses to add"
              className="form-textarea"
              placeholder={'192.168.1.1\n10.0.0.2'}
              value={input}
              onChange={e => setInput(e.target.value)}
              rows={12}
              disabled={posting || clientDeleting}
            />
          </div>
          {parsedInputIps.length > 0 && (
            <div className="pac-ip-preview">
              <div className="pac-ip-preview-summary">
                {newIps.length > 0 && <span className="pac-ip-badge pac-ip-badge--new">{newIps.length} new to save</span>}
                {dupIps.length > 0 && <span className="pac-ip-badge pac-ip-badge--dup">{dupIps.length} already in DB</span>}
                {ipv6Ips.length > 0 && <span className="pac-ip-badge pac-ip-badge--skip">IPv6 detected — will not be saved to DB</span>}
              </div>
              <div className="pac-ip-chips">
                {newIps.map(ip => (
                  <span key={ip} className="pac-ip-chip pac-ip-chip--new" title="Will be saved">{ip}</span>
                ))}
                {dupIps.map(ip => (
                  <span key={ip} className="pac-ip-chip pac-ip-chip--dup" title="Already in DB">{ip}</span>
                ))}
                {ipv6Ips.map(ip => (
                  <span key={ip} className="pac-ip-chip pac-ip-chip--skip" title="IPv6 not supported">{ip}</span>
                ))}
              </div>
            </div>
          )}

          <div className="tab-actions">
            <button className="btn btn-primary" onClick={handleSubmit} disabled={!input.trim() || posting || clientDeleting || newIps.length === 0}>
              {posting && progress ? `Posting… (${progress.done}/${progress.total})` : `Submit ${newIps.length > 0 ? `${newIps.length} IPs` : ''} to DB`}
            </button>
          </div>
          <div className="pac-delete-section">
            <div className="pac-section-title pac-section-title--danger">Delete IP</div>
            <div className="form-group" style={{ marginBottom: '0.5rem' }}>
              <textarea
                aria-label="IP addresses to delete"
                className="form-textarea"
                placeholder={'192.168.1.1\n10.0.0.2\n2001:db8::1'}
                value={deleteInput}
                onChange={e => setDeleteInput(e.target.value)}
                rows={5}
                disabled={loading || posting || clientDeleting}
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
              disabled={toDelete.length === 0 || loading || posting || clientDeleting}
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
                    aria-label="Custom SIEM field"
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
                    displayValue={siemQueryPreview}
                    copyLabel="COPY ALL"
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
      </div>}

    </div>
  );
}
