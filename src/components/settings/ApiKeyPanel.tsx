import { useCallback, useEffect, useState } from 'react';
import { api } from '../../lib/api';
import type { ApiIocType, ApiKeyMetadata, ApiScope } from '../../types/api';
import { CopyButton } from '../shared/CopyButton';
import { Spinner } from '../shared/Spinner';
import { StatusMessage } from '../shared/StatusMessage';

const SCOPE_OPTIONS: Array<{ id: ApiScope; label: string; note: string }> = [
  { id: 'ioc:scan', label: 'Scan IOCs', note: 'POST /api/v1/scan — spends VirusTotal quota' },
  { id: 'ioc:read', label: 'Read cached verdicts', note: 'GET /api/v1/verdict — no quota' },
];

const TYPE_OPTIONS: Array<{ id: ApiIocType; label: string }> = [
  { id: 'ip', label: 'IP' },
  { id: 'domain', label: 'Domain' },
  { id: 'hash', label: 'Hash' },
];

type Status = { type: 'error' | 'success' | 'info'; text: string } | null;

function formatUsed(iso: string | null) {
  return iso ? `Last used ${new Date(iso).toLocaleString('en-GB')}` : 'Never used';
}

export function ApiKeyPanel() {
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [keys, setKeys] = useState<ApiKeyMetadata[]>([]);
  const [secret, setSecret] = useState<{ label: string; value: string } | null>(null);
  const [label, setLabel] = useState('');
  const [editingId, setEditingId] = useState<string | null>(null);
  const [scopes, setScopes] = useState<ApiScope[]>(['ioc:scan', 'ioc:read']);
  const [types, setTypes] = useState<ApiIocType[]>(['ip', 'domain', 'hash']);
  const [status, setStatus] = useState<Status>(null);

  const load = useCallback(async () => {
    const res = await api.apiKeys.list();
    setKeys(res.keys || []);
  }, []);

  useEffect(() => {
    load()
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => setLoading(false));
  }, [load]);

  function toggle<T extends string>(list: T[], value: T, setter: (next: T[]) => void) {
    setter(list.includes(value) ? list.filter(item => item !== value) : [...list, value]);
  }

  async function run(action: () => Promise<void>, success?: string) {
    setBusy(true); setStatus(null);
    try {
      await action();
      if (success) setStatus({ type: 'success', text: success });
    } catch (err) {
      setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) });
    } finally { setBusy(false); }
  }

  function resetForm() {
    setEditingId(null);
    setLabel('');
    setScopes(['ioc:scan', 'ioc:read']);
    setTypes(['ip', 'domain', 'hash']);
  }

  const create = () => run(async () => {
    const res = await api.apiKeys.create(label.trim(), scopes, types);
    const created = res.key;
    if (res.secret) setSecret({ label: created?.label || label.trim() || 'API key', value: res.secret });
    // Mutation, not a refetch: two quick creates would otherwise race and the
    // older GET could land last and drop the newer key from the list.
    if (created) setKeys(current => [created, ...current.filter(k => k.id !== created.id)]);
    setLabel('');
  }, 'Key created. Copy it now — it is shown once.');

  function startEdit(key: ApiKeyMetadata) {
    setEditingId(key.id);
    setLabel(key.label || '');
    setScopes(key.scopes);
    setTypes(key.allowedTypes);
    setStatus({ type: 'info', text: `Editing “${key.label || key.prefix}”. Changes apply to that key only.` });
  }

  function cancelEdit() {
    resetForm();
    setStatus(null);
  }

  const saveAcl = () => run(async () => {
    if (!editingId) return;
    const res = await api.apiKeys.update(editingId, { label: label.trim(), scopes, allowedTypes: types });
    const updated = res.key;
    if (updated) setKeys(current => current.map(k => (k.id === updated.id ? updated : k)));
    resetForm();
  }, 'API access updated.');

  const toggleEnabled = (key: ApiKeyMetadata) => run(async () => {
    const res = await api.apiKeys.update(key.id, { enabled: !key.enabled });
    const updated = res.key;
    if (updated) setKeys(current => current.map(k => (k.id === updated.id ? updated : k)));
  });

  const revoke = (key: ApiKeyMetadata) => {
    if (!window.confirm(`Revoke "${key.label || key.prefix}"? Any client using it stops working immediately.`)) return;
    return run(async () => {
      await api.apiKeys.revoke(key.id);
      if (secret && key.prefix === secret.value.slice(0, key.prefix.length)) setSecret(null);
      if (editingId === key.id) resetForm();
      setKeys(current => current.filter(k => k.id !== key.id));
    }, 'Key revoked.');
  };

  if (loading) return <div className="settings-loading"><Spinner size={16} /> Loading API access…</div>;

  return (
    <>
      <div className="settings-panel__head">
        <div>
          <h3>API access</h3>
          <p>One key per integration. Scans run as you, against your VT quota and scan budget.</p>
        </div>
        <span className={`settings-state ${keys.some(k => k.enabled) ? 'is-on' : ''}`}>
          {keys.filter(k => k.enabled).length} active
        </span>
      </div>

      {keys.length > 0 && (
        <div className="settings-row">
          <span className="settings-field__label">Keys</span>
          <ul className="settings-list-plain" style={{ listStyle: 'none', margin: 0, padding: 0, display: 'grid', gap: '.5rem' }}>
            {keys.map(key => (
              <li key={key.id} style={{ display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: '.5rem', borderTop: '1px solid var(--border)', paddingTop: '.5rem' }}>
                <strong style={{ minWidth: '8rem' }}>{key.label || 'Unnamed key'}</strong>
                <code style={{ fontFamily: 'var(--font-mono, monospace)' }}>{key.prefix}…</code>
                <span className="settings-field__hint">{key.scopes.join(' · ')} — {key.allowedTypes.join(', ')}</span>
                <span className="settings-field__hint">{formatUsed(key.lastUsedAt)}</span>
                <span className="settings-field__hint">{key.enabled ? 'Active' : 'Disabled'}</span>
                <span style={{ marginLeft: 'auto', display: 'flex', flexWrap: 'wrap', gap: '.4rem' }}>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => startEdit(key)} disabled={busy}>Edit ACL</button>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => toggleEnabled(key)} disabled={busy}>
                    {key.enabled ? 'Disable' : 'Enable'}
                  </button>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => revoke(key)} disabled={busy}>Revoke</button>
                </span>
              </li>
            ))}
          </ul>
        </div>
      )}

      {secret && (
        <div className="settings-row">
          <span className="settings-field__label">“{secret.label}” — shown once</span>
          <code className="form-input" style={{ fontFamily: 'var(--font-mono, monospace)', overflowWrap: 'anywhere' }}>{secret.value}</code>
          <div className="settings-toolbar">
            <span>Store it in your secret manager now. It cannot be recovered.</span>
            <CopyButton text={secret.value} label="Copy key" labelDone="✓ Copied" className="btn btn-secondary btn-sm" />
          </div>
        </div>
      )}

      <label className="settings-field">
        <span className="settings-field__label">New key label</span>
        <input className="form-input" value={label} onChange={event => setLabel(event.target.value)} maxLength={60} placeholder="n8n prod / laptop cli / siem probe" autoComplete="off" />
      </label>

      <fieldset className="settings-acl">
        <legend className="settings-field__label">Allowed actions</legend>
        {SCOPE_OPTIONS.map(option => (
          <label className="settings-toggle" key={option.id}>
            <input type="checkbox" checked={scopes.includes(option.id)} onChange={() => toggle(scopes, option.id, setScopes)} />
            <span className="settings-toggle__label">{option.label}</span>
            <span className="settings-field__hint">{option.note}</span>
          </label>
        ))}
      </fieldset>

      <fieldset className="settings-acl">
        <legend className="settings-field__label">Allowed IOC types</legend>
        {TYPE_OPTIONS.map(option => (
          <label className="settings-toggle" key={option.id}>
            <input type="checkbox" checked={types.includes(option.id)} onChange={() => toggle(types, option.id, setTypes)} />
            <span className="settings-toggle__label">{option.label}</span>
          </label>
        ))}
      </fieldset>

      {status && <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />}

      <div className="settings-toolbar">
        <span>
          {editingId
            ? 'Editing one key — changes do not touch your other keys.'
            : <>Test it: <code>curl -H &quot;Authorization: Bearer $KRN&quot; …/api/v1/me</code></>}
        </span>
        {editingId && <button type="button" className="btn btn-secondary" onClick={cancelEdit} disabled={busy}>Cancel</button>}
        {editingId
          ? <button type="button" className="btn btn-primary" onClick={saveAcl} disabled={busy || !scopes.length || !types.length}>{busy ? 'Saving…' : 'Save ACL'}</button>
          : <button type="button" className="btn btn-primary" onClick={create} disabled={busy || !scopes.length || !types.length}>{busy ? 'Working…' : 'Generate key'}</button>}
      </div>
    </>
  );
}
