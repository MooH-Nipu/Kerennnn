import { useState, useEffect, FormEvent } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';

export function SettingsTab() {
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [status, setStatus] = useState<{ type: 'error' | 'success' | 'info'; text: string } | null>(null);

  const [webhookUrl, setWebhookUrl] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [minConfidence, setMinConfidence] = useState(70);

  useEffect(() => {
    let cancelled = false;
    api.userWebhook.get()
      .then(r => {
        if (cancelled) return;
        setWebhookUrl(r.webhook_url || '');
        setEnabled(r.enabled);
        setMinConfidence(r.min_confidence);
      })
      .catch(err => {
        if (cancelled) return;
        setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) });
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  const urlValid = !webhookUrl.trim() || /^https:\/\//i.test(webhookUrl.trim());

  function save(e: FormEvent) {
    e.preventDefault();
    if (!urlValid) {
      setStatus({ type: 'error', text: 'Webhook URL must start with https://' });
      return;
    }
    setSaving(true);
    setStatus(null);
    api.userWebhook.save(webhookUrl.trim(), enabled, minConfidence)
      .then(r => {
        setWebhookUrl(r.webhook_url || '');
        setEnabled(r.enabled);
        setMinConfidence(r.min_confidence);
        setStatus({ type: 'success', text: 'Webhook settings saved.' });
      })
      .catch(err => setStatus({ type: 'error', text: err instanceof Error ? err.message : String(err) }))
      .finally(() => setSaving(false));
  }

  if (loading) {
    return (
      <div className="tab-content formatter-tab">
        <div className="settings-loading"><Spinner size={16} /> Loading settings…</div>
      </div>
    );
  }

  return (
    <div className="tab-content formatter-tab settings-tab">
      <div className="section-header">
        <h2>Settings</h2>
        <span className="form-hint">Your personal alert configuration</span>
      </div>

      <form onSubmit={save} className="settings-card">
        <div className="settings-card__head">
          <h3>Malicious IOC Alert Webhook</h3>
          <p className="settings-card__desc">
            When an IOC scan resolves at or above your confidence threshold, an alert
            is POSTed to this URL. Only you receive your own alerts — each user
            configures their own webhook.
          </p>
        </div>

        <label className="settings-field">
          <span className="settings-field__label">Webhook URL</span>
          <input
            type="url"
            className={`form-input ${!urlValid ? 'form-input--error' : ''}`}
            placeholder="https://hooks.slack.com/services/…  or  https://discord.com/api/webhooks/…"
            value={webhookUrl}
            onChange={e => setWebhookUrl(e.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
          <span className="settings-field__hint">
            Must be an <code>https://</code> URL. Leave blank to disable.
          </span>
        </label>

        <label className="settings-toggle">
          <input
            type="checkbox"
            checked={enabled}
            onChange={e => setEnabled(e.target.checked)}
          />
          <span className="settings-toggle__label">Enable alerts</span>
          <span className="settings-field__hint">Uncheck to pause without deleting the URL.</span>
        </label>

        <label className="settings-field">
          <span className="settings-field__label">
            Minimum confidence to alert: <strong>{minConfidence}</strong>
          </span>
          <input
            type="range"
            className="settings-range"
            min={0}
            max={100}
            step={5}
            value={minConfidence}
            onChange={e => setMinConfidence(Number(e.target.value))}
          />
          <span className="settings-field__hint">
            Alerts fire only for IOCs scoring ≥ this value (0–100).
          </span>
        </label>

        {status && <StatusMessage type={status.type} message={status.text} onDismiss={() => setStatus(null)} />}

        <div className="settings-actions">
          <button type="submit" className="btn btn-primary" disabled={saving || !urlValid}>
            {saving ? 'Saving…' : 'Save settings'}
          </button>
        </div>
      </form>
    </div>
  );
}
