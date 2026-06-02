import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { fmtDate } from '../lib/utils';
import type { AuditLogEntry, LoginAttemptEntry } from '../types/api';

type View = 'audit' | 'logins';

export function AdminLogsTab() {
  const [view, setView] = useState<View>('audit');
  const [audit, setAudit] = useState<AuditLogEntry[]>([]);
  const [logins, setLogins] = useState<LoginAttemptEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchLogs = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await api.admin.logs();
      setAudit(res.audit ?? []);
      setLogins(res.logins ?? []);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchLogs(); }, [fetchLogs]);

  const tabBtn = (id: View, label: string, count: number) => (
    <button
      onClick={() => setView(id)}
      style={{
        padding: '0.45rem 0.9rem',
        borderRadius: 8,
        border: '1px solid var(--border, #1e2a3f)',
        background: view === id ? 'var(--accent, #4ade80)' : 'transparent',
        color: view === id ? '#08111f' : 'var(--text-secondary, #a3b3cc)',
        fontWeight: 600,
        fontSize: '0.8rem',
        cursor: 'pointer',
      }}
    >
      {label} <span style={{ opacity: 0.7 }}>({count})</span>
    </button>
  );

  return (
    <div style={{ maxWidth: 960, margin: '0 auto', padding: '0.5rem' }}>
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          gap: '0.75rem',
          marginBottom: '1rem',
          flexWrap: 'wrap',
        }}
      >
        <div>
          <h2 style={{ margin: 0, fontSize: '1.15rem' }}>Activity Logs</h2>
          <p style={{ margin: '0.2rem 0 0', fontSize: '0.78rem', color: 'var(--text-muted, #6b7f9a)' }}>
            Admin audit trail & login attempts (latest 100 each).
          </p>
        </div>
        <button
          onClick={fetchLogs}
          disabled={loading}
          style={{
            padding: '0.45rem 0.9rem',
            borderRadius: 8,
            border: '1px solid var(--border, #1e2a3f)',
            background: 'transparent',
            color: 'var(--text-secondary, #a3b3cc)',
            fontWeight: 600,
            fontSize: '0.8rem',
            cursor: loading ? 'default' : 'pointer',
          }}
        >
          {loading ? 'Memuat…' : '↻ Refresh'}
        </button>
      </div>

      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        {tabBtn('audit', 'Audit', audit.length)}
        {tabBtn('logins', 'Login Attempts', logins.length)}
      </div>

      {error && <StatusMessage type="error" message={error} />}

      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', padding: '2rem' }}>
          <Spinner size={28} />
        </div>
      ) : view === 'audit' ? (
        <AuditList rows={audit} />
      ) : (
        <LoginList rows={logins} />
      )}
    </div>
  );
}

const rowStyle: React.CSSProperties = {
  display: 'flex',
  alignItems: 'flex-start',
  gap: '0.75rem',
  padding: '0.6rem 0.75rem',
  borderRadius: 8,
  border: '1px solid var(--border, #1e2a3f)',
  background: 'var(--bg-elevated, #0d1525)',
  marginBottom: '0.5rem',
};

const whenStyle: React.CSSProperties = {
  flex: '0 0 140px',
  fontSize: '0.72rem',
  color: 'var(--text-muted, #6b7f9a)',
  fontFamily: 'var(--font-mono, monospace)',
};

function AuditList({ rows }: { rows: AuditLogEntry[] }) {
  if (!rows.length) return <Empty label="No audit entries yet." />;
  return (
    <div>
      {rows.map((r) => (
        <div key={r.id} style={rowStyle}>
          <span style={whenStyle}>{fmtDate(r.created_at)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>
              <span style={{ color: 'var(--accent, #4ade80)' }}>{r.action}</span>
              {r.target && <span style={{ color: 'var(--text-secondary, #a3b3cc)' }}> → {r.target}</span>}
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #6b7f9a)', marginTop: '0.15rem' }}>
              oleh <strong>{r.actor_username ?? 'unknown'}</strong>
              {r.detail && Object.keys(r.detail).length > 0 && (
                <span style={{ fontFamily: 'var(--font-mono, monospace)' }}> · {JSON.stringify(r.detail)}</span>
              )}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function LoginList({ rows }: { rows: LoginAttemptEntry[] }) {
  if (!rows.length) return <Empty label="No login attempts recorded yet." />;
  return (
    <div>
      {rows.map((r) => (
        <div key={r.id} style={rowStyle}>
          <span style={whenStyle}>{fmtDate(r.attempted_at)}</span>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 600 }}>
              <span style={{ color: r.success ? 'var(--accent, #4ade80)' : '#f87171' }}>
                {r.success ? '✓ success' : '✗ failed'}
              </span>
              <span style={{ color: 'var(--text-secondary, #a3b3cc)' }}> · {r.username}</span>
            </div>
            <div style={{ fontSize: '0.74rem', color: 'var(--text-muted, #6b7f9a)', marginTop: '0.15rem', fontFamily: 'var(--font-mono, monospace)' }}>
              IP {r.ip}
            </div>
          </div>
        </div>
      ))}
    </div>
  );
}

function Empty({ label }: { label: string }) {
  return (
    <div style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted, #6b7f9a)', fontSize: '0.85rem' }}>
      {label}
    </div>
  );
}
