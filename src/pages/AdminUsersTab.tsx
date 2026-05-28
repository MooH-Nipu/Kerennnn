import { useState, useEffect, useCallback } from 'react';
import { api } from '../lib/api';
import { RoleBadge } from '../components/shared/RoleBadge';
import { Modal } from '../components/shared/Modal';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import type { AppUser, Role } from '../types/api';
import { useAuthState } from '../context/AuthContext';

const ROLES: Role[] = ['admin', 'pac', 'charlie', 'l1', 'l2'];

export function AdminUsersTab() {
  const { username: selfUsername } = useAuthState();
  const [users, setUsers] = useState<AppUser[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  // Create user form
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState<Role>('l1');
  const [creating, setCreating] = useState(false);

  // Delete modal
  const [deleteTarget, setDeleteTarget] = useState<AppUser | null>(null);

  const fetchUsers = useCallback(async () => {
    setLoading(true);
    try {
      const res = await api.admin.listUsers();
      setUsers(res.users);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { fetchUsers(); }, [fetchUsers]);

  async function handleCreate() {
    if (!newUsername.trim() || !newPassword) return;
    setCreating(true);
    setError(null);
    try {
      await api.admin.createUser(newUsername.trim(), newPassword, newRole);
      setSuccess(`User "${newUsername}" berhasil dibuat.`);
      setNewUsername(''); setNewPassword(''); setNewRole('l1');
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreating(false);
    }
  }

  async function handleRoleChange(user: AppUser, role: Role) {
    try {
      await api.admin.updateUser(user.id, { role });
      setUsers(prev => prev.map(u => u.id === user.id ? { ...u, role } : u));
      setSuccess(`Role ${user.username} diubah ke ${role}.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.admin.deleteUser(deleteTarget.id);
      setUsers(prev => prev.filter(u => u.id !== deleteTarget.id));
      setSuccess(`User "${deleteTarget.username}" dihapus.`);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setDeleteTarget(null);
    }
  }

  return (
    <div className="tab-content admin-tab">
      <div className="section-header">
        <h2>User Management</h2>
        <button className="btn btn-ghost" onClick={fetchUsers} disabled={loading} style={{ marginLeft: 'auto' }}>
          {loading ? <Spinner size={14} /> : '↻'} Refresh
        </button>
      </div>

      {error   && <StatusMessage type="error"   message={error}   onDismiss={() => setError(null)} />}
      {success && <StatusMessage type="success" message={success} onDismiss={() => setSuccess(null)} />}

      {/* Create user */}
      <div className="admin-create-card" style={{ marginBottom: '1.5rem' }}>
        <h3 className="admin-section-title">Tambah User Baru</h3>
        <div className="admin-create-form">
          <div className="form-group" style={{ flex: 1, minWidth: 180 }}>
            <label className="form-label">Username</label>
            <input className="form-input" type="text" placeholder="username" value={newUsername} onChange={e => setNewUsername(e.target.value)} />
          </div>
          <div className="form-group" style={{ flex: 1, minWidth: 180 }}>
            <label className="form-label">Password</label>
            <input className="form-input" type="password" placeholder="••••••••" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
          </div>
          <div className="form-group" style={{ minWidth: 140 }}>
            <label className="form-label">Role</label>
            <select className="form-input role-select" value={newRole} onChange={e => setNewRole(e.target.value as Role)}>
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <div className="form-group" style={{ alignSelf: 'flex-end' }}>
            <button
              className="btn btn-primary"
              onClick={handleCreate}
              disabled={creating || !newUsername.trim() || !newPassword}
            >
              {creating ? <Spinner size={14} /> : 'Buat User'}
            </button>
          </div>
        </div>
        {newRole && <div style={{ marginTop: '0.5rem' }}><RoleBadge role={newRole} size="sm" /></div>}
      </div>

      {/* User list */}
      <div className="user-list-section">
        <div className="user-list-header">
          <h3 className="admin-section-title" style={{ margin: 0 }}>Daftar User</h3>
          <span className="user-count">{users.length} user</span>
        </div>

        {!loading && users.length === 0 && (
          <div className="user-empty">Tidak ada user.</div>
        )}

        <div className="user-grid">
          {users.map(user => {
            const isSelf = user.username === selfUsername;
            const initials = user.username.slice(0, 2).toUpperCase();
            return (
              <div key={user.id} className={`user-card${isSelf ? ' user-card--self' : ''}`}>
                <div className="user-card__head">
                  <div className={`user-avatar user-avatar--${user.role}`}>{initials}</div>
                  <div className="user-card__identity">
                    <div className="user-card__name">
                      {user.username}
                      {isSelf && <span className="user-card__self-tag">YOU</span>}
                    </div>
                    <div className="user-card__meta">
                      Bergabung {new Date(user.created_at).toLocaleDateString('id-ID', { day: 'numeric', month: 'short', year: 'numeric' })}
                    </div>
                  </div>
                  <RoleBadge role={user.role} size="sm" />
                </div>

                <div className="user-card__body">
                  <label className="user-card__field">
                    <span className="user-card__field-label">Ubah Role</span>
                    <select
                      className="form-input role-select"
                      value={user.role}
                      onChange={e => handleRoleChange(user, e.target.value as Role)}
                      disabled={isSelf}
                    >
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </label>
                </div>

                <div className="user-card__actions">
                  <button
                    className="btn btn-ghost btn-delete-user"
                    onClick={() => setDeleteTarget(user)}
                    disabled={isSelf}
                    title={isSelf ? 'Tidak dapat menghapus akun sendiri' : 'Hapus user'}
                  >
                    Hapus User
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <Modal
        open={!!deleteTarget}
        title="Hapus User"
        message={`Hapus user "${deleteTarget?.username}"? Tindakan ini tidak dapat dibatalkan.`}
        confirmLabel="Hapus"
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
        danger
      />
    </div>
  );
}
