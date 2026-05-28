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

      {/* User table */}
      <div className="admin-table-card">
        <h3 className="admin-section-title">Daftar User</h3>
        <div className="pac-table-wrap">
          <table className="dash-table admin-users-table">
            <thead>
              <tr>
                <th>Username</th>
                <th style={{ width: 170 }}>Role</th>
                <th style={{ width: 115 }}>Created</th>
                <th style={{ width: 88, textAlign: 'right' }}>Aksi</th>
              </tr>
            </thead>
            <tbody>
              {users.map(user => (
                <tr key={user.id} className="dash-row">
                  <td className="mono">
                    {user.username}
                    {user.username === selfUsername && <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem', marginLeft: '0.4rem' }}>(you)</span>}
                  </td>
                  <td>
                    <select
                      className="role-select"
                      value={user.role}
                      onChange={e => handleRoleChange(user, e.target.value as Role)}
                      disabled={user.username === selfUsername}
                      style={{ width: '100%' }}
                    >
                      {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                    </select>
                  </td>
                  <td className="dash-when">
                    {new Date(user.created_at).toLocaleDateString('id-ID')}
                  </td>
                  <td style={{ textAlign: 'right' }}>
                    <button
                      className="btn btn-ghost btn-delete"
                      onClick={() => setDeleteTarget(user)}
                      disabled={user.username === selfUsername}
                    >
                      Hapus
                    </button>
                  </td>
                </tr>
              ))}
              {!loading && users.length === 0 && (
                <tr><td colSpan={4} className="dash-empty">Tidak ada user.</td></tr>
              )}
            </tbody>
          </table>
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
