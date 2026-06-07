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

  // Inline edit (one card at a time) — username + password + role
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editUsername, setEditUsername] = useState('');
  const [editPassword, setEditPassword] = useState('');
  const [editRole, setEditRole] = useState<Role>('l1');
  const [savingId, setSavingId] = useState<string | null>(null);

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
      setSuccess(`User "${newUsername}" created.`);
      setNewUsername(''); setNewPassword(''); setNewRole('l1');
      fetchUsers();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setCreating(false);
    }
  }

  function startEdit(user: AppUser) {
    setEditingId(user.id);
    setEditUsername(user.username);
    setEditPassword('');
    setEditRole(user.role);
    setError(null);
    setSuccess(null);
  }

  function cancelEdit() {
    setEditingId(null);
    setEditUsername('');
    setEditPassword('');
  }

  async function saveEdit(user: AppUser) {
    const uname = editUsername.trim();
    const isSelf = user.username === selfUsername;
    if (!uname) { setError('Username cannot be empty.'); return; }

    const updates: { username?: string; password?: string; role?: Role } = {};
    if (uname !== user.username) updates.username = uname;
    if (editPassword) updates.password = editPassword;
    if (!isSelf && editRole !== user.role) updates.role = editRole;

    if (Object.keys(updates).length === 0) {
      setError('No changes to save.');
      return;
    }

    setSavingId(user.id);
    setError(null);
    try {
      await api.admin.updateUser(user.id, updates);
      setUsers(prev => prev.map(u =>
        u.id === user.id
          ? { ...u, username: updates.username ?? u.username, role: updates.role ?? u.role }
          : u
      ));
      setSuccess(`User "${uname}" updated.`);
      cancelEdit();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setSavingId(null);
    }
  }

  async function handleDelete() {
    if (!deleteTarget) return;
    try {
      await api.admin.deleteUser(deleteTarget.id);
      setUsers(prev => prev.filter(u => u.id !== deleteTarget.id));
      setSuccess(`User "${deleteTarget.username}" deleted.`);
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
      <div className="admin-create-card">
        <h3 className="admin-section-title">Add New User</h3>
        <div className="admin-create-form">
          <div className="form-group">
            <label className="form-label">Username</label>
            <input className="form-input" type="text" placeholder="username" value={newUsername} onChange={e => setNewUsername(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Password</label>
            <input className="form-input" type="password" placeholder="••••••••" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
          </div>
          <div className="form-group">
            <label className="form-label">Role</label>
            <select className="form-input role-select" value={newRole} onChange={e => setNewRole(e.target.value as Role)}>
              {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
            </select>
          </div>
          <button
            className="btn btn-primary admin-create-submit"
            onClick={handleCreate}
            disabled={creating || !newUsername.trim() || !newPassword}
          >
            {creating ? <Spinner size={14} /> : 'Create User'}
          </button>
        </div>
      </div>

      {/* User list */}
      <div className="user-list-section">
        <div className="user-list-header">
          <h3 className="admin-section-title" style={{ margin: 0 }}>User List</h3>
          <span className="user-count">{users.length} users</span>
        </div>

        {!loading && users.length === 0 && (
          <div className="user-empty">No users.</div>
        )}

        <div className="user-grid">
          {users.map(user => {
            const isSelf = user.username === selfUsername;
            const isEditing = editingId === user.id;
            const isSaving = savingId === user.id;
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
                      Joined {new Date(user.created_at).toLocaleDateString('en-US', { day: 'numeric', month: 'short', year: 'numeric' })}
                    </div>
                  </div>
                  <RoleBadge role={user.role} size="sm" />
                </div>

                {isEditing ? (
                  <>
                    <div className="user-card__body user-card__edit">
                      <label className="user-card__field">
                        <span className="user-card__field-label">Username</span>
                        <input
                          className="form-input"
                          type="text"
                          value={editUsername}
                          onChange={e => setEditUsername(e.target.value)}
                        />
                      </label>
                      <label className="user-card__field">
                        <span className="user-card__field-label">New Password</span>
                        <input
                          className="form-input"
                          type="password"
                          placeholder="Leave blank to keep current"
                          value={editPassword}
                          onChange={e => setEditPassword(e.target.value)}
                        />
                      </label>
                      <label className="user-card__field">
                        <span className="user-card__field-label">Role</span>
                        <select
                          className="form-input role-select"
                          value={editRole}
                          onChange={e => setEditRole(e.target.value as Role)}
                          disabled={isSelf}
                          title={isSelf ? 'Cannot change your own role' : undefined}
                        >
                          {ROLES.map(r => <option key={r} value={r}>{r}</option>)}
                        </select>
                      </label>
                    </div>

                    <div className="user-card__actions user-card__actions--edit">
                      <button className="btn btn-ghost btn-sm" onClick={cancelEdit} disabled={isSaving}>
                        Cancel
                      </button>
                      <button className="btn btn-primary btn-sm" onClick={() => saveEdit(user)} disabled={isSaving}>
                        {isSaving ? <Spinner size={14} /> : 'Save'}
                      </button>
                    </div>
                  </>
                ) : (
                  <div className="user-card__actions">
                    <button className="btn btn-ghost btn-sm btn-edit-user" onClick={() => startEdit(user)}>
                      Edit
                    </button>
                    <button
                      className="btn btn-ghost btn-sm btn-delete-user"
                      onClick={() => setDeleteTarget(user)}
                      disabled={isSelf}
                      title={isSelf ? 'Cannot delete your own account' : 'Delete user'}
                    >
                      Delete
                    </button>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>

      <Modal
        open={!!deleteTarget}
        title="Delete User"
        message={`Delete user "${deleteTarget?.username}"? This action cannot be undone.`}
        confirmLabel="Delete"
        cancelLabel="Cancel"
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
        danger
      />
    </div>
  );
}
