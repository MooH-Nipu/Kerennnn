import { useState, FormEvent } from 'react';
import { useAuthState, useAuthActions } from '../../context/AuthContext';
import { Spinner } from '../shared/Spinner';

export function LoginPage() {
  const { pending, loginError } = useAuthState();
  const { login, clearError } = useAuthActions();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    await login(username.trim(), password);
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <div className="login-logo">
          <span className="login-logo__icon">◈</span>
          <div>
            <span className="login-logo__title">Charlie kerennnn</span>
            <span className="login-logo__sub">SOC Toolbox</span>
          </div>
        </div>

        <form className="login-form" onSubmit={handleSubmit}>
          <div className="form-group">
            <label htmlFor="login-username" className="form-label">Username</label>
            <input
              id="login-username"
              type="text"
              className="form-input"
              placeholder="Enter username"
              value={username}
              onChange={e => { setUsername(e.target.value); clearError(); }}
              autoComplete="username"
              autoFocus
              disabled={pending}
            />
          </div>

          <div className="form-group">
            <label htmlFor="login-password" className="form-label">Password</label>
            <input
              id="login-password"
              type="password"
              className="form-input"
              placeholder="Enter password"
              value={password}
              onChange={e => { setPassword(e.target.value); clearError(); }}
              autoComplete="current-password"
              disabled={pending}
            />
          </div>

          {loginError && (
            <div className="login-error">{loginError}</div>
          )}

          <button
            type="submit"
            className="btn btn-primary login-btn"
            disabled={pending || !username.trim() || !password}
          >
            {pending ? <Spinner size={16} /> : 'Sign in'}
          </button>
        </form>
      </div>
    </div>
  );
}
