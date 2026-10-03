import { useState, FormEvent } from 'react';
import { useAuthState, useAuthActions } from '../../context/AuthContext';
import { Spinner } from '../shared/Spinner';
import { SessionExpiredToast } from '../shared/SessionExpiredToast';

export function LoginPage() {
  const { pending, loginError, sessionExpired } = useAuthState();
  const { login, clearError } = useAuthActions();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [showExpiredToast, setShowExpiredToast] = useState(sessionExpired);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!username.trim() || !password) return;
    await login(username.trim(), password);
  }

  return (
    <div className="login-page">
      <div className="login-layout">
        <section className="login-intro" aria-label="Product introduction">
          <div className="login-kicker">SECURITY OPERATIONS PLATFORM</div>
          <h1>Investigate faster.<br /><span>Respond with confidence.</span></h1>
          <p>One workspace for IOC triage, threat intelligence, and operational reporting.</p>
          <div className="login-intro__status"><span /> Systems ready for analyst access</div>
        </section>
        <div className="login-card">
          <div className="login-logo">
            <span className="login-logo__icon">◈</span>
            <div>
              <span className="login-logo__title">Charlie kerennnn</span>
              <span className="login-logo__sub">SOC Toolbox</span>
            </div>
          </div>
          <div className="login-heading">
            <h2>Welcome back</h2>
            <p>Sign in to continue to your operations workspace.</p>
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

      {showExpiredToast && (
        <SessionExpiredToast
          message="Your session ended automatically. Please sign in again."
          onClose={() => setShowExpiredToast(false)}
        />
      )}
    </div>
  );
}
