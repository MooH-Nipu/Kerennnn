import { useEffect, useState } from 'react';
import { LATEST_UPDATE } from '../../lib/updates';

// Shows the latest changelog entry once per user (per browser) per version.
// Bumping LATEST_UPDATE.version re-triggers it for everyone (see updates.ts).
const SEEN_KEY = 'socToolboxSeenUpdate';

export function UpdateToast() {
  const [show, setShow] = useState(false);

  useEffect(() => {
    try {
      const seen = localStorage.getItem(SEEN_KEY);
      if (seen !== LATEST_UPDATE.version) setShow(true);
    } catch { /* storage blocked → just don't show */ }
  }, []);

  function dismiss() {
    try { localStorage.setItem(SEEN_KEY, LATEST_UPDATE.version); } catch { /* ignore */ }
    setShow(false);
  }

  if (!show) return null;

  return (
    <div className="update-toast" role="status" aria-live="polite">
      <button className="update-toast__close" onClick={dismiss} aria-label="Tutup">×</button>
      <div className="update-toast__head">
        <span className="update-toast__badge">✨ Update changes</span>
        <strong className="update-toast__title">{LATEST_UPDATE.title}</strong>
      </div>
      <ul className="update-toast__list">
        {LATEST_UPDATE.changes.map((c, i) => (
          <li key={i}>{c}</li>
        ))}
      </ul>
      <button className="btn btn-primary btn-sm update-toast__ok" onClick={dismiss}>
        Mengerti
      </button>
    </div>
  );
}
