interface Props {
  message: string;
  onClose: () => void;
}

export function SessionExpiredToast({ message, onClose }: Props) {
  return (
    <div className="update-toast" role="status" aria-live="polite">
      <button className="update-toast__close" onClick={onClose} aria-label="Dismiss">×</button>
      <div className="update-toast__head">
        <span className="update-toast__badge">Session</span>
        <strong className="update-toast__title">Signed out</strong>
      </div>
      <ul className="update-toast__list">
        <li>{message}</li>
      </ul>
      <button className="btn btn-primary update-toast__ok" onClick={onClose}>OK</button>
    </div>
  );
}
