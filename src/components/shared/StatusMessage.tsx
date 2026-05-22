interface Props {
  type: 'error' | 'success' | 'info' | 'warning';
  message: string;
  onDismiss?: () => void;
}

const ICONS = { error: '✗', success: '✓', info: 'ℹ', warning: '⚠' };

export function StatusMessage({ type, message, onDismiss }: Props) {
  return (
    <div className={`status-msg status-msg--${type}`}>
      <span className="status-msg__icon">{ICONS[type]}</span>
      <span className="status-msg__text">{message}</span>
      {onDismiss && (
        <button className="status-msg__dismiss" onClick={onDismiss} aria-label="Tutup">×</button>
      )}
    </div>
  );
}
