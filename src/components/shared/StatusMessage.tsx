interface Props {
  type: 'error' | 'success' | 'info' | 'warning';
  message: string;
  onDismiss?: () => void;
}

const ICONS = { error: '✗', success: '✓', info: 'ℹ', warning: '⚠' };

export function StatusMessage({ type, message, onDismiss }: Props) {
  return (
    <div
      className={`status-msg status-msg--${type}`}
      role={type === 'error' ? 'alert' : 'status'}
      aria-live={type === 'error' ? 'assertive' : 'polite'}
    >
      <span className="status-msg__icon">{ICONS[type]}</span>
      <span className="status-msg__text">{message}</span>
      {onDismiss && (
        <button type="button" className="status-msg__dismiss" onClick={onDismiss} aria-label="Dismiss">×</button>
      )}
    </div>
  );
}
