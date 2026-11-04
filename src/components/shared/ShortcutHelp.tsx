import { useEffect, useRef } from 'react';

interface Props {
  onClose: () => void;
}

export function ShortcutHelp({ onClose }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const previousFocus = document.activeElement as HTMLElement | null;
    const focusable = () => Array.from(dialogRef.current?.querySelectorAll<HTMLElement>('button, [href], [tabindex]:not([tabindex="-1"])') ?? []);
    focusable()[0]?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') onClose();
      if (event.key !== 'Tab') return;
      const items = focusable();
      if (!items.length) return;
      const first = items[0];
      const last = items[items.length - 1];
      if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first.focus(); }
    };
    window.addEventListener('keydown', onKey);
    return () => { window.removeEventListener('keydown', onKey); previousFocus?.focus(); };
  }, [onClose]);
  return (
    <div
      className="shortcut-overlay"
      onClick={onClose}
      role="dialog"
      aria-modal="true"
      aria-labelledby="shortcut-help-title"
    >
      <div ref={dialogRef} className="shortcut-modal" onClick={e => e.stopPropagation()}>
        <div className="shortcut-modal__head">
          <h3 id="shortcut-help-title">Keyboard Shortcuts</h3>
          <button type="button" className="shortcut-modal__close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <table className="shortcut-table">
          <tbody>
            <tr><td><kbd>Alt</kbd>+<kbd>1</kbd>–<kbd>9</kbd></td><td>Switch to tab 1–9</td></tr>
            <tr><td><kbd>Ctrl</kbd>+<kbd>Enter</kbd></td><td>Run IoC scan</td></tr>
            <tr><td><kbd>Ctrl</kbd>+<kbd>K</kbd></td><td>Paste an IOC to scan</td></tr>
            <tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
          </tbody>
        </table>
        <div className="shortcut-modal__hint">Shortcuts follow visible navigation order.</div>
      </div>
    </div>
  );
}
