interface Props {
  onClose: () => void;
}

export function ShortcutHelp({ onClose }: Props) {
  return (
    <div
      className="shortcut-overlay"
      onClick={onClose}
      role="dialog"
      aria-label="Keyboard shortcuts"
    >
      <div className="shortcut-modal" onClick={e => e.stopPropagation()}>
        <div className="shortcut-modal__head">
          <h3>Keyboard Shortcuts</h3>
          <button className="shortcut-modal__close" onClick={onClose} aria-label="Close">×</button>
        </div>
        <table className="shortcut-table">
          <tbody>
            <tr><td><kbd>Alt</kbd>+<kbd>1</kbd>–<kbd>9</kbd></td><td>Switch to tab 1–9</td></tr>
            <tr><td><kbd>Ctrl</kbd>+<kbd>Enter</kbd></td><td>Run IoC scan</td></tr>
            <tr><td><kbd>?</kbd></td><td>Show this help</td></tr>
          </tbody>
        </table>
        <div className="shortcut-modal__hint">
          Drag tabs to reorder them. Shortcuts follow the visible order.
        </div>
      </div>
    </div>
  );
}
