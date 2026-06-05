import { useEffect, useMemo, useRef, useState } from 'react';
import type { Role } from '../../types/api';
import type { TabId } from '../../lib/permissions';
import { orderedAllowedTabs, type TabDef } from './TabNav';

interface Props {
  open: boolean;
  role: Role;
  order: TabId[];
  hidden: TabId[];
  onClose: () => void;
  onSave: (order: TabId[], hidden: TabId[]) => void;
  onReset: () => void;
}

export function TabCustomizer({ open, role, order, hidden, onClose, onSave, onReset }: Props) {
  // Label/icon lookup for every tab this role may see (order-independent).
  const defById = useMemo(() => {
    const m = new Map<TabId, TabDef>();
    for (const t of orderedAllowedTabs(role, [])) m.set(t.id, t);
    return m;
  }, [role]);

  // Working copy — initialized from props each time the modal opens.
  const [items, setItems] = useState<TabId[]>([]);
  const [hiddenSet, setHiddenSet] = useState<Set<TabId>>(new Set());
  const dragId = useRef<TabId | null>(null);

  useEffect(() => {
    if (!open) return;
    setItems(orderedAllowedTabs(role, order).map(t => t.id));
    setHiddenSet(new Set(hidden));
  }, [open]); // eslint-disable-line react-hooks/exhaustive-deps -- snapshot props only on open

  useEffect(() => {
    if (!open) return;
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [open, onClose]);

  if (!open) return null;

  const visibleCount = items.filter(id => !hiddenSet.has(id)).length;

  function move(from: number, to: number) {
    if (to < 0 || to >= items.length) return;
    setItems(prev => {
      const next = [...prev];
      const [moved] = next.splice(from, 1);
      next.splice(to, 0, moved);
      return next;
    });
  }

  function onDragOver(e: React.DragEvent, overId: TabId) {
    e.preventDefault();
    const id = dragId.current;
    if (id == null || id === overId) return;
    setItems(prev => {
      const from = prev.indexOf(id);
      const to = prev.indexOf(overId);
      if (from < 0 || to < 0 || from === to) return prev;
      const next = [...prev];
      next.splice(from, 1);
      next.splice(to, 0, id);
      return next;
    });
  }

  function toggleHidden(id: TabId) {
    setHiddenSet(prev => {
      const next = new Set(prev);
      if (next.has(id)) {
        next.delete(id);
      } else {
        // Never hide the last visible tab.
        if (items.filter(x => !next.has(x)).length <= 1) return prev;
        next.add(id);
      }
      return next;
    });
  }

  function handleSave() {
    onSave(items, [...hiddenSet]);
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-box tabcust-box" onClick={e => e.stopPropagation()}>
        <h3 className="modal-title">Atur Tab</h3>
        <p className="modal-msg">Seret untuk mengubah urutan, atau sembunyikan tab yang tidak dipakai.</p>

        <ul className="tabcust-list">
          {items.map((id, idx) => {
            const def = defById.get(id);
            if (!def) return null;
            const isHidden = hiddenSet.has(id);
            const lockHide = !isHidden && visibleCount <= 1;
            return (
              <li
                key={id}
                className={`tabcust-row ${isHidden ? 'tabcust-row--hidden' : ''}`}
                draggable
                onDragStart={() => { dragId.current = id; }}
                onDragOver={e => onDragOver(e, id)}
                onDragEnd={() => { dragId.current = null; }}
              >
                <span className="tabcust-handle" aria-hidden="true">⠿</span>
                <span className="tabcust-icon" aria-hidden="true">{def.icon}</span>
                <span className="tabcust-label">{def.label}</span>

                <div className="tabcust-controls">
                  <button
                    type="button"
                    className="btn btn-sm btn-ghost tabcust-move"
                    onClick={() => move(idx, idx - 1)}
                    disabled={idx === 0}
                    aria-label={`Naikkan ${def.label}`}
                  >▲</button>
                  <button
                    type="button"
                    className="btn btn-sm btn-ghost tabcust-move"
                    onClick={() => move(idx, idx + 1)}
                    disabled={idx === items.length - 1}
                    aria-label={`Turunkan ${def.label}`}
                  >▼</button>
                  <label
                    className="tabcust-toggle"
                    title={lockHide ? 'Minimal satu tab harus tampil' : undefined}
                  >
                    <input
                      type="checkbox"
                      checked={!isHidden}
                      disabled={lockHide}
                      onChange={() => toggleHidden(id)}
                    />
                    <span>{isHidden ? 'Sembunyi' : 'Tampil'}</span>
                  </label>
                </div>
              </li>
            );
          })}
        </ul>

        <div className="modal-actions tabcust-actions">
          <button type="button" className="btn btn-ghost" onClick={onReset}>Reset default</button>
          <span className="tabcust-spacer" />
          <button type="button" className="btn btn-ghost" onClick={onClose}>Batal</button>
          <button type="button" className="btn btn-primary" onClick={handleSave}>Simpan</button>
        </div>
      </div>
    </div>
  );
}
