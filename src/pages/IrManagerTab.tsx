import { useState, useEffect, useRef, useCallback } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { Modal } from '../components/shared/Modal';
import { CopyButton } from '../components/shared/CopyButton';
import type { IrCase } from '../types/api';
import { useAuthState } from '../context/AuthContext';

// ── Column alias mapping (bilingual EN/ID) ─────────────────────────────────
const IR_FIELDS = ['event_name', 'description', 'impact', 'details', 'corrective', 'preventive'] as const;
type IrField = typeof IR_FIELDS[number];

const FIELD_LABELS: Record<IrField, string> = {
  event_name:  'Event Name *',
  description: 'Description',
  impact:      'Impact',
  details:     'Details',
  corrective:  'Corrective Action',
  preventive:  'Preventive Action',
};

const COLUMN_ALIASES: Record<IrField, string[]> = {
  event_name:  ['event_name','event','alarm','alert','title','name','judul','nama_event','nama alert','alert name','nama event'],
  description: ['description','desc','keterangan','deskripsi','detail description'],
  impact:      ['impact','dampak','severity'],
  details:     ['details','detail','findings','temuan','log','full_log'],
  corrective:  ['corrective','corrective_action','corrective action','rekomendasi','remediation','tindakan korektif'],
  preventive:  ['preventive','preventive_action','preventive action','prevention','mitigation','tindakan preventif'],
};

type PreviewRow = Record<IrField, string> & { _id: string; _removed: boolean };

function autoDetectColumns(headers: string[]): Record<string, string> {
  const result: Record<string, string> = {};
  const normalized = headers.map(h => h.toLowerCase().trim().replace(/\s+/g, '_'));
  for (const field of IR_FIELDS) {
    for (const alias of COLUMN_ALIASES[field]) {
      const aliasNorm = alias.toLowerCase().replace(/\s+/g, '_');
      const idx = normalized.findIndex(h => h === aliasNorm || h.includes(aliasNorm));
      if (idx >= 0) { result[field] = headers[idx]; break; }
    }
  }
  return result;
}

function formatEmailTemplate(v: Record<string, string>): string {
  return `Dear .. Team,

We have found an alarm "${v.event_name}" with following details:

${v.description}

Impact:
${v.impact}

Details:
${v.details}

Corrective Action
${v.corrective}

Preventive Action
${v.preventive}

Thank you
Best Regards
Protergo`;
}

// ── File parsers ───────────────────────────────────────────────────────────
async function parseExcel(file: File): Promise<{ headers: string[]; rows: string[][] }> {
  const ExcelJS = (await import('exceljs')).default;
  const wb = new ExcelJS.Workbook();
  await wb.xlsx.load(await file.arrayBuffer());
  const ws = wb.worksheets[0];
  const allRows: string[][] = [];
  ws.eachRow(row => {
    allRows.push((row.values as unknown[]).slice(1).map(v => String(v ?? '')));
  });
  if (!allRows.length) return { headers: [], rows: [] };
  return { headers: allRows[0], rows: allRows.slice(1) };
}

function parseCsv(text: string): { headers: string[]; rows: string[][] } {
  const lines = text.split(/\r?\n/).filter(l => l.trim());
  if (!lines.length) return { headers: [], rows: [] };
  const split = (line: string) => line.split(',').map(c => c.replace(/^"|"$/g, '').trim());
  return { headers: split(lines[0]), rows: lines.slice(1).map(split) };
}

// ── Main component ─────────────────────────────────────────────────────────
export function IrManagerTab() {
  // Auth / permissions
  const { role } = useAuthState();
  const canDelete = role !== 'l1';

  // List state
  const [cases, setCases]           = useState<IrCase[]>([]);
  const [total, setTotal]           = useState(0);
  const [offset, setOffset]         = useState(0);
  const [searchQ, setSearchQ]       = useState('');
  const [loading, setLoading]       = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  // Expand / edit
  const [expandedId, setExpandedId]       = useState<string | null>(null);
  const [expandedBody, setExpandedBody]   = useState('');
  const [expandLoading, setExpandLoading] = useState(false);
  const [editingId, setEditingId]         = useState<string | null>(null);
  const [editTitle, setEditTitle]         = useState('');
  const [editDesc, setEditDesc]           = useState('');
  const [saving, setSaving]               = useState(false);

  // Add form
  const [showAdd, setShowAdd]   = useState(false);
  const [newTitle, setNewTitle] = useState('');
  const [newDesc, setNewDesc]   = useState('');
  const [adding, setAdding]     = useState(false);

  // Delete
  const [deleteTarget, setDeleteTarget] = useState<IrCase | null>(null);
  const [deleting, setDeleting]         = useState(false);

  // Import wizard: 0=hidden, 1=map columns, 2=preview rows
  const [importStep, setImportStep]           = useState<0 | 1 | 2>(0);
  const [importHeaders, setImportHeaders]     = useState<string[]>([]);
  const [importRows, setImportRows]           = useState<string[][]>([]);
  const [colMap, setColMap]                   = useState<Partial<Record<IrField, string>>>({});
  const [importing, setImporting]             = useState(false);
  const [previewRows, setPreviewRows]         = useState<PreviewRow[]>([]);
  const [editingPreviewId, setEditingPreviewId] = useState<string | null>(null);

  // Status
  const [error, setError]     = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);

  const fileRef    = useRef<HTMLInputElement>(null);
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  // ── Fetch ──────────────────────────────────────────────────────────────
  const fetchCases = useCallback(async (newOffset: number, q: string, append = false) => {
    if (append) setLoadingMore(true); else setLoading(true);
    setError(null);
    try {
      const res = await api.irCases.list(q, newOffset);
      setCases(prev => append ? [...prev, ...res.cases] : res.cases);
      setTotal(res.total);
      setOffset(newOffset);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      if (append) setLoadingMore(false); else setLoading(false);
    }
  }, []);

  useEffect(() => { fetchCases(0, ''); }, [fetchCases]);

  // ── Search debounce ────────────────────────────────────────────────────
  function handleSearchChange(q: string) {
    setSearchQ(q);
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => fetchCases(0, q), 300);
  }

  // ── Expand / collapse ─────────────────────────────────────────────────
  async function handleExpand(id: string) {
    if (expandedId === id) {
      setExpandedId(null);
      setEditingId(null);
      return;
    }
    setExpandedId(id);
    setEditingId(null);
    setExpandedBody('');
    setExpandLoading(true);
    try {
      const res = await api.irCases.detail(id);
      setExpandedBody(res.case.description);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setExpandLoading(false);
    }
  }

  // ── Add ───────────────────────────────────────────────────────────────
  async function handleAdd() {
    if (!newTitle.trim()) { setError('Title is required.'); return; }
    setAdding(true);
    setError(null);
    try {
      await api.irCases.create(newTitle.trim(), newDesc.trim());
      setSuccess('Case created.');
      setNewTitle(''); setNewDesc(''); setShowAdd(false);
      await fetchCases(0, searchQ);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setAdding(false);
    }
  }

  // ── Edit ──────────────────────────────────────────────────────────────
  function startEdit(c: IrCase) {
    setEditingId(c.id);
    setEditTitle(c.title);
    setEditDesc(expandedBody);
  }

  async function handleSave() {
    if (!editTitle.trim()) { setError('Title is required.'); return; }
    setSaving(true);
    setError(null);
    try {
      const res = await api.irCases.update(editingId!, editTitle.trim(), editDesc);
      setCases(prev => prev.map(c => c.id === editingId ? { ...c, title: res.case!.title, updated_at: res.case!.updated_at } : c));
      setExpandedBody(editDesc);
      setEditingId(null);
      setSuccess('Case updated.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  }

  // ── Delete ────────────────────────────────────────────────────────────
  async function handleDelete() {
    if (!deleteTarget) return;
    setDeleting(true);
    try {
      await api.irCases.delete(deleteTarget.id);
      setCases(prev => prev.filter(c => c.id !== deleteTarget.id));
      setTotal(t => t - 1);
      if (expandedId === deleteTarget.id) setExpandedId(null);
      setSuccess('Case deleted.');
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setDeleting(false);
      setDeleteTarget(null);
    }
  }

  // ── Import ────────────────────────────────────────────────────────────
  async function handleFileSelect(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    e.target.value = '';
    setError(null);
    try {
      let parsed: { headers: string[]; rows: string[][] };
      if (file.name.endsWith('.xlsx') || file.name.endsWith('.xls')) {
        parsed = await parseExcel(file);
      } else {
        parsed = parseCsv(await file.text());
      }
      if (!parsed.headers.length) { setError('File appears empty or unreadable.'); return; }
      setImportHeaders(parsed.headers);
      setImportRows(parsed.rows);
      setColMap(autoDetectColumns(parsed.headers) as Partial<Record<IrField, string>>);
      setImportStep(1);
    } catch (err) {
      setError(`Parse error: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  function cancelImport() {
    setImportStep(0);
    setImportHeaders([]); setImportRows([]); setColMap({});
    setPreviewRows([]); setEditingPreviewId(null);
  }

  function applyMappingToPreview() {
    const get = (field: IrField, row: string[]) => {
      const col = colMap[field] ?? '';
      const idx = importHeaders.indexOf(col);
      return idx >= 0 ? (row[idx] ?? '') : '';
    };
    const rows: PreviewRow[] = importRows.map((row, i) => {
      const r = { _id: String(i), _removed: false } as PreviewRow;
      for (const f of IR_FIELDS) r[f] = get(f, row);
      return r;
    });
    setPreviewRows(rows);
    setEditingPreviewId(null);
    setImportStep(2);
  }

  function updatePreviewField(id: string, field: IrField, value: string) {
    setPreviewRows(prev => prev.map(r => r._id === id ? { ...r, [field]: value } : r));
  }

  function toggleRemoveRow(id: string) {
    setPreviewRows(prev => prev.map(r => r._id === id ? { ...r, _removed: !r._removed } : r));
  }

  async function handleImportConfirm() {
    const toInsert = previewRows
      .filter(r => !r._removed && r.event_name.trim())
      .map(r => {
        const v: Record<string, string> = {};
        for (const f of IR_FIELDS) v[f] = r[f];
        return { title: v.event_name.trim(), description: formatEmailTemplate(v) };
      });

    if (!toInsert.length) { setError('No valid rows to import (event_name column required).'); return; }

    setImporting(true);
    setError(null);
    try {
      await api.irCases.bulkCreate(toInsert);
      setSuccess(`${toInsert.length} case(s) imported.`);
      cancelImport();
      await fetchCases(0, searchQ);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setImporting(false);
    }
  }

  // ── Render ────────────────────────────────────────────────────────────
  return (
    <div className="tab-content ir-manager-tab">
      <div className="section-header">
        <h2>IR Manager</h2>
        {total > 0 && <span className="line-count">{total} case{total !== 1 ? 's' : ''}</span>}
        <div style={{ marginLeft: 'auto', display: 'flex', gap: '0.5rem' }}>
          <button className="btn btn-secondary" onClick={() => { setShowAdd(v => !v); setError(null); }}>
            {showAdd ? '✕ Cancel' : '+ Add Case'}
          </button>
          <button className="btn btn-secondary" onClick={() => fileRef.current?.click()}>
            ⬆ Import
          </button>
          <button className="btn btn-secondary" onClick={() => fetchCases(0, searchQ)} title="Refresh">
            ↻
          </button>
        </div>
      </div>

      <input
        ref={fileRef}
        type="file"
        accept=".xlsx,.xls,.csv"
        style={{ display: 'none' }}
        onChange={handleFileSelect}
      />

      {error   && <StatusMessage type="error"   message={error}   onDismiss={() => setError(null)} />}
      {success && <StatusMessage type="success" message={success} onDismiss={() => setSuccess(null)} />}

      {/* ── Add form ── */}
      {showAdd && (
        <div className="ir-add-form">
          <div className="form-group">
            <label className="form-label">Title</label>
            <input
              className="form-input"
              value={newTitle}
              onChange={e => setNewTitle(e.target.value)}
              placeholder="Event / alarm name"
              onKeyDown={e => e.key === 'Enter' && handleAdd()}
            />
          </div>
          <div className="form-group">
            <label className="form-label">Description</label>
            <textarea
              className="form-textarea"
              rows={6}
              value={newDesc}
              onChange={e => setNewDesc(e.target.value)}
              placeholder="Case description..."
            />
          </div>
          <div className="ir-add-form__actions">
            <button className="btn btn-primary" onClick={handleAdd} disabled={adding}>
              {adding ? <Spinner size={14} /> : 'Save Case'}
            </button>
            <button className="btn btn-secondary" onClick={() => { setShowAdd(false); setNewTitle(''); setNewDesc(''); }}>
              Cancel
            </button>
          </div>
        </div>
      )}

      {/* ── Import wizard overlay ── */}
      {importStep === 1 && (
        <div className="ir-import-overlay" onClick={e => { if (e.target === e.currentTarget) { setImportStep(0); } }}>
          <div className="ir-import-box">
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
              <h3 className="ir-import-title">Import IR Cases</h3>
              <span className="ir-import-step">Step 1 of 2 — Map Columns</span>
            </div>

            <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', margin: 0 }}>
              Preview (first 5 rows). Map which column maps to each field, then confirm.
            </p>

            {/* Preview table */}
            <div className="ir-preview-table-wrap">
              <table className="ir-preview-table">
                <thead>
                  <tr>{importHeaders.map(h => <th key={h}>{h}</th>)}</tr>
                </thead>
                <tbody>
                  {importRows.slice(0, 5).map((row, i) => (
                    <tr key={i}>
                      {importHeaders.map((_, j) => <td key={j}>{row[j] ?? ''}</td>)}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Column mapping */}
            <div className="ir-col-map-grid">
              {IR_FIELDS.map(field => (
                <div key={field} className="ir-col-map-row">
                  <label className="ir-col-map-label">{FIELD_LABELS[field]}</label>
                  <select
                    className="form-input"
                    value={colMap[field] ?? ''}
                    onChange={e => setColMap(prev => ({ ...prev, [field]: e.target.value }))}
                  >
                    <option value="">(none)</option>
                    {importHeaders.map(h => <option key={h} value={h}>{h}</option>)}
                  </select>
                </div>
              ))}
            </div>

            <div className="ir-import-actions">
              <button className="btn btn-secondary" onClick={cancelImport}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={applyMappingToPreview}>
                Preview Rows →
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── Import wizard step 2: row preview & editor ── */}
      {importStep === 2 && (() => {
        const readyCount   = previewRows.filter(r => !r._removed && r.event_name.trim()).length;
        const removedCount = previewRows.filter(r => r._removed).length;
        return (
          <div className="ir-import-overlay" onClick={e => { if (e.target === e.currentTarget) cancelImport(); }}>
            <div className="ir-import-box ir-import-box--wide">

              {/* Header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                <h3 className="ir-import-title">Import IR Cases</h3>
                <span className="ir-import-step">Step 2 of 2 — Review Rows</span>
              </div>

              {/* Stats bar */}
              <div className="ir-preview-stats">
                <span>{readyCount} row{readyCount !== 1 ? 's' : ''} ready</span>
                {removedCount > 0 && (
                  <span className="ir-preview-stats__removed">· {removedCount} removed</span>
                )}
              </div>

              {/* Row table */}
              <div className="ir-preview-table-wrap ir-preview-table-wrap--editable">
                <table className="ir-preview-table">
                  <thead>
                    <tr>
                      <th className="ir-preview-num">#</th>
                      <th>Event Name</th>
                      <th style={{ width: '5rem' }}></th>
                    </tr>
                  </thead>
                  <tbody>
                    {previewRows.map((row, i) => (
                      <>
                        <tr key={row._id} className={row._removed ? 'ir-preview-row--removed' : ''}>
                          <td className="ir-preview-num">{i + 1}</td>
                          <td>
                            <input
                              className="ir-preview-cell-input"
                              value={row.event_name}
                              onChange={e => updatePreviewField(row._id, 'event_name', e.target.value)}
                            />
                          </td>
                          <td style={{ whiteSpace: 'nowrap' }}>
                            <button
                              className="ir-preview-edit-btn"
                              title="Expand / collapse"
                              onClick={() => setEditingPreviewId(prev => prev === row._id ? null : row._id)}
                            >✎</button>
                            <button
                              className={`ir-preview-remove-btn${row._removed ? ' ir-preview-remove-btn--undo' : ''}`}
                              title={row._removed ? 'Undo remove' : 'Remove row'}
                              onClick={() => toggleRemoveRow(row._id)}
                            >{row._removed ? '↩' : '×'}</button>
                          </td>
                        </tr>

                        {editingPreviewId === row._id && (
                          <tr key={`${row._id}-edit`} className="ir-preview-edit-row">
                            <td />
                            <td colSpan={2}>
                              <div className="ir-preview-edit-panel">
                                {IR_FIELDS.filter(f => f !== 'event_name').map(f => (
                                  <div key={f}>
                                    <label className="ir-col-map-label">{FIELD_LABELS[f]}</label>
                                    <textarea
                                      className="form-textarea"
                                      rows={2}
                                      value={row[f]}
                                      onChange={e => updatePreviewField(row._id, f, e.target.value)}
                                    />
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Actions */}
              <div className="ir-import-actions">
                <button className="btn btn-secondary" onClick={cancelImport}>Cancel</button>
                <button className="btn btn-secondary" onClick={() => setImportStep(1)}>← Back</button>
                <button
                  className="btn btn-primary"
                  onClick={handleImportConfirm}
                  disabled={importing || readyCount === 0}
                >
                  {importing ? <Spinner size={14} /> : `Import ${readyCount} row${readyCount !== 1 ? 's' : ''}`}
                </button>
              </div>
            </div>
          </div>
        );
      })()}

      {/* ── Search ── */}
      <div className="ir-search-row">
        <input
          className="form-input"
          placeholder="Search cases..."
          value={searchQ}
          onChange={e => handleSearchChange(e.target.value)}
        />
      </div>

      {/* ── List ── */}
      {loading && <div style={{ padding: '2rem', display: 'flex', justifyContent: 'center' }}><Spinner size={24} /></div>}

      {!loading && (
        <div className="ir-cases-list">
          {cases.length === 0 && (
            <div className="dash-empty" style={{ padding: '2rem', textAlign: 'center', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
              {searchQ ? 'No cases match your search.' : 'No cases yet. Add one or import from Excel/CSV.'}
            </div>
          )}

          {cases.map(c => {
            const isExpanded = expandedId === c.id;
            const isEditing  = editingId  === c.id;
            return (
              <div key={c.id} className={`ir-case-card${isExpanded ? ' ir-case-card--expanded' : ''}`}>
                {/* Header row */}
                <div className="ir-case-header" onClick={() => handleExpand(c.id)}>
                  <span className="ir-chevron">{isExpanded ? '▾' : '▸'}</span>
                  <span className="ir-case-glyph" aria-hidden="true">
                    {(c.title || '?').trim().charAt(0).toUpperCase() || '?'}
                  </span>
                  <span className="ir-case-title">{c.title}</span>
                  <div className="ir-case-actions" onClick={e => e.stopPropagation()}>
                    {canDelete && (
                      <button
                        className="btn-delete-ir"
                        onClick={() => setDeleteTarget(c)}
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </div>

                {/* Expanded body */}
                {isExpanded && (
                  <div className="ir-case-body">
                    {expandLoading && expandedId === c.id ? (
                      <div style={{ display: 'flex', justifyContent: 'center', padding: '1rem' }}><Spinner size={18} /></div>
                    ) : isEditing ? (
                      <div className="ir-edit-form">
                        <div className="form-group">
                          <label className="form-label">Title</label>
                          <input
                            className="form-input"
                            value={editTitle}
                            onChange={e => setEditTitle(e.target.value)}
                          />
                        </div>
                        <div className="form-group">
                          <label className="form-label">Description</label>
                          <textarea
                            className="form-textarea"
                            rows={14}
                            value={editDesc}
                            onChange={e => setEditDesc(e.target.value)}
                          />
                        </div>
                        <div className="ir-edit-form__actions">
                          <button className="btn btn-primary" onClick={handleSave} disabled={saving}>
                            {saving ? <Spinner size={14} /> : 'Save'}
                          </button>
                          <button className="btn btn-secondary" onClick={() => setEditingId(null)}>Cancel</button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="ir-case-body__actions">
                          <button className="btn btn-secondary" style={{ fontSize: '0.75rem' }} onClick={() => startEdit(c)}>
                            ✎ Edit
                          </button>
                          <CopyButton text={expandedBody} />
                        </div>
                        <pre className="ir-description">{expandedBody}</pre>
                      </>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {/* ── Load more ── */}
      {!loading && cases.length > 0 && cases.length < total && (
        <div className="ir-load-more">
          <button
            className="btn btn-secondary"
            onClick={() => fetchCases(offset + 20, searchQ, true)}
            disabled={loadingMore}
          >
            {loadingMore ? <Spinner size={14} /> : `Load more (${total - cases.length} remaining)`}
          </button>
        </div>
      )}

      {/* ── Delete confirm ── */}
      <Modal
        open={!!deleteTarget}
        title="Delete Case"
        message={`Delete "${deleteTarget?.title}"? This cannot be undone.`}
        confirmLabel={deleting ? 'Deleting…' : 'Delete'}
        onConfirm={handleDelete}
        onCancel={() => setDeleteTarget(null)}
        danger
      />
    </div>
  );
}
