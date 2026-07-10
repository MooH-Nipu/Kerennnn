import { useState, useRef, useCallback } from 'react';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';

interface FileSlot {
  id: string;
  label: string;
  accept: string;
  description: string;
}

const SLOTS: FileSlot[] = [
  { id: 'dci',   label: 'DCI',   accept: '.csv', description: 'CSV from Kibana DCI' },
  { id: 'bprks', label: 'BPRKS', accept: '.csv', description: 'CSV from Kibana BPRKS' },
  { id: 'pac',   label: 'PAC',   accept: '.csv', description: 'CSV from Kibana PAC' },
  { id: 'smi',   label: 'SMI',   accept: '.csv', description: 'CSV "Daily" from SMI' },
  { id: 'mms',   label: 'MMS',   accept: '.csv', description: 'CSV "Daily" → MMS Daily Report (3-sheet)' },
];

export function DailyEodTab() {
  const [files, setFiles] = useState<Record<string, File | null>>({});
  const [date, setDate] = useState(() => new Date().toISOString().slice(0, 10));
  const [shiftName, setShiftName] = useState('');
  const [defaultAlarmTime, setDefaultAlarmTime] = useState('');
  const [showMmsFields, setShowMmsFields] = useState(false);
  const [projectName, setProjectName] = useState('');
  const [customerName, setCustomerName] = useState('');
  const [siemMemory, setSiemMemory] = useState('');
  const [siemCpu, setSiemCpu] = useState('');
  const [siemDisk, setSiemDisk] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [success, setSuccess] = useState<string | null>(null);
  const inputRefs = useRef<Record<string, HTMLInputElement | null>>({});

  function handleFile(id: string, f: File | null) {
    setFiles(prev => ({ ...prev, [id]: f }));
  }

  function handleDrop(id: string, e: React.DragEvent) {
    e.preventDefault();
    const f = e.dataTransfer.files[0];
    if (f) handleFile(id, f);
  }

  const clearAll = useCallback(() => {
    setFiles({});
    setError(null);
    setSuccess(null);
    setDefaultAlarmTime('');
    setShowMmsFields(false);
    setProjectName('');
    setCustomerName('');
    setSiemMemory('');
    setSiemCpu('');
    setSiemDisk('');
    Object.values(inputRefs.current).forEach(ref => { if (ref) ref.value = ''; });
  }, []);

  async function handleGenerate() {
    setLoading(true);
    setError(null);
    setSuccess(null);
    try {
      const fd = new FormData();
      fd.append('report_date', date);
      if (shiftName) fd.append('shift_name', shiftName);
      if (defaultAlarmTime) fd.append('default_alarm_time', defaultAlarmTime);
      if (projectName) fd.append('project_name', projectName);
      if (customerName) fd.append('customer_name', customerName);
      if (siemMemory) fd.append('siem_memory', siemMemory);
      if (siemCpu) fd.append('siem_cpu', siemCpu);
      if (siemDisk) fd.append('siem_disk', siemDisk);
      for (const slot of SLOTS) {
        const f = files[slot.id];
        if (f) fd.append(slot.id, f, f.name);
      }

      const res = await fetch('/api/kibana-combined-report', {
        method: 'POST',
        credentials: 'include',
        body: fd,
      });

      if (!res.ok) {
        const j = await res.json().catch(() => ({})) as { error?: string };
        throw new Error(j.error ?? `HTTP ${res.status}`);
      }

      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `EOD_${date}${shiftName ? '_' + shiftName : ''}.xlsx`;
      a.click();
      URL.revokeObjectURL(url);
      setSuccess('✓ Excel file downloaded successfully.');
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setLoading(false);
    }
  }

  const hasAnyFile = SLOTS.some(s => !!files[s.id]);

  return (
    <div className="tab-content daily-eod-tab">
      <div className="section-header">
        <h2>Daily EOD</h2>
      </div>

      {error && <StatusMessage type="error" message={error} onDismiss={() => setError(null)} />}
      {success && <StatusMessage type="success" message={success} onDismiss={() => setSuccess(null)} />}

      <div className="eod-controls" style={{ alignItems: 'flex-end' }}>
        <div className="form-group" style={{ flex: '0 0 180px' }}>
          <label className="form-label" htmlFor="eod-date">Report Date</label>
          <input
            id="eod-date"
            type="date"
            className="form-input"
            value={date}
            onChange={e => setDate(e.target.value)}
          />
        </div>
        <div className="form-group" style={{ flex: '1' }}>
          <label className="form-label" htmlFor="eod-shift">Shift Name</label>
          <input
            id="eod-shift"
            type="text"
            className="form-input"
            placeholder="e.g. Morning / Afternoon / Night"
            value={shiftName}
            onChange={e => setShiftName(e.target.value)}
          />
        </div>
        <div className="form-group" style={{ flex: '0 0 165px' }}>
          <label className="form-label" htmlFor="eod-alarm-time">Default Alarm Time</label>
          <input
            id="eod-alarm-time"
            type="time"
            step="1"
            className="form-input"
            value={defaultAlarmTime}
            onChange={e => setDefaultAlarmTime(e.target.value)}
            title="Fallback alarm time for CSV rows without a timestamp"
          />
        </div>
      </div>

      {files['mms'] && (
        <div style={{ marginTop: '0.75rem' }}>
          <button
            className="btn btn-ghost"
            style={{ fontSize: '0.8rem', padding: '0.3rem 0.6rem' }}
            onClick={() => setShowMmsFields(v => !v)}
          >
            {showMmsFields ? '▾' : '▸'} MMS Options
          </button>
          {showMmsFields && (
            <div className="eod-controls" style={{ marginTop: '0.5rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ flex: '1' }}>
                <label className="form-label" htmlFor="mms-project">Project Name</label>
                <input id="mms-project" type="text" className="form-input" placeholder="MMS" value={projectName} onChange={e => setProjectName(e.target.value)} />
              </div>
              <div className="form-group" style={{ flex: '1' }}>
                <label className="form-label" htmlFor="mms-customer">Customer Name</label>
                <input id="mms-customer" type="text" className="form-input" placeholder="MMS Resources" value={customerName} onChange={e => setCustomerName(e.target.value)} />
              </div>
              <div className="form-group" style={{ flex: '0 0 120px' }}>
                <label className="form-label" htmlFor="mms-mem">Memory %</label>
                <input id="mms-mem" type="text" className="form-input" placeholder="e.g. 38.56%" value={siemMemory} onChange={e => setSiemMemory(e.target.value)} />
              </div>
              <div className="form-group" style={{ flex: '0 0 120px' }}>
                <label className="form-label" htmlFor="mms-cpu">CPU %</label>
                <input id="mms-cpu" type="text" className="form-input" placeholder="e.g. 9.74%" value={siemCpu} onChange={e => setSiemCpu(e.target.value)} />
              </div>
              <div className="form-group" style={{ flex: '0 0 120px' }}>
                <label className="form-label" htmlFor="mms-disk">Disk %</label>
                <input id="mms-disk" type="text" className="form-input" placeholder="e.g. 29.88%" value={siemDisk} onChange={e => setSiemDisk(e.target.value)} />
              </div>
            </div>
          )}
        </div>
      )}

      <div className="eod-slots">
        {SLOTS.map(slot => {
          const f = files[slot.id];
          const lineEst = f ? Math.round(f.size / 80) : null;
          return (
            <div
              key={slot.id}
              className={`eod-slot ${f ? 'eod-slot--filled' : ''}`}
              onDragOver={e => e.preventDefault()}
              onDrop={e => handleDrop(slot.id, e)}
              onClick={() => inputRefs.current[slot.id]?.click()}
            >
              <input
                type="file"
                accept={slot.accept}
                ref={el => { inputRefs.current[slot.id] = el; }}
                style={{ display: 'none' }}
                onChange={e => handleFile(slot.id, e.target.files?.[0] ?? null)}
              />
              <div className="eod-slot__label">{slot.label}</div>
              {f ? (
                <>
                  <div className="eod-slot__name">{f.name}</div>
                  {lineEst && <div className="eod-slot__est">~{lineEst} rows</div>}
                  <button
                    className="eod-slot__clear"
                    onClick={e => { e.stopPropagation(); handleFile(slot.id, null); }}
                  >×</button>
                </>
              ) : (
                <div className="eod-slot__hint">Drop CSV or click to choose</div>
              )}
              <div className="eod-slot__desc">{slot.description}</div>
            </div>
          );
        })}
      </div>

      <div className="tab-actions">
        <button className="btn btn-primary" onClick={handleGenerate} disabled={!hasAnyFile || loading}>
          {loading ? <><Spinner size={14} /> Generating…</> : '⬇ Generate Excel'}
        </button>
        <button className="btn btn-ghost" onClick={clearAll} disabled={!hasAnyFile}>
          Reset all
        </button>
      </div>
    </div>
  );
}
