import { useState } from 'react';
import type { ScanItem } from '../../types/vt';
import { calcVerdict, confToVerdict, countryFlag, hashLabel } from '../../lib/ioc';
import { DetectionBar } from './DetectionBar';
import { MetaGrid } from './MetaGrid';
import { CorrelationPanel } from './CorrelationPanel';
import { PassiveDnsPanel } from './PassiveDnsPanel';
import { CertHistoryPanel } from './CertHistoryPanel';
import { CopyButton } from '../shared/CopyButton';

interface Props {
  item: ScanItem;
  selected?: boolean;
  onToggleSelect?: () => void;
  forceExpanded?: boolean | null;
}

export function VtCard({ item, selected, onToggleSelect, forceExpanded }: Props) {
  const [collapsed, setCollapsed] = useState(true);
  // When forceExpanded is set, it overrides the per-card collapsed state.
  const effectiveCollapsed = forceExpanded !== undefined && forceExpanded !== null ? !forceExpanded : collapsed;

  if (item.pending) {
    return (
      <div className="vt-card vt-card--pending">
        <div className="vt-card-header" style={{ cursor: 'default' }}>
          <span className="vt-ioc-val">{item.ioc}</span>
          <span className="vt-scanning">scanning…</span>
        </div>
      </div>
    );
  }

  const shellProps = {
    collapsed: effectiveCollapsed,
    onToggle: () => {
      // Always update the local collapsed state so per-card toggles
      // survive after the expand/collapse all button is released.
      setCollapsed(c => !c);
    },
    selected,
    onToggleSelect,
  };

  if (item.error)        return <ErrorCard  item={item} {...shellProps} />;
  if (item.type === 'ip')     return <IpCard     item={item} {...shellProps} />;
  if (item.type === 'hash')   return <HashCard   item={item} {...shellProps} />;
  if (item.type === 'domain') return <DomainCard item={item} {...shellProps} />;
  return <ErrorCard item={item} {...shellProps} />;
}

interface CardProps {
  item: ScanItem;
  collapsed: boolean;
  onToggle: () => void;
  selected?: boolean;
  onToggleSelect?: () => void;
}

function CardShell({ header, body, corr, collapsed, onToggle, selected, onToggleSelect }: {
  header: React.ReactNode;
  body: React.ReactNode;
  corr: ScanItem;
  collapsed: boolean;
  onToggle: () => void;
  selected?: boolean;
  onToggleSelect?: () => void;
}) {
  return (
    <div className={`vt-card${selected ? ' vt-card--selected' : ''}`}>
      <div className="vt-card-header" onClick={onToggle}>
        {onToggleSelect && (
          <input
            type="checkbox"
            className="vt-select"
            checked={!!selected}
            onChange={onToggleSelect}
            onClick={e => e.stopPropagation()}
            title="Select for copy"
          />
        )}
        <span className={`vt-chevron${collapsed ? '' : ' open'}`}>›</span>
        {header}
      </div>
      {!collapsed && (
        <div className="vt-card-body">
          {body}
          <CorrelationPanel loading={corr.correlationLoading} data={corr.correlation as Parameters<typeof CorrelationPanel>[0]['data']} />
        </div>
      )}
    </div>
  );
}

function IpCard({ item, collapsed, onToggle, selected, onToggleSelect }: CardProps) {
  const raw = item.result as Record<string, unknown> | null;
  const d = (raw?.data as Record<string, unknown>) ?? {};
  const a = (d.attributes as Record<string, unknown>) ?? {};
  const s = (a.last_analysis_stats as Record<string, number>) ?? {};
  const mal = s.malicious ?? 0;
  const sus = s.suspicious ?? 0;
  const total = Object.values(s).reduce((x, y) => x + y, 0);
  const v = calcVerdict(mal, sus, total);
  const blendedV = (!item.correlationLoading && item.correlation !== null)
    ? confToVerdict(item.correlation.confidence)
    : v;
  const flag = countryFlag(String(a.country ?? ''));
  const ctry = String(a.country ?? '—');
  const meta = raw?._meta as Record<string, unknown> | undefined;
  const cache = (meta?.cache as Record<string, unknown>) ?? {};
  const seenBefore = !!cache.seenBefore;
  const stableId = String(cache.stableId ?? '');

  const header = (
    <>
      <span className="vt-type-badge badge-ip">IP ADDRESS</span>
      <span className="vt-ioc-val">{item.ioc}</span>
      {seenBefore && <span className="vt-seen" title="Already scanned">♻ SCANNED</span>}
      {flag && <span className="ctry-badge">{flag} {ctry}</span>}
      <span className={`verdict ${blendedV.cls}${item.correlationLoading ? ' verdict--pending' : ''}`}>● {blendedV.label}</span>
      <span className="vt-header-actions" onClick={e => e.stopPropagation()}>
        <CopyButton text={item.ioc} label="COPY" labelDone="✓" variant="overlay" className="copy-btn-small" />
        {stableId && (
          <a
            className="vt-detail-btn"
            href={`/result/${stableId}`}
            onClick={e => e.stopPropagation()}
            title={`UUID: ${stableId}`}
          >
            🔍 Deep Analysis
          </a>
        )}
      </span>
    </>
  );

  const rep = a.reputation !== undefined ? a.reputation : '—';
  const repColor = typeof rep === 'number' ? (rep > 0 ? 'green' : rep < 0 ? 'red' : '') : '';

  const body = (
    <>
      <DetectionBar malicious={mal} suspicious={sus} total={total} />
      <MetaGrid items={[
        { label: 'Malicious',  value: mal,                       color: mal > 0 ? 'red' : 'green' },
        { label: 'Suspicious', value: sus,                       color: sus > 0 ? 'yellow' : '' },
        { label: 'Undetected', value: s.undetected ?? 0 },
        { label: 'VT Verdict', value: v.label,                   color: v.cls === 'verdict-malicious' ? 'red' : v.cls === 'verdict-suspicious' ? 'yellow' : v.cls === 'verdict-clean' ? 'green' : '' },
        { label: 'Country',    value: (flag ? flag + ' ' : '') + ctry, color: 'cyan' },
        { label: 'ASN',        value: a.asn ? 'AS' + String(a.asn) : '—', color: 'purple' },
        { label: 'AS Owner',   value: String(a.as_owner ?? '—') },
        { label: 'Network',    value: String(a.network ?? '—') },
        { label: 'Reputation', value: String(rep),               color: repColor },
      ]} />
      <a className="vt-open-link" href={`https://www.virustotal.com/gui/ip-address/${item.ioc}`} target="_blank" rel="noopener">↗ Open in VirusTotal</a>
      <PassiveDnsPanel ioc={item.ioc} type="ip" />
    </>
  );

  return <CardShell header={header} body={body} corr={item} collapsed={collapsed} onToggle={onToggle} selected={selected} onToggleSelect={onToggleSelect} />;
}

function HashCard({ item, collapsed, onToggle, selected, onToggleSelect }: CardProps) {
  const raw = item.result as Record<string, unknown> | null;
  const d = (raw?.data as Record<string, unknown>) ?? {};
  const a = (d.attributes as Record<string, unknown>) ?? {};
  const s = (a.last_analysis_stats as Record<string, number>) ?? {};
  const mal = s.malicious ?? 0;
  const sus = s.suspicious ?? 0;
  const total = Object.values(s).reduce((x, y) => x + y, 0);
  const v = calcVerdict(mal, sus, total);
  const blendedV = (!item.correlationLoading && item.correlation !== null)
    ? confToVerdict(item.correlation.confidence)
    : v;

  const names = ((a.names as string[] | undefined) ?? []).slice(0, 3).join(', ') || '—';
  const ftype = String(a.type_description ?? a.magic ?? '—');
  const size = typeof a.size === 'number' ? (a.size / 1024).toFixed(1) + ' KB' : '—';
  const first = typeof a.first_submission_date === 'number' ? new Date(a.first_submission_date * 1000).toLocaleDateString('en-GB') : '—';
  const last  = typeof a.last_analysis_date    === 'number' ? new Date(a.last_analysis_date    * 1000).toLocaleDateString('en-GB') : '—';
  const meta = raw?._meta as Record<string, unknown> | undefined;
  const cache = (meta?.cache as Record<string, unknown>) ?? {};
  const seenBefore = !!cache.seenBefore;
  const stableId = String(cache.stableId ?? '');

  const header = (
    <>
      <span className={`vt-type-badge badge-hash`}>{hashLabel(item.ioc.length)}</span>
      <span className="vt-ioc-val">{item.ioc}</span>
      {seenBefore && <span className="vt-seen" title="Already scanned">♻ SCANNED</span>}
      <span className={`verdict ${blendedV.cls}${item.correlationLoading ? ' verdict--pending' : ''}`}>● {blendedV.label}</span>
      <span className="vt-header-actions" onClick={e => e.stopPropagation()}>
        <CopyButton text={item.ioc} label="COPY" labelDone="✓" variant="overlay" className="copy-btn-small" />
        {stableId && (
          <a
            className="vt-detail-btn"
            href={`/result/${stableId}`}
            onClick={e => e.stopPropagation()}
            title={`UUID: ${stableId}`}
          >
            🔍 Deep Analysis
          </a>
        )}
      </span>
    </>
  );

  const body = (
    <>
      <DetectionBar malicious={mal} suspicious={sus} total={total} />
      <MetaGrid items={[
        { label: 'Malicious',  value: mal,   color: mal > 0 ? 'red' : 'green' },
        { label: 'Suspicious', value: sus,   color: sus > 0 ? 'yellow' : '' },
        { label: 'Undetected', value: s.undetected ?? 0 },
        { label: 'VT Verdict', value: v.label, color: v.cls === 'verdict-malicious' ? 'red' : v.cls === 'verdict-suspicious' ? 'yellow' : v.cls === 'verdict-clean' ? 'green' : '' },
        { label: 'File Type',  value: ftype, color: 'purple' },
        { label: 'Size',       value: size },
        { label: 'File Names', value: names },
        { label: 'First Seen', value: first, color: 'cyan' },
        { label: 'Last Scan',  value: last },
      ]} />
      <a className="vt-open-link" href={`https://www.virustotal.com/gui/file/${item.ioc}`} target="_blank" rel="noopener">↗ Open in VirusTotal</a>
    </>
  );

  return <CardShell header={header} body={body} corr={item} collapsed={collapsed} onToggle={onToggle} selected={selected} onToggleSelect={onToggleSelect} />;
}

function DomainCard({ item, collapsed, onToggle, selected, onToggleSelect }: CardProps) {
  const raw = item.result as Record<string, unknown> | null;
  const d = (raw?.data as Record<string, unknown>) ?? {};
  const a = (d.attributes as Record<string, unknown>) ?? {};
  const s = (a.last_analysis_stats as Record<string, number>) ?? {};
  const mal = s.malicious ?? 0;
  const sus = s.suspicious ?? 0;
  const total = Object.values(s).reduce((x, y) => x + y, 0);
  const v = calcVerdict(mal, sus, total);
  const blendedV = (!item.correlationLoading && item.correlation !== null)
    ? confToVerdict(item.correlation.confidence)
    : v;

  const registrar = String(a.registrar ?? '—');
  const created = typeof a.creation_date    === 'number' ? new Date(a.creation_date    * 1000).toLocaleDateString('en-GB') : '—';
  const updated = typeof a.last_update_date === 'number' ? new Date(a.last_update_date * 1000).toLocaleDateString('en-GB') : '—';
  const cats = Object.values((a.categories as Record<string, string>) ?? {}).slice(0, 2).join(', ') || '—';
  const rep = a.reputation !== undefined ? a.reputation : '—';
  const repColor = typeof rep === 'number' ? (rep > 0 ? 'green' : rep < 0 ? 'red' : '') : '';
  const meta = raw?._meta as Record<string, unknown> | undefined;
  const cache = (meta?.cache as Record<string, unknown>) ?? {};
  const seenBefore = !!cache.seenBefore;
  const stableId = String(cache.stableId ?? '');

  const header = (
    <>
      <span className="vt-type-badge badge-domain">DOMAIN</span>
      <span className="vt-ioc-val">{item.ioc}</span>
      {seenBefore && <span className="vt-seen" title="Already scanned">♻ SCANNED</span>}
      <span className={`verdict ${blendedV.cls}${item.correlationLoading ? ' verdict--pending' : ''}`}>● {blendedV.label}</span>
      <span className="vt-header-actions" onClick={e => e.stopPropagation()}>
        <CopyButton text={item.ioc} label="COPY" labelDone="✓" variant="overlay" className="copy-btn-small" />
        {stableId && (
          <a
            className="vt-detail-btn"
            href={`/result/${stableId}`}
            onClick={e => e.stopPropagation()}
            title={`UUID: ${stableId}`}
          >
            🔍 Deep Analysis
          </a>
        )}
      </span>
    </>
  );

  const body = (
    <>
      <DetectionBar malicious={mal} suspicious={sus} total={total} />
      <MetaGrid items={[
        { label: 'Malicious',  value: mal,       color: mal > 0 ? 'red' : 'green' },
        { label: 'Suspicious', value: sus,       color: sus > 0 ? 'yellow' : '' },
        { label: 'Undetected', value: s.undetected ?? 0 },
        { label: 'VT Verdict', value: v.label,   color: v.cls === 'verdict-malicious' ? 'red' : v.cls === 'verdict-suspicious' ? 'yellow' : v.cls === 'verdict-clean' ? 'green' : '' },
        { label: 'Registrar',  value: registrar, color: 'purple' },
        { label: 'Created',    value: created,   color: 'cyan' },
        { label: 'Updated',    value: updated },
        { label: 'Categories', value: cats },
        { label: 'Reputation', value: String(rep), color: repColor },
      ]} />
      <a className="vt-open-link" href={`https://www.virustotal.com/gui/domain/${item.ioc}`} target="_blank" rel="noopener">↗ Open in VirusTotal</a>
      <PassiveDnsPanel ioc={item.ioc} type="domain" />
      <CertHistoryPanel domain={item.ioc} />
    </>
  );

  return <CardShell header={header} body={body} corr={item} collapsed={collapsed} onToggle={onToggle} selected={selected} onToggleSelect={onToggleSelect} />;
}

function ErrorCard({ item, collapsed, onToggle, selected, onToggleSelect }: CardProps) {
  const type = item.type ?? 'unknown';
  const badgeCls = type === 'ip' ? 'badge-ip' : type === 'domain' ? 'badge-domain' : 'badge-hash';

  const header = (
    <>
      <span className={`vt-type-badge ${badgeCls}`}>{String(type).toUpperCase()}</span>
      <span className="vt-ioc-val">{item.ioc}</span>
      <span className="verdict verdict-unknown">● VT: ERROR</span>
      <span className="vt-header-actions" onClick={e => e.stopPropagation()}>
        <CopyButton text={item.ioc} label="COPY" labelDone="✓" variant="overlay" className="copy-btn-small" />
      </span>
    </>
  );

  const body = (
    <div className="vt-error-box">
      {item.error}
    </div>
  );

  return <CardShell header={header} body={body} corr={item} collapsed={collapsed} onToggle={onToggle} selected={selected} onToggleSelect={onToggleSelect} />;
}
