import { useEffect, useState, FormEvent, DragEvent } from 'react';
import { api } from '../lib/api';
import { StatusMessage } from '../components/shared/StatusMessage';
import { Spinner } from '../components/shared/Spinner';
import { ALL_TABS, isTabVisible } from '../components/layout/TabNav';
import { DEFAULT_NAV_LAYOUT, type NavGroup, type TabPrefsState } from '../hooks/useTabPrefs';
import type { Role } from '../types/api';
import type { TabId } from '../lib/permissions';
import { useAuthActions, useAuthState } from '../context/AuthContext';

interface Props {
  role: Role;
  prefs: TabPrefsState & {
    save: (next: TabPrefsState) => Promise<void>;
    reset: () => Promise<void>;
    dismissTutorial: () => Promise<void>;
  };
}

type DragItem = { type: 'tab'; id: TabId } | { type: 'group'; id: string };
type SettingsSection = 'workspace' | 'navigation' | 'alerts';

const SETTINGS_SECTIONS: { id: SettingsSection; label: string; note: string }[] = [
  { id: 'workspace', label: 'Workspace', note: 'Team scope' },
  { id: 'navigation', label: 'Navigation', note: 'Sidebar layout' },
  { id: 'alerts', label: 'Alerts', note: 'Webhook delivery' },
];

export function SettingsTab({ role, prefs }: Props) {
  const { setActiveTeam } = useAuthActions();
  const { assignedTeam, allowedTeams, canSwitchTeam, activeTeam } = useAuthState();
  const canChooseTeam = canSwitchTeam;
  const [activeSection, setActiveSection] = useState<SettingsSection>('workspace');
  const [loadingWebhook, setLoadingWebhook] = useState(true);
  const [savingWebhook, setSavingWebhook] = useState(false);
  const [savingNav, setSavingNav] = useState(false);
  const [navStatus, setNavStatus] = useState<{ type: 'error' | 'success' | 'info'; text: string } | null>(null);
  const [webhookStatus, setWebhookStatus] = useState<{ type: 'error' | 'success' | 'info'; text: string } | null>(null);
  const [draft, setDraft] = useState<TabPrefsState>({ hidden: prefs.hidden, tabLabels: prefs.tabLabels, groupLabels: prefs.groupLabels, layout: prefs.layout, tutorialDismissed: prefs.tutorialDismissed });
  const [dragging, setDragging] = useState<DragItem | null>(null);
  const [newGroupName, setNewGroupName] = useState('');
  const [webhookUrl, setWebhookUrl] = useState('');
  const [enabled, setEnabled] = useState(true);
  const [minConfidence, setMinConfidence] = useState(70);

  useEffect(() => {
    setDraft(current => ({ ...current, hidden: prefs.hidden, tabLabels: prefs.tabLabels, groupLabels: prefs.groupLabels, layout: prefs.layout }));
  }, [prefs.hidden, prefs.tabLabels, prefs.groupLabels, prefs.layout]);

  useEffect(() => {
    setDraft(current => ({ ...current, tutorialDismissed: prefs.tutorialDismissed }));
  }, [prefs.tutorialDismissed]);

  useEffect(() => {
    let cancelled = false;
    api.userWebhook.get()
      .then(response => {
        if (cancelled) return;
        setWebhookUrl(response.webhook_url || '');
        setEnabled(response.enabled);
        setMinConfidence(response.min_confidence);
      })
      .catch(error => {
        if (!cancelled) setWebhookStatus({ type: 'error', text: error instanceof Error ? error.message : String(error) });
      })
      .finally(() => { if (!cancelled) setLoadingWebhook(false); });
    return () => { cancelled = true; };
  }, []);

  const urlValid = !webhookUrl.trim() || /^https:\/\//i.test(webhookUrl.trim());
  const alertState = !webhookUrl.trim() ? 'Not configured' : enabled ? 'Active' : 'Paused';
  const availableTabs = ALL_TABS.filter(tab => tab.id !== 'settings' && isTabVisible(tab, role, allowedTeams));
  const assigned = new Set(draft.layout.flatMap(group => group.tabs));
  const poolTabs = availableTabs.filter(tab => !assigned.has(tab.id));
  const tabById = new Map(availableTabs.map(tab => [tab.id, tab]));

  function beginDrag(event: DragEvent, item: DragItem) {
    setDragging(item);
    event.dataTransfer.effectAllowed = 'move';
    event.dataTransfer.setData('text/plain', `${item.type}:${item.id}`);
  }

  function allowDrop(event: DragEvent) {
    event.preventDefault();
    event.dataTransfer.dropEffect = 'move';
  }

  function moveTab(tabId: TabId, groupId: string, beforeId?: TabId) {
    setDraft(current => {
      const layout = current.layout.map(group => ({ ...group, tabs: group.tabs.filter(id => id !== tabId) }));
      const target = layout.find(group => group.id === groupId);
      if (!target) return current;
      const index = beforeId ? target.tabs.indexOf(beforeId) : -1;
      if (index >= 0) target.tabs.splice(index, 0, tabId);
      else target.tabs.push(tabId);
      return { ...current, hidden: current.hidden.filter(id => id !== tabId), layout };
    });
  }

  function moveTabToPool(tabId: TabId) {
    setDraft(current => ({
      ...current,
      hidden: [...new Set([...current.hidden, tabId])],
      layout: current.layout.map(group => ({ ...group, tabs: group.tabs.filter(id => id !== tabId) })),
    }));
  }

  function dropOnGroup(event: DragEvent, groupId: string) {
    allowDrop(event);
    if (dragging?.type === 'tab') moveTab(dragging.id, groupId);
    else if (dragging?.type === 'group' && dragging.id !== groupId) {
      setDraft(current => {
        const layout = [...current.layout];
        const from = layout.findIndex(group => group.id === dragging.id);
        const to = layout.findIndex(group => group.id === groupId);
        if (from < 0 || to < 0) return current;
        const [group] = layout.splice(from, 1);
        layout.splice(to, 0, group);
        return { ...current, layout };
      });
    }
    setDragging(null);
  }

  function dropBeforeTab(event: DragEvent, groupId: string, beforeId: TabId) {
    event.stopPropagation();
    allowDrop(event);
    if (dragging?.type === 'tab' && dragging.id !== beforeId) moveTab(dragging.id, groupId, beforeId);
    setDragging(null);
  }

  function dropOnPool(event: DragEvent) {
    allowDrop(event);
    if (dragging?.type === 'tab') moveTabToPool(dragging.id);
    setDragging(null);
  }

  function addGroup() {
    const label = newGroupName.trim().slice(0, 24);
    if (!label || draft.layout.length >= 12) return;
    const base = label.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'group';
    let id = `custom-${base}`.slice(0, 32);
    let suffix = 2;
    while (draft.layout.some(group => group.id === id)) id = `${`custom-${base}`.slice(0, 29)}-${suffix++}`;
    setDraft(current => ({ ...current, layout: [...current.layout, { id, label, tabs: [] }] }));
    setNewGroupName('');
  }

  function deleteGroup(group: NavGroup) {
    setDraft(current => ({
      ...current,
      hidden: [...new Set([...current.hidden, ...group.tabs])],
      layout: current.layout.filter(item => item.id !== group.id),
    }));
  }

  function renameGroup(id: string, label: string) {
    setDraft(current => ({ ...current, layout: current.layout.map(group => group.id === id ? { ...group, label: label.slice(0, 24) } : group) }));
  }

  function renameTab(id: TabId, label: string) {
    setDraft(current => ({ ...current, tabLabels: { ...current.tabLabels, [id]: label.slice(0, 24) } }));
  }

  function moveGroup(id: string, delta: number) {
    setDraft(current => {
      const layout = [...current.layout];
      const from = layout.findIndex(group => group.id === id);
      const to = from + delta;
      if (from < 0 || to < 0 || to >= layout.length) return current;
      const [group] = layout.splice(from, 1);
      layout.splice(to, 0, group);
      return { ...current, layout };
    });
  }

  function moveTabBy(id: TabId, groupId: string, delta: number) {
    setDraft(current => {
      const layout = current.layout.map(group => ({ ...group, tabs: [...group.tabs] }));
      const group = layout.find(item => item.id === groupId);
      if (!group) return current;
      const from = group.tabs.indexOf(id);
      const to = from + delta;
      if (from < 0 || to < 0 || to >= group.tabs.length) return current;
      group.tabs.splice(from, 1);
      group.tabs.splice(to, 0, id);
      return { ...current, layout };
    });
  }

  async function dismissNavTutorial() {
    setSavingNav(true);
    setNavStatus(null);
    try {
      await prefs.dismissTutorial();
      setDraft(current => ({ ...current, tutorialDismissed: true }));
    } catch (error) {
      setNavStatus({ type: 'error', text: error instanceof Error ? error.message : String(error) });
    } finally { setSavingNav(false); }
  }

  async function saveNavigation() {
    setSavingNav(true);
    setNavStatus(null);
    try {
      const clean: TabPrefsState = {
        hidden: availableTabs.map(tab => tab.id).filter(id => !draft.layout.some(group => group.tabs.includes(id))),
        tabLabels: Object.fromEntries(Object.entries(draft.tabLabels).map(([id, label]) => [id, label?.trim()]).filter(([, label]) => label)) as Partial<Record<TabId, string>>,
        groupLabels: {},
        layout: draft.layout.map(group => ({ ...group, label: group.label.trim() })).filter(group => group.label),
        tutorialDismissed: prefs.tutorialDismissed,
      };
      await prefs.save(clean);
      setNavStatus({ type: 'success', text: 'Navigation layout saved.' });
    } catch (error) {
      setNavStatus({ type: 'error', text: error instanceof Error ? error.message : String(error) });
    } finally { setSavingNav(false); }
  }

  async function resetNavigation() {
    setSavingNav(true);
    setNavStatus(null);
    try {
      await prefs.reset();
      setDraft({ hidden: [], tabLabels: {}, groupLabels: {}, layout: DEFAULT_NAV_LAYOUT, tutorialDismissed: prefs.tutorialDismissed });
      setNavStatus({ type: 'success', text: 'Navigation restored to defaults.' });
    } catch (error) {
      setNavStatus({ type: 'error', text: error instanceof Error ? error.message : String(error) });
    } finally { setSavingNav(false); }
  }

  function saveWebhook(event: FormEvent) {
    event.preventDefault();
    if (!urlValid) return setWebhookStatus({ type: 'error', text: 'Webhook URL must start with https://' });
    setSavingWebhook(true);
    setWebhookStatus(null);
    api.userWebhook.save(webhookUrl.trim(), enabled, minConfidence)
      .then(response => {
        setWebhookUrl(response.webhook_url || '');
        setEnabled(response.enabled);
        setMinConfidence(response.min_confidence);
        setWebhookStatus({ type: 'success', text: 'Webhook settings saved.' });
      })
      .catch(error => setWebhookStatus({ type: 'error', text: error instanceof Error ? error.message : String(error) }))
      .finally(() => setSavingWebhook(false));
  }

  return (
    <div className="tab-content formatter-tab settings-tab">
      <header className="settings-page-head">
        <div><span className="settings-page-head__eyebrow">Personal configuration</span><h2>Settings</h2></div>
        <p>Workspace scope, sidebar layout, and alert delivery.</p>
      </header>

      <div className="settings-layout">
        <nav className="settings-section-nav" aria-label="Settings sections">
          {SETTINGS_SECTIONS.map(section => (
            <button key={section.id} type="button" className={activeSection === section.id ? 'is-active' : ''} onClick={() => setActiveSection(section.id)} aria-current={activeSection === section.id ? 'page' : undefined}>
              <span>{section.label}</span><small>{section.note}</small>
            </button>
          ))}
        </nav>

        <main className="settings-content">
          {activeSection === 'workspace' && (
            <section className="settings-panel settings-workspace" aria-labelledby="workspace-settings-title">
              <div className="settings-panel__head"><div><h3 id="workspace-settings-title">Workspace</h3><p>{canChooseTeam ? 'Choose which operational team data Team Filter reads and writes.' : 'Current operational team scope.'}</p></div><span className="settings-state">{role}</span></div>
              {activeTeam ? (
                <div className="settings-row">
                  {canChooseTeam ? (
                    <>
                      <div><strong>Team context</strong><span>Applies immediately to Team Filter.</span></div>
                      <select className="settings-select" value={activeTeam} onChange={event => setActiveTeam(event.target.value as 'PAC' | 'CHARLIE')} aria-label="Active Team Filter context">
                        {allowedTeams.map(team => <option key={team} value={team}>{team}</option>)}
                      </select>
                    </>
                  ) : <div className="settings-team-context">Team context: {activeTeam}</div>}
                </div>
              ) : <div className="settings-empty">This role has no Team Filter workspace.</div>}
              <dl className="settings-meta"><div><dt>Role assignment</dt><dd>{assignedTeam || 'Cross-team access'}</dd></div><div><dt>Available contexts</dt><dd>{allowedTeams.join(', ') || 'None'}</dd></div></dl>
            </section>
          )}

          {activeSection === 'navigation' && (
      <section className="settings-panel nav-settings-card" aria-labelledby="navigation-settings-title">
        <div className="settings-panel__head">
          <div><h3 id="navigation-settings-title">Navigation</h3><p>Order groups and tabs. Items in Available stay hidden.</p></div>
          <span className="settings-state">{draft.layout.length} groups</span>
        </div>

        {!prefs.tutorialDismissed && (
          <details className="nav-guide">
            <summary>How navigation editing works</summary>
            <div><span>Drag to reorder.</span><span>Move to Available to hide.</span><span>Rename inline.</span><span>Save when done.</span></div>
            <button type="button" disabled={savingNav} onClick={dismissNavTutorial}>Do not show again</button>
          </details>
        )}

        <div className="nav-builder">
          <aside className={`nav-pool ${dragging?.type === 'tab' ? 'nav-drop-ready' : ''}`} onDragOver={allowDrop} onDrop={dropOnPool}>
            <div className="nav-builder__title">Available tabs <span>{poolTabs.length}</span></div>
            <div className="nav-builder__hint">Drop here to hide</div>
            <div className="nav-builder__items">
              {poolTabs.map(tab => (
                <div className="nav-builder-tab" draggable onDragStart={event => beginDrag(event, { type: 'tab', id: tab.id })} onDragEnd={() => setDragging(null)} key={tab.id}>
                  <span className="drag-handle" aria-hidden="true">⠿</span><span>{tab.icon}</span><span>{draft.tabLabels[tab.id] || tab.label}</span>
                  <button type="button" className="nav-move-btn" disabled={!draft.layout.length} onClick={() => draft.layout[0] && moveTab(tab.id, draft.layout[0].id)} aria-label={`Enable ${tab.label} in first group`}>Enable</button>
                </div>
              ))}
              {!poolTabs.length && <div className="nav-builder__empty">All allowed tabs enabled</div>}
            </div>
          </aside>

          <div className="nav-enabled">
            <div className="nav-builder__title">Enabled groups <span>{draft.layout.length}</span></div>
            {draft.layout.map((group, groupIndex) => (
              <section className={`nav-builder-group ${dragging ? 'nav-drop-ready' : ''}`} key={group.id} onDragOver={allowDrop} onDrop={event => dropOnGroup(event, group.id)}>
                <div className="nav-builder-group__head" draggable onDragStart={event => beginDrag(event, { type: 'group', id: group.id })} onDragEnd={() => setDragging(null)}>
                  <span className="drag-handle drag-handle--group" title="Drag group" aria-hidden="true">⠿</span>
                  <input className="nav-group-name" aria-label={`Rename ${group.label} group`} maxLength={24} value={group.label} onChange={event => renameGroup(group.id, event.target.value)} onPointerDown={event => event.stopPropagation()} />
                  <span className="nav-group-count">{group.tabs.length}</span>
                  <span className="nav-keyboard-actions">
                    <button type="button" className="nav-move-btn" disabled={groupIndex === 0} onClick={() => moveGroup(group.id, -1)} aria-label={`Move ${group.label} group up`}>↑</button>
                    <button type="button" className="nav-move-btn" disabled={groupIndex === draft.layout.length - 1} onClick={() => moveGroup(group.id, 1)} aria-label={`Move ${group.label} group down`}>↓</button>
                    <button type="button" className="nav-group-delete" title={`Delete ${group.label} group`} aria-label={`Delete ${group.label} group`} onClick={() => deleteGroup(group)}>×</button>
                  </span>
                </div>
                <div className="nav-builder__items nav-builder__items--group">
                  {group.tabs.map(id => {
                    const tab = tabById.get(id);
                    if (!tab) return null;
                    return (
                      <div className="nav-builder-tab" draggable onDragStart={event => beginDrag(event, { type: 'tab', id })} onDragEnd={() => setDragging(null)} onDragOver={allowDrop} onDrop={event => dropBeforeTab(event, group.id, id)} key={id}>
                        <span className="drag-handle" aria-hidden="true">⠿</span><span>{tab.icon}</span>
                        <input className="nav-tab-name" aria-label={`Rename ${tab.label} tab`} maxLength={24} value={draft.tabLabels[id] || ''} placeholder={tab.label} onChange={event => renameTab(id, event.target.value)} onPointerDown={event => event.stopPropagation()} />
                        <span className="nav-keyboard-actions">
                          <select className="nav-group-select" value={group.id} onChange={event => event.target.value === '__available__' ? moveTabToPool(id) : moveTab(id, event.target.value)} aria-label={`Move ${tab.label} to group`}>
                            {draft.layout.map(option => <option key={option.id} value={option.id}>{option.label}</option>)}
                            <option value="__available__">Available (hidden)</option>
                          </select>
                          <button type="button" className="nav-move-btn" disabled={group.tabs.indexOf(id) === 0} onClick={() => moveTabBy(id, group.id, -1)} aria-label={`Move ${tab.label} up`}>↑</button>
                          <button type="button" className="nav-move-btn" disabled={group.tabs.indexOf(id) === group.tabs.length - 1} onClick={() => moveTabBy(id, group.id, 1)} aria-label={`Move ${tab.label} down`}>↓</button>
                        </span>
                      </div>
                    );
                  })}
                  {!group.tabs.length && <div className="nav-builder__empty">Drop tabs here</div>}
                </div>
              </section>
            ))}
            <div className="nav-add-group">
              <input className="form-input" aria-label="New navigation group name" maxLength={24} value={newGroupName} placeholder="New group name" onChange={event => setNewGroupName(event.target.value)} onKeyDown={event => { if (event.key === 'Enter') { event.preventDefault(); addGroup(); } }} />
              <button type="button" className="btn btn-ghost" disabled={!newGroupName.trim() || draft.layout.length >= 12} onClick={addGroup}>Add group</button>
            </div>
          </div>
        </div>

        {navStatus && <StatusMessage type={navStatus.type} message={navStatus.text} onDismiss={() => setNavStatus(null)} />}
        <div className="settings-toolbar">
          <span>{assigned.size} tabs enabled</span>
          <div><button type="button" className="btn btn-ghost" disabled={savingNav} onClick={resetNavigation}>Reset</button><button type="button" className="btn btn-primary" disabled={savingNav} onClick={saveNavigation}>{savingNav ? 'Saving…' : 'Save navigation'}</button></div>
        </div>
      </section>
          )}

          {activeSection === 'alerts' && (
            <form onSubmit={saveWebhook} className="settings-panel settings-alerts" aria-labelledby="alert-settings-title">
              <div className="settings-panel__head"><div><h3 id="alert-settings-title">Malicious IOC alerts</h3><p>Send high-confidence scan outcomes to one HTTPS webhook.</p></div><span className={`settings-state ${alertState === 'Active' ? 'is-on' : ''}`}>{alertState}</span></div>
              {loadingWebhook ? <div className="settings-loading"><Spinner size={16} /> Loading alert configuration…</div> : (
                <>
                  <label className="settings-field"><span className="settings-field__label">Webhook URL</span><input type="url" className={`form-input ${!urlValid ? 'form-input--error' : ''}`} placeholder="https://hooks.example.com/…" value={webhookUrl} onChange={event => setWebhookUrl(event.target.value)} autoComplete="off" spellCheck={false} aria-invalid={!urlValid} aria-describedby="webhook-url-help" /><span id="webhook-url-help" className="settings-field__hint">HTTPS only. Clear URL to stop delivery and remove destination.</span></label>
                  <div className="settings-row settings-row--controls"><label className="settings-toggle"><input type="checkbox" checked={enabled} onChange={event => setEnabled(event.target.checked)} /><span className="settings-toggle__label">Enable delivery</span><span className="settings-field__hint">Pause without deleting URL.</span></label><label className="settings-threshold"><span>Minimum confidence</span><output>{minConfidence}%</output><input type="range" className="settings-range" min={0} max={100} step={5} value={minConfidence} onChange={event => setMinConfidence(Number(event.target.value))} /><span className="settings-range-bounds"><small>0</small><small>100</small></span></label></div>
                  {webhookStatus && <StatusMessage type={webhookStatus.type} message={webhookStatus.text} onDismiss={() => setWebhookStatus(null)} />}
                  <div className="settings-toolbar"><span>Triggers after completed IOC scans.</span><button type="submit" className="btn btn-primary" disabled={savingWebhook || !urlValid}>{savingWebhook ? 'Saving…' : 'Save alerts'}</button></div>
                </>
              )}
            </form>
          )}
        </main>
      </div>
    </div>
  );
}
