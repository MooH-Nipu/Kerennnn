/* ── TABS ── */
const LS_TAB = 'socToolboxActiveTab';
function openTab(id, btn) {
    document.querySelectorAll('.tab-content').forEach(t=>t.classList.remove('active'));
    document.querySelectorAll('.tab-btn').forEach(b=>b.classList.remove('active'));
    document.getElementById(id).classList.add('active');
    btn.classList.add('active');
    try { localStorage.setItem(LS_TAB, id); } catch (e) {}

    // A11y: keep ARIA tab state in sync with active panel.
    try {
        document.querySelectorAll('.tab-btn[role="tab"]').forEach(function (b) {
            b.setAttribute('aria-selected', b === btn ? 'true' : 'false');
        });
    } catch (e) {}

    if (id === 'tab-vt') {
        _vtState = _vtStateLookup;
        _vtActiveResultsId = 'vtResults';
        _vtActiveNoteId = 'vtSelectedNote';
        _vtStatusMsgId = 'statusVT';
    } else if (id === 'tab-history') {
        _vtState = _vtStateHistory;
        _vtActiveResultsId = 'historyScanResults';
        _vtActiveNoteId = 'historySelectedNote';
        _vtStatusMsgId = 'statusHistory';
    } else if (id === 'tab-merger-db') {
        if (!_mergerDbDidAutoRefresh) {
            _mergerDbDidAutoRefresh = true;
            mergerDbRefreshFromDb();
        }
    } else if (id === 'tab-dashboard') {
        try { dashboardRefreshRecent(); } catch (e) {}
    }
    if (id === 'tab-vt' || id === 'tab-history') vtSyncFilterUIs();
}

/* ── UTILS ── */
function setStatus(id, html, type) {
    const e = document.getElementById(id);
    e.innerHTML = html;
    e.className = 'status ' + type;
}
function clearStatus(id) { document.getElementById(id).className = 'status'; }
/** API error may be string or nested object — avoid "[object Object]" in UI */
function formatApiError(err) {
    if (err == null || err === '') return '';
    if (typeof err === 'string') return err;
    if (typeof err === 'number' || typeof err === 'boolean') return String(err);
    if (Array.isArray(err)) return err.map(formatApiError).filter(Boolean).join('; ');
    if (typeof err === 'object') {
        if (err.message) return String(err.message);
        if (err.error) return formatApiError(err.error);
        try { return JSON.stringify(err); } catch (e) { return String(err); }
    }
    return String(err);
}
async function readFetchJson(r) {
    const text = await r.text();
    if (!text) return { data: {}, text: '' };
    try {
        return { data: JSON.parse(text), text };
    } catch (e) {
        return { data: null, text, parseError: e };
    }
}
function escHtml(s) {
    return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}
function copyText(elId, btnId) {
    const text = document.getElementById(elId).textContent;
    const btn  = document.getElementById(btnId);
    navigator.clipboard.writeText(text).then(()=>{
        const orig = btn.textContent;
        btn.textContent = '✓ COPIED'; btn.classList.add('copied');
        setTimeout(()=>{ btn.textContent = orig; btn.classList.remove('copied'); }, 2000);
    }).catch(e=>alert('Copy failed: '+e));
}

/* ── AUTH (single password) ── */
let _authReady = false;
let _isAuthed = false;
let _loginOverlayDismissed = false;

function setAuthUi(authed) {
    const yccaBtn = document.getElementById('yccaBtn');
    const logoutBtn = document.getElementById('logoutBtn');
    if (yccaBtn) {
        yccaBtn.style.display = 'inline-flex';
        yccaBtn.title = authed ? 'Logged in (YCCA)' : 'Login YCCA';
    }
    if (logoutBtn) logoutBtn.style.display = authed ? 'inline-flex' : 'none';

    const pacBtn = document.getElementById('tabBtn-merger-db');
    if (pacBtn) pacBtn.style.display = authed ? '' : 'none';
}

function authShowLogin() {
    _loginOverlayDismissed = false;
    const ov = document.getElementById('loginOverlay');
    if (ov) {
        ov.style.display = 'flex';
        ov.setAttribute('aria-hidden', 'false');
    }
    try {
        const inp = document.getElementById('loginPassword');
        if (inp) inp.focus();
    } catch (e) {}
}

function setLockedUi(locked) {
    document.body.classList.toggle('app-locked', !!locked);
    const ov = document.getElementById('loginOverlay');
    if (ov) {
        ov.style.display = (locked && !_loginOverlayDismissed) ? 'flex' : 'none';
        ov.setAttribute('aria-hidden', locked ? 'false' : 'true');
    }
    if (!locked) _loginOverlayDismissed = false;
    setAuthUi(!locked);
}

function authDismissLogin() {
    _loginOverlayDismissed = true;
    const ov = document.getElementById('loginOverlay');
    if (ov) {
        ov.style.display = 'none';
        ov.setAttribute('aria-hidden', 'true');
    }
}

async function authCheck() {
    try {
        const r = await fetch('/api/auth/me', { headers: { 'Accept': 'application/json' } });
        if (!r.ok) return false;
        const j = await r.json().catch(() => null);
        // If auth is disabled server-side, allow access (and show PAC Filter).
        if (j && j.enabled === false) return true;
        return !!j?.ok;
    } catch {
        return false;
    }
}

async function authInit() {
    const ok = await authCheck();
    _authReady = true;
    _isAuthed = ok;
    // Do NOT force a login prompt on page load.
    setAuthUi(ok);
    try { if (ok) dashboardRefreshRecent(); } catch (e) {}
}

async function authLogin() {
    clearStatus('statusLogin');
    const btn = document.getElementById('loginBtn');
    const inp = document.getElementById('loginPassword');
    const pw = (inp && inp.value) ? String(inp.value) : '';
    if (!pw) { setStatus('statusLogin', '⚠ Password tidak boleh kosong.', 'error'); return; }
    if (btn) btn.disabled = true;
    setStatus('statusLogin', '<span class="spinner"></span> Login…', 'loading');
    try {
        const r = await fetch('/api/auth/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ password: pw })
        });
        const { data, text } = await readFetchJson(r);
        if (!r.ok) {
            const msg = formatApiError(data && data.error) || text || r.status;
            setStatus('statusLogin', '⚠ ' + escHtml(msg), 'error');
            return;
        }
        if (inp) inp.value = '';
        setStatus('statusLogin', '✓ Login berhasil.', 'success');
        await authInit();
    } catch (e) {
        setStatus('statusLogin', '⚠ ' + escHtml(e.message || String(e)), 'error');
    } finally {
        if (btn) btn.disabled = false;
    }
}

async function authLogout() {
    try { await fetch('/api/auth/logout', { method: 'POST' }); } catch (e) {}
    _isAuthed = false;
    // Logging out should not block public features; just hide YCCA-only UI.
    setAuthUi(false);
}

async function ipCachePostCorrelation(corr) {
    try {
        if (!corr || typeof corr !== 'object') return;
        if (corr.type !== 'ip') return;
        const ip = corr.ioc;
        if (!ip) return;
        const r = await fetch('/api/ip-cache/correlation', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
            body: JSON.stringify({ ioc: ip, correlation: corr })
        });
        if (r.status === 401) {
            if (_authReady) setLockedUi(true);
        }
    } catch (e) {
        // ignore caching errors
    }
}

/* ── DASHBOARD (Recent IP cache) ── */
function dashboardOpenSearchConsole() {
    const tabBtn = document.querySelector('.tab-btn[data-tab="tab-vt"]');
    if (tabBtn) openTab('tab-vt', tabBtn);
}

function dashboardScrollToInvestigations() {
    scrollToDashboardSection('dash-recent-feed');
}

function scrollToDashboardSection(sectionId) {
    const dashTabBtn = document.getElementById('tabBtn-dashboard');
    const dashPanel = document.getElementById('tab-dashboard');
    if (!dashTabBtn || !dashPanel) return;
    const wasActive = dashPanel.classList.contains('active');
    if (!wasActive && dashTabBtn) openTab('tab-dashboard', dashTabBtn);
    const scrollIt = () => {
        const el = document.getElementById(sectionId);
        if (!el) return;
        try {
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } catch (e) {
            el.scrollIntoView(true);
        }
    };
    if (wasActive) scrollIt();
    else setTimeout(scrollIt, 50);
}

/** Dashboard nav links (#dash-*) switch to Dashboard tab before scrolling */
function dashboardInTabAnchor(ev, el) {
    if (ev) ev.preventDefault();
    const raw = el && el.getAttribute ? String(el.getAttribute('href') || '') : '';
    const id = raw.charAt(0) === '#' ? raw.slice(1) : '';
    if (id) scrollToDashboardSection(id);
    return false;
}

/** Update Live Watch risk bar from recent cache items */
function dashboardUpdateRiskMix(items) {
    const countEl = document.getElementById('dashRiskMixCount');
    const els = document.querySelectorAll('.dash-risk-bar .dash-risk-seg');
    if (!els.length) return;

    var nc = 0;
    var ns = 0;
    var nm = 0;
    var nu = 0;
    (items || []).forEach(function (it) {
        var v = String(it && it.vt_verdict ? it.vt_verdict : 'unknown').toLowerCase();
        if (v === 'clean') nc++;
        else if (v === 'malicious') nm++;
        else if (v === 'suspicious') ns++;
        else nu++;
    });
    var n = (items && items.length) || 0;
    if (countEl) countEl.textContent = n === 1 ? '1 item' : String(n) + ' items';

    var uThird = nu / 3;
    var g0 = nc + uThird;
    var g1 = ns + uThird;
    var g2 = nm + uThird;
    var totalG = g0 + g1 + g2;

    els.forEach(function (seg, idx) {
        var g = idx === 0 ? g0 : idx === 1 ? g1 : g2;
        if (!totalG || n === 0) {
            seg.style.flex = '1 1 0';
            seg.style.opacity = '0.35';
        } else {
            seg.style.flex = String(Math.max(g, 0)) + ' 1 0';
            seg.style.opacity = '1';
        }
    });
}

function fmtWhen(iso) {
    if (!iso) return '—';
    const d = new Date(iso);
    if (isNaN(d.getTime())) return String(iso);
    return d.toLocaleString();
}

function dashboardRowHtml(item) {
    const stableId = item?.id || '';
    const ip = item?.ip || '';
    const verdict = (item?.vt_verdict || 'unknown').toLowerCase();
    const when = fmtWhen(item?.last_scanned_at);
    const sc = Number(item?.scan_count || 0);
    const corr = item?.corr_confidence;
    const stats = item?.vt_stats || {};
    const mal = stats?.malicious ?? '';
    const sus = stats?.suspicious ?? '';
    const total = stats?.total ?? '';
    const det = (mal !== '' && total !== '') ? `${mal}/${total}` : '—';
    const idJs = JSON.stringify(ip);
    const sidJs = JSON.stringify(stableId);
    return `<div class="dash-row">
        <div class="dash-left">
            <div class="dash-ip">
                ${escHtml(ip)}
                <span class="dash-pill ${escHtml(verdict)}">${escHtml(verdict.toUpperCase())}</span>
            </div>
            <div class="dash-meta">
                <span class="dash-pill">scan: ${escHtml(sc)}</span>
                <span class="dash-pill">det: ${escHtml(det)}</span>
                <span class="dash-pill">ti: ${escHtml(corr === null || corr === undefined ? '—' : String(corr) + '%')}</span>
                <span class="dash-when">${escHtml(when)}</span>
            </div>
        </div>
        <button type="button" class="dash-go" title="${stableId ? 'Open cached result' : 'Open in IoC Scan'}" onclick='dashboardRowOpen(${sidJs}, ${idJs})'>›</button>
    </div>`;
}

function dashboardGoToLookup(ip) {
    if (!ip) return;
    const ta = document.getElementById('vtInput');
    if (ta) ta.value = String(ip);
    const tabBtn = document.querySelector('.tab-btn[data-tab="tab-vt"]');
    if (tabBtn) openTab('tab-vt', tabBtn);
    setStatus('statusVT', '✓ IP dari Dashboard ditempelkan — klik <strong>Run IoC Scan</strong> untuk scan.', 'success');
}

/** Recent row: open cached result page when we have a stable id; otherwise paste IP into IoC Scan. */
function dashboardRowOpen(stableId, ip) {
    if (stableId) {
        dashboardOpenResult(stableId);
        return;
    }
    dashboardGoToLookup(ip);
}

/** Pretty URL for cached IOC result page (same path as Dashboard “open result”). */
function vtCachedResultHref(stableId) {
    if (!stableId) return '#';
    const sid = String(stableId);
    return `/result/${encodeURIComponent(sid)}?id=${encodeURIComponent(sid)}`;
}

function dashboardOpenResult(stableId) {
    if (!stableId) return;
    const sid = String(stableId);
    const pretty = vtCachedResultHref(stableId);
    const fallback = `/result.html?id=${encodeURIComponent(sid)}`;
    try {
        window.open(pretty, '_blank', 'noopener');
    } catch (e) {
        try { window.open(fallback, '_blank', 'noopener'); } catch {}
    }
}

async function dashboardRefreshRecent() {
    clearStatus('statusDashboard');
    setStatus('statusDashboard', '<span class="spinner"></span> Memuat recent IP…', 'loading');
    const host = document.getElementById('dashboardRecentList');
    if (host) host.innerHTML = '<div class="dash-empty">Loading…</div>';
    try {
        const r = await fetch('/api/ip-cache/recent?limit=15', { headers: { 'Accept': 'application/json' } });
        const { data, text } = await readFetchJson(r);
        if (!r.ok) {
            if (r.status === 401) {
                if (_authReady) setLockedUi(true);
            }
            const msg = formatApiError(data && data.error) || text || r.status;
            setStatus('statusDashboard', '⚠ ' + escHtml(msg), 'error');
            if (host) host.innerHTML = '<div class="dash-empty">Tidak bisa memuat data.</div>';
            dashboardUpdateRiskMix([]);
            return;
        }
        const items = (data && data.items) || [];
        if (!items.length) {
            if (host) host.innerHTML = '<div class="dash-empty">Belum ada IP yang tercache (atau semua sudah expired).</div>';
        } else {
            if (host) host.innerHTML = items.map(dashboardRowHtml).join('');
        }
        dashboardUpdateRiskMix(items);
        setStatus('statusDashboard', `✓ Loaded ${items.length} IP.`, 'success');
    } catch (e) {
        setStatus('statusDashboard', '⚠ ' + escHtml(e.message || String(e)), 'error');
        if (host) host.innerHTML = '<div class="dash-empty">Tidak bisa memuat data.</div>';
        dashboardUpdateRiskMix([]);
    }
}

/* ── TAB 1: IP FORMATTER ── */
function processFormatter() {
    const raw = document.getElementById('rawIps').value;
    clearStatus('statusFormatter');
    document.getElementById('copyBtnList').style.display = 'none';
    const ips = raw.split('\n').map(s=>s.trim()).filter(Boolean);
    const unique = [...new Set(ips)];
    if (!unique.length) { setStatus('statusFormatter','⚠ List IP tidak boleh kosong!','error'); return; }
    document.getElementById('outputList').textContent = unique.join('; ');
    document.getElementById('copyBtnList').style.display = 'block';
    setStatus('statusFormatter',`✓ ${unique.length} IP formatted — ${ips.length-unique.length} duplicate(s) removed.`,'success');
}

/* ── TAB 2: JSON MERGER ── */
function processMerger() {
    const oldText = document.getElementById('oldQuery').value.trim();
    const newText = document.getElementById('newIpsMerger').value.trim();
    clearStatus('statusMerger');
    document.getElementById('copyBtnJson').style.display = 'none';
    if (!oldText) { setStatus('statusMerger','⚠ Query lama tidak boleh kosong!','error'); return; }
    const newIps = [...new Set(newText.split('\n').map(s=>s.trim()).filter(Boolean))];
    if (!newIps.length) { setStatus('statusMerger','⚠ List IP baru tidak boleh kosong!','error'); return; }
    let obj;
    try { obj = JSON.parse(oldText); } catch(e) { setStatus('statusMerger','⚠ JSON tidak valid: '+e.message,'error'); return; }
    const terms = obj?.query?.terms;
    if (!terms) { setStatus('statusMerger','⚠ Struktur harus: query > terms','error'); return; }
    const arrayKeys = Object.keys(terms).filter(k => Array.isArray(terms[k]));
    if (!arrayKeys.length) { setStatus('statusMerger','⚠ Struktur harus: query > terms > <key> (array)','error'); return; }

    function looksLikeIp(s) {
        s = String(s ?? '').trim();
        if (!s) return false;
        // IPv4
        if (/^\d{1,3}(\.\d{1,3}){3}$/.test(s)) return true;
        // IPv6 (simple heuristic: hex + ":" char)
        if (s.includes(':') && /^[0-9a-fA-F:]+$/.test(s)) return true;
        return false;
    }
    function ipScore(key) {
        const arr = terms[key];
        let score = 0;
        for (const item of arr.slice(0, 50)) {
            if (looksLikeIp(item)) score++;
        }
        return score;
    }

    // Prefer keys yang dulu pernah didukung, tapi tetap dinamis untuk key lain.
    const preferredKeys = ['data.real_ip', 'source.ip'];
    const preferredKey = preferredKeys.find(k => arrayKeys.includes(k));
    const sortedByIpLikeness = arrayKeys.slice().sort((a, b) => {
        const sc = ipScore(b) - ipScore(a);
        if (sc !== 0) return sc;
        const la = Array.isArray(terms[a]) ? terms[a].length : 0;
        const lb = Array.isArray(terms[b]) ? terms[b].length : 0;
        if (lb !== la) return lb - la;
        return String(a).localeCompare(String(b));
    });
    const ipKey = (preferredKey && arrayKeys.includes(preferredKey))
        ? preferredKey
        : sortedByIpLikeness[0];

    const existing = terms[ipKey];
    const combined = [...new Set([...existing,...newIps])];
    terms[ipKey] = combined;
    document.getElementById('outputJson').textContent = JSON.stringify(obj, null, 2);
    document.getElementById('copyBtnJson').style.display = 'block';
    const added = combined.length - existing.length;
    const note = arrayKeys.length > 1 ? ` (detected ${arrayKeys.length} array keys, using ${ipKey})` : '';
    setStatus('statusMerger',`✓ ${added} IP added. Total: ${combined.length} (${ipKey})${note}`,'success');
}

/* ── TAB 3: VIRUSTOTAL ── */

// Client-side: just used to filter blank lines & show label
// Real detection + URL stripping happens server-side
function looksLikeIOC(s) {
    if (!s || s.length < 4) return false;
    // Pass anything that could be an IP, hash, domain, or URL
    return /[a-zA-Z0-9]/.test(s);
}

function hashLabel(len) {
    return { 32:'MD5/NTLM', 40:'SHA-1', 56:'SHA-224', 64:'SHA-256', 96:'SHA-384', 128:'SHA-512' }[len] || `HASH`;
}

async function vtGet(ioc) {
    let r, data;
    try {
        r = await fetch(`/api/vt?ioc=${encodeURIComponent(ioc)}`, {
            headers: { 'Accept': 'application/json' }
        });
        data = await r.json();
    } catch(e) {
        const err = new Error('Network error: ' + e.message); err.status = 0; throw err;
    }
    if (!r.ok) {
        const msg = data?.error?.message || data?.error || r.statusText;
        const err = new Error(`[${r.status}] ${msg}`);
        err.status = r.status;
        err.detail = msg;
        throw err;
    }
    return data;
}

function verdict(mal, sus, total) {
    if (!total) return { label:'UNKNOWN',    cls:'verdict-unknown' };
    if (mal > 3)             return { label:'MALICIOUS',  cls:'verdict-malicious' };
    if (mal > 0 || sus > 3) return { label:'SUSPICIOUS', cls:'verdict-suspicious' };
    return { label:'CLEAN', cls:'verdict-clean' };
}

function fillCls(ratio) {
    if (!ratio)      return 'fill-clean';
    if (ratio < 0.1) return 'fill-low';
    if (ratio < 0.3) return 'fill-high';
    return 'fill-critical';
}

function mi(k, v, c='') {
    return `<div class="meta-item"><div class="mk">${escHtml(k)}</div><div class="mv ${c}">${escHtml(String(v??'—'))}</div></div>`;
}

function detBar(mal, sus, total) {
    const n = mal + sus;
    const pct = total ? Math.round(n/total*100) : 0;
    const fc  = fillCls(total ? n/total : 0);
    const dc  = mal > 0 ? 'red' : sus > 0 ? 'yellow' : 'green';
    return `<div class="det-bar-wrap">
        <div class="det-bar-label">
            <span class="dl">Detection ratio</span>
            <span class="mv ${dc}" style="font-size:0.74rem">${n}/${total} &nbsp;(${pct}%)</span>
        </div>
        <div class="det-bar-bg"><div class="det-bar-fill ${fc}" style="width:${Math.min(pct,100)}%"></div></div>
    </div>`;
}

function countryFlag(code) {
    if (!code || code.length !== 2) return '';
    return String.fromCodePoint(...[...code.toUpperCase()].map(c => 0x1F1E6 - 65 + c.charCodeAt(0)));
}

function toggleCard(el) {
    const card = el.closest('.vt-card');
    const body = card.querySelector('.vt-card-body');
    const chev = card.querySelector('.vt-chevron');
    const collapsed = body.classList.toggle('collapsed');
    chev.classList.toggle('open', !collapsed);
}

function openCachedResult(stableId) {
    if (!stableId) return;
    dashboardOpenResult(stableId);
}

let _cardIdx = 0;
function makeVtState() {
    return { items: [], filters: { clean: true, suspicious: true, malicious: true } };
}
let _vtStateLookup = makeVtState();
let _vtStateHistory = makeVtState();
let _vtState = _vtStateLookup;

/** Target DOM untuk kartu hasil: Lookup (#vtResults) atau Riwayat (#historyScanResults) */
let _vtActiveResultsId = 'vtResults';
let _vtActiveNoteId = 'vtSelectedNote';
let _vtStatusMsgId = 'statusVT';
/** IOC text dari entri riwayat yang sedang ditampilkan (untuk "Scan ulang di Lookup") */
let _historyViewingVtInput = '';

function vtNotify(msg, type) {
    const id = _vtStatusMsgId || 'statusVT';
    const el = document.getElementById(id);
    if (!el) return;
    el.innerHTML = msg;
    el.className = 'status ' + type;
}

const VT_FILTER_IDS = {
    lookup:  { clean: 'vtF_clean', suspicious: 'vtF_suspicious', malicious: 'vtF_malicious' },
    history: { clean: 'hVtF_clean', suspicious: 'hVtF_suspicious', malicious: 'hVtF_malicious' }
};
function vtSyncFilterUIs() {
    function apply(state, idMap) {
        ['clean', 'suspicious', 'malicious'].forEach(k => {
            const cb = document.getElementById(idMap[k]);
            const chip = cb?.closest('.vt-chip');
            const on = !!state.filters[k];
            if (cb) cb.checked = on;
            chip?.classList.toggle('on', on);
        });
    }
    apply(_vtStateLookup, VT_FILTER_IDS.lookup);
    apply(_vtStateHistory, VT_FILTER_IDS.history);
}

/* ── LOCAL HISTORY + EXPORT PRESETS ── */
const LS_HISTORY = 'socToolboxScanHistory';
const LS_HISTORY_SAVE = 'socToolboxSaveHistory';
const LS_EXPORT_PRESET = 'socToolboxExportPreset';
const LS_EXPORT_CUSTOM = 'socToolboxExportCustomCols';
const HISTORY_MAX = 20;

const VT_EXPORT_ALL_KEYS = ['ioc','type','vt_verdict','detections','abuseipdb_percent','otx_pulses','abusech_url_count','abusech_online_urls','country','as_owner','confidence','sources'];
const VT_EXPORT_LABELS = {
    ioc: 'IOC', type: 'Type', vt_verdict: 'VT Verdict', detections: 'Detections',
    abuseipdb_percent: 'AbuseIPDB', otx_pulses: 'OTX Pulses', abusech_url_count: 'Abuse.ch URLs',
    abusech_online_urls: 'Online URLs', country: 'Country', as_owner: 'AS Owner',
    confidence: 'Confidence', sources: 'Threat Intel Sources'
};
const VT_EXPORT_PRESETS = {
    full: VT_EXPORT_ALL_KEYS.slice(),
    minimal: ['ioc','vt_verdict','confidence'],
    siem: ['ioc','type','vt_verdict','detections','confidence','sources']
};

let _mergerDbLastItems = [];
let _mergerDbDidAutoRefresh = false;
const MERGER_DB_POST_CHUNK = 40;

/** Samakan dengan api/_ioc.js — normalisasi sebelum cek duplikat / DB. */
function mergerDbExtractIoc(raw) {
    let s = String(raw ?? '').trim();
    s = s.replace(/^\[|\]$/g, '');
    s = s.replace(/^hxxps?/i, 'https');
    s = s.replace(/\[\.\]/g, '.').replace(/\(dot\)/gi, '.');
    if (/^https?:\/\//i.test(s)) {
        try {
            const u = new URL(s);
            s = u.hostname;
        } catch (e) {
            s = s.replace(/^https?:\/\//i, '').split('/')[0];
        }
    }
    s = s.split('/')[0].split('?')[0].split('#')[0];
    s = s.replace(/:(\d+)$/, '');
    s = s.replace(/\.$/, '');
    return s.toLowerCase();
}
function mergerDbDetectType(s) {
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(s)) return 'ip';
    if (/^[0-9a-f:]{3,39}$/.test(s) && s.includes(':') && s.split(':').length >= 3) return 'ip';
    if (/^[0-9a-f]+$/.test(s) && [32, 40, 56, 64, 96, 128].includes(s.length)) return 'hash';
    if (/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/.test(s)) return 'domain';
    return null;
}
function mergerDbNormalizeIpLine(raw) {
    const ioc = mergerDbExtractIoc(raw);
    if (mergerDbDetectType(ioc) !== 'ip') return null;
    return ioc;
}

/** Hitung baris vs IP unik vs perkiraan simpan / sudah ada (memakai data terakhir Refresh). */
function mergerDbGetInputClassification() {
    const ta = document.getElementById('mergerDbItemsInput');
    const raw = ta && ta.value ? ta.value : '';
    const lines = raw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    const dbSet = new Set();
    (_mergerDbLastItems || []).forEach(function (r) {
        if (r && r.ip) dbSet.add(String(r.ip));
    });
    let invalidLines = 0;
    const uniqueNorm = [];
    const seen = new Set();
    for (let i = 0; i < lines.length; i++) {
        const norm = mergerDbNormalizeIpLine(lines[i]);
        if (!norm) {
            invalidLines++;
            continue;
        }
        if (!seen.has(norm)) {
            seen.add(norm);
            uniqueNorm.push(norm);
        }
    }
    let wouldSave = 0;
    let alreadyInDb = 0;
    for (let j = 0; j < uniqueNorm.length; j++) {
        if (dbSet.has(uniqueNorm[j])) alreadyInDb++;
        else wouldSave++;
    }
    const validLineCount = lines.length - invalidLines;
    const dupAmongValid = validLineCount - uniqueNorm.length;
    return {
        lineCount: lines.length,
        invalidLines: invalidLines,
        uniqueValid: uniqueNorm.length,
        validLineCount: validLineCount,
        dupAmongValid: dupAmongValid,
        wouldSave: wouldSave,
        alreadyInDb: alreadyInDb,
        dbCachedCount: dbSet.size
    };
}

function mergerDbUpdateInputPreview() {
    const el = document.getElementById('mergerDbInputPreview');
    if (!el) return;
    const c = mergerDbGetInputClassification();
    if (!c.lineCount) {
        el.textContent = 'Pratinjau: belum ada isian.';
        return;
    }
    let s = 'Pratinjau: ' + c.lineCount + ' baris isi';
    if (c.invalidLines) s += ', ' + c.invalidLines + ' ditolak (bukan IP)';
    s += ' → ' + c.uniqueValid + ' IP unik valid';
    if (c.dupAmongValid) s += ' (' + c.dupAmongValid + ' baris berulang ke IP yang sama)';
    s += ' — ' + c.wouldSave + ' akan disimpan, ' + c.alreadyInDb + ' sudah ada di DB.';
    s += ' Perkiraan memakai ' + c.dbCachedCount + ' IP dari muatan terakhir; Refresh bila database berubah di luar halaman ini.';
    el.textContent = s;
}

function mergerDbSetSaveProgress(pct, text) {
    const wrap = document.getElementById('mergerDbSaveProgressWrap');
    const fill = document.getElementById('mergerDbSaveProgressFill');
    const lab = document.getElementById('mergerDbSaveProgressLabel');
    const n = Math.max(0, Math.min(100, Math.round(Number(pct) || 0)));
    if (fill) fill.style.width = n + '%';
    if (lab) lab.textContent = text != null ? String(text) : n + '%';
    if (wrap) wrap.style.display = 'block';
}

function mergerDbHideSaveProgress() {
    const wrap = document.getElementById('mergerDbSaveProgressWrap');
    const fill = document.getElementById('mergerDbSaveProgressFill');
    if (wrap) wrap.style.display = 'none';
    if (fill) fill.style.width = '0%';
}

function mergerDbAuthHeaders() {
    return { 'Content-Type': 'application/json', 'Accept': 'application/json' };
}

function mergerDbSyncTermsCustomVisibility() {
    const sel = document.getElementById('mergerDbTermsPreset');
    const wrap = document.getElementById('mergerDbTermsCustomWrap');
    const custom = sel && sel.value === 'custom';
    if (wrap) wrap.style.display = custom ? 'block' : 'none';
}

function mergerDbGetTermsFieldKey() {
    const sel = document.getElementById('mergerDbTermsPreset');
    const v = sel && sel.value ? String(sel.value) : 'data.real_ip';
    if (v === 'custom') {
        const inp = document.getElementById('mergerDbTermsField');
        const fk = ((inp && inp.value) || '').trim();
        return fk || 'data.real_ip';
    }
    return v;
}

function mergerDbRebuildOutputs(items) {
    _mergerDbLastItems = Array.isArray(items) ? items.slice() : [];
    const sortedRows = _mergerDbLastItems.slice().sort((a, b) => String(a.ip || '').localeCompare(String(b.ip || '')));
    const ips = sortedRows.map(x => x && x.ip).filter(Boolean);

    const fk = mergerDbGetTermsFieldKey();
    const out = { query: { terms: { [fk]: ips.slice() } } };

    const pre = document.getElementById('outputJsonDb');
    const copyBtn = document.getElementById('copyBtnJsonDb');
    if (pre) {
        pre.textContent = JSON.stringify(out, null, 2);
        if (copyBtn) copyBtn.style.display = 'block';
    }
    mergerDbUpdateInputPreview();
}

async function mergerDbRefreshFromDb() {
    clearStatus('statusMergerDb');
    setStatus('statusMergerDb', '<span class="spinner"></span> Memuat dari DB…', 'loading');
    try {
        const r = await fetch('/api/scan-merger', { method: 'GET', headers: mergerDbAuthHeaders() });
        const { data, text } = await readFetchJson(r);
        if (!r.ok) {
            setStatus('statusMergerDb', '⚠ ' + escHtml(formatApiError(data && data.error) || text || r.status), 'error');
            return;
        }
        if (!data || typeof data !== 'object') {
            setStatus('statusMergerDb', '⚠ Respons tidak valid.', 'error');
            return;
        }
        const items = data.items || [];
        mergerDbRebuildOutputs(items);
        setStatus('statusMergerDb', `✓ ${items.length} baris dari database.`, 'success');
    } catch (e) {
        setStatus('statusMergerDb', '⚠ ' + escHtml(e.message || String(e)), 'error');
    }
}

function mergerDbCollectNormUniqueIps(raw) {
    const lines = raw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    const seen = new Set();
    const out = [];
    for (let i = 0; i < lines.length; i++) {
        const norm = mergerDbNormalizeIpLine(lines[i]);
        if (!norm || seen.has(norm)) continue;
        seen.add(norm);
        out.push(norm);
    }
    return out;
}

async function mergerDbPostItems() {
    clearStatus('statusMergerDb');
    const ta = document.getElementById('mergerDbItemsInput');
    const raw = ta && ta.value ? ta.value : '';
    const normUnique = mergerDbCollectNormUniqueIps(raw);
    if (!normUnique.length) {
        setStatus('statusMergerDb', '⚠ Isi minimal satu IP valid (satu per baris).', 'error');
        return;
    }
    mergerDbUpdateInputPreview();
    const preSnap = mergerDbGetInputClassification();
    const dbSet = new Set();
    (_mergerDbLastItems || []).forEach(function (r) {
        if (r && r.ip) dbSet.add(String(r.ip));
    });
    const toPost = normUnique.filter(function (ip) { return !dbSet.has(ip); });
    const clientSkipped = normUnique.length - toPost.length;
    const postBtn = document.getElementById('mergerDbPostBtn');
    const refBtn = document.getElementById('mergerDbRefreshBtn');
    if (postBtn) postBtn.disabled = true;
    if (refBtn) refBtn.disabled = true;
    const totalSend = toPost.length;
    mergerDbSetSaveProgress(0, totalSend ? '0% · 0 / ' + totalSend + ' IP dikirim' : '—');
    setStatus(
        'statusMergerDb',
        '<span class="spinner"></span> Menyimpan ke DB… (pratinjau: ~' +
            preSnap.wouldSave +
            ' baru, ~' +
            preSnap.alreadyInDb +
            ' sudah ada' +
            (clientSkipped ? '; ' + clientSkipped + ' tidak dikirim karena sudah di snapshot' : '') +
            ')',
        'loading'
    );
    let totalSaved = 0;
    let totalSkipped = 0;
    let totalErr = 0;
    try {
        if (!totalSend) {
            mergerDbSetSaveProgress(100, 'Selesai · 0 dikirim');
            let msg =
                '✓ Tidak ada IP baru yang dikirim — ' +
                clientSkipped +
                ' sudah ada di snapshot (sama dengan muatan terakhir Refresh).';
            msg += ' Refresh bila database berubah di luar halaman ini.';
            setStatus('statusMergerDb', escHtml(msg), 'success');
            await mergerDbRefreshFromDb();
            return;
        }
        for (let i = 0; i < totalSend; i += MERGER_DB_POST_CHUNK) {
            const chunk = toPost.slice(i, i + MERGER_DB_POST_CHUNK);
            const items = chunk.map(function (ip) { return { ioc: ip }; });
            const doneBefore = i;
            const r = await fetch('/api/scan-merger', {
                method: 'POST',
                headers: mergerDbAuthHeaders(),
                body: JSON.stringify({ items }),
            });
            const { data } = await readFetchJson(r);
            if (!r.ok) {
                mergerDbSetSaveProgress(
                    Math.round((doneBefore / totalSend) * 100),
                    'Gagal di batch ' + (Math.floor(i / MERGER_DB_POST_CHUNK) + 1)
                );
                setStatus('statusMergerDb', '⚠ ' + escHtml(formatApiError(data && data.error) || r.status), 'error');
                return;
            }
            totalSaved += (data && data.savedCount) || 0;
            totalSkipped += (data && data.skippedCount) || 0;
            totalErr += (data && data.errorCount) || 0;
            const done = Math.min(i + chunk.length, totalSend);
            const pct = Math.round((done / totalSend) * 100);
            mergerDbSetSaveProgress(pct, pct + '% · ' + done + ' / ' + totalSend + ' IP dikirim');
        }
        let msg = `✓ Selesai: ${totalSaved} IP baru disimpan.`;
        if (clientSkipped) msg += ` ${clientSkipped} tidak dikirim (sudah di snapshot).`;
        if (totalSkipped) msg += ` ${totalSkipped} dilewati di server (sudah ada di DB).`;
        if (totalErr) msg += ` ${totalErr} error.`;
        if (!totalSaved && !totalErr && totalSkipped && !clientSkipped) {
            msg = `✓ Semua ${totalSkipped} IP sudah ada di database — tidak ada yang ditambahkan.`;
        }
        setStatus('statusMergerDb', escHtml(msg), totalErr ? 'error' : 'success');
        mergerDbSetSaveProgress(100, '100% · ' + totalSend + ' / ' + totalSend + ' IP dikirim');
        await mergerDbRefreshFromDb();
    } catch (e) {
        setStatus('statusMergerDb', '⚠ ' + escHtml(e.message || String(e)), 'error');
    } finally {
        if (postBtn) postBtn.disabled = false;
        if (refBtn) refBtn.disabled = false;
        setTimeout(mergerDbHideSaveProgress, 1800);
    }
}

async function mergerDbDeleteBatch() {
    clearStatus('statusMergerDb');
    const ta = document.getElementById('mergerDbDeleteIps');
    const raw = ta && ta.value ? ta.value : '';
    const lines = raw.split('\n').map(function (s) { return s.trim(); }).filter(Boolean);
    const unique = [];
    const seen = new Set();
    for (let i = 0; i < lines.length; i++) {
        const n = mergerDbNormalizeIpLine(lines[i]);
        if (n && !seen.has(n)) {
            seen.add(n);
            unique.push(n);
        }
    }
    if (!unique.length) {
        setStatus('statusMergerDb', '⚠ Isi minimal satu IP valid (satu per baris).', 'error');
        return;
    }
    setStatus(
        'statusMergerDb',
        '<span class="spinner"></span> Menghapus ' + unique.length + ' IP…',
        'loading'
    );
    try {
        const r = await fetch('/api/scan-merger', {
            method: 'DELETE',
            headers: mergerDbAuthHeaders(),
            body: JSON.stringify({ ips: unique }),
        });
        const { data } = await readFetchJson(r);
        if (!r.ok) {
            setStatus('statusMergerDb', '⚠ ' + escHtml(formatApiError(data && data.error) || r.status), 'error');
            return;
        }
        const del = data && typeof data.deletedCount === 'number' ? data.deletedCount : 0;
        const reqCount = data && typeof data.requested === 'number' ? data.requested : unique.length;
        if (ta) ta.value = '';
        setStatus(
            'statusMergerDb',
            '✓ Baris terhapus dari DB: ' + del + ' (diminta: ' + reqCount + ' IP unik valid).',
            'success'
        );
        await mergerDbRefreshFromDb();
    } catch (e) {
        setStatus('statusMergerDb', '⚠ ' + escHtml(e.message || String(e)), 'error');
    }
}

function errToObj(e) {
    if (!e) return { message: 'Unknown error' };
    return {
        message: e.message || String(e),
        status: e.status,
        detail: e.detail
    };
}
function objToErr(o) {
    const e = new Error(o?.message || 'Error');
    if (o && o.status !== undefined) e.status = o.status;
    if (o && o.detail !== undefined) e.detail = o.detail;
    return e;
}

function historySaveEnabled() {
    const el = document.getElementById('historySaveToggle');
    if (!el) return true;
    return !!el.checked;
}
function historyPersistSavePref() {
    try { localStorage.setItem(LS_HISTORY_SAVE, historySaveEnabled() ? '1' : '0'); } catch (e) {}
}

function loadHistoryEntries() {
    try {
        const raw = localStorage.getItem(LS_HISTORY);
        const a = raw ? JSON.parse(raw) : [];
        return Array.isArray(a) ? a : [];
    } catch (e) { return []; }
}
function saveHistoryEntries(arr) {
    try {
        localStorage.setItem(LS_HISTORY, JSON.stringify(arr));
        return true;
    } catch (e) {
        return false;
    }
}

function pushHistoryFromLineResults(vtInput, lineResults) {
    const entry = {
        id: 'h-' + Date.now() + '-' + Math.random().toString(36).slice(2, 9),
        ts: new Date().toISOString(),
        vtInput,
        results: lineResults.map(r => ({
            rawIoc: r.rawIoc,
            vt: r.vtResult.status === 'fulfilled' ? r.vtResult.value : null,
            vtErr: r.vtResult.status === 'rejected' ? errToObj(r.vtResult.reason) : null,
            corr: r.corrResult.status === 'fulfilled' ? r.corrResult.value : null,
            corrErr: r.corrResult.status === 'rejected' ? (r.corrResult.reason?.message || String(r.corrResult.reason)) : null
        }))
    };
    let list = loadHistoryEntries();
    list.unshift(entry);
    while (list.length > HISTORY_MAX) list.pop();
    let ok = false;
    while (true) {
        ok = saveHistoryEntries(list);
        if (ok) return;
        if (list.length <= 1) break;
        list.pop();
    }
    if (!ok) {
        try { localStorage.removeItem(LS_HISTORY); } catch (e) {}
        saveHistoryEntries([entry]);
    }
}

function historyDeleteEntry(id) {
    const list = loadHistoryEntries().filter(x => x.id !== id);
    saveHistoryEntries(list);
    renderHistoryListDOM();
}

function renderHistoryListDOM() {
    const host = document.getElementById('historyList');
    if (!host) return;
    const list = loadHistoryEntries();
    if (!list.length) {
        host.innerHTML = '<span class="history-empty">Belum ada riwayat.</span>';
        return;
    }
    host.innerHTML = list.map(ent => {
        const d = new Date(ent.ts);
        const when = isNaN(d.getTime()) ? ent.ts : d.toLocaleString();
        const n = (ent.results && ent.results.length) || 0;
        const preview = String(ent.vtInput || '').split('\n').filter(Boolean)[0] || '—';
        const idJs = JSON.stringify(ent.id);
        return `<div class="history-row">
            <div class="h-meta">
                <div>${escHtml(when)} · ${n} IOC</div>
                <div class="history-mini" title="${escHtml(preview)}">${escHtml(preview.length > 64 ? preview.slice(0,64)+'…' : preview)}</div>
            </div>
            <div class="h-actions">
                <button type="button" class="vt-mini-btn" onclick='historyRestoreEntry(${idJs})'>Lihat hasil</button>
                <button type="button" class="vt-mini-btn" onclick='historyDeleteEntry(${idJs})'>Hapus</button>
            </div>
        </div>`;
    }).join('');
}

async function historyRestoreEntry(id) {
    const ent = loadHistoryEntries().find(x => x.id === id);
    if (!ent || !ent.results || !ent.results.length) return;
    _historyViewingVtInput = ent.vtInput || '';

    const lineResults = ent.results.map(r => ({
        rawIoc: r.rawIoc,
        vtResult: r.vt ? { status: 'fulfilled', value: r.vt } : { status: 'rejected', reason: objToErr(r.vtErr || { message: 'VT error' }) },
        corrResult: r.corr ? { status: 'fulfilled', value: r.corr } : { status: 'rejected', reason: { message: r.corrErr || 'Correlation failed' } }
    }));

    const tabBtn = document.querySelector('.tab-btn[data-tab="tab-history"]');
    if (tabBtn) openTab('tab-history', tabBtn);

    vtNotify('<span class="spinner"></span> Memuat snapshot hasil…', 'loading');
    await renderScanBatch(lineResults, { mode: 'history' });
    vtNotify('✓ Snapshot dimuat (data lokal, tanpa API).', 'success');
}

function historySendIocToLookup() {
    const txt = _historyViewingVtInput || '';
    if (!txt.trim()) {
        setStatus('statusHistory', '⚠ Tidak ada IOC tersimpan untuk entri ini.', 'error');
        return;
    }
    document.getElementById('vtInput').value = txt;
    const tabBtn = document.querySelector('.tab-btn[data-tab="tab-vt"]');
    if (tabBtn) openTab('tab-vt', tabBtn);
    setStatus('statusVT', '✓ IOC dari riwayat ditempelkan — jalankan <strong>Run IoC Scan</strong> bila ingin scan ulang.', 'success');
}

function vtGetExportColumnKeys() {
    const sel = document.getElementById('vtExportPreset');
    const preset = sel ? sel.value : 'full';
    if (preset === 'custom') {
        try {
            const raw = localStorage.getItem(LS_EXPORT_CUSTOM);
            const a = raw ? JSON.parse(raw) : null;
            if (Array.isArray(a) && a.length) return a.filter(k => VT_EXPORT_ALL_KEYS.includes(k));
        } catch (e) {}
        return VT_EXPORT_PRESETS.full;
    }
    return VT_EXPORT_PRESETS[preset] ? VT_EXPORT_PRESETS[preset].slice() : VT_EXPORT_PRESETS.full;
}

function vtExportCellValue(item, key) {
    const srcLine = (item.correlation?.sources || []).map(s => {
        const v = (s.verdict || (s.skipped ? 'skipped' : s.error ? 'error' : 'unknown'));
        return `${s.source}:${v}`;
    }).join(' | ');
    switch (key) {
        case 'ioc': return item.ioc;
        case 'type': return String(item.type || '').toUpperCase();
        case 'vt_verdict': return item.vtVerdict;
        case 'detections': return `${item.malicious}/${item.total || 0}`;
        case 'abuseipdb_percent': {
            const p = vtGetAbusePercent(item);
            return p === '' ? '' : (String(p) + '%');
        }
        case 'otx_pulses': return vtGetOtxPulses(item);
        case 'abusech_url_count': return vtGetAbuseChUrlCount(item);
        case 'abusech_online_urls': return vtGetAbuseChOnlineUrls(item);
        case 'country': return item.country || '';
        case 'as_owner': return item.asOwner || '';
        case 'confidence': return item.correlation?.confidence ?? '';
        case 'sources': return srcLine;
        default: return '';
    }
}

function vtExportPdfCellDisplay(item, key) {
    const v = vtExportCellValue(item, key);
    if (v === '' || v === null || v === undefined) return '—';
    return v;
}

function vtOnExportPresetChange() {
    const sel = document.getElementById('vtExportPreset');
    const chips = document.getElementById('vtExportColChips');
    if (!sel || !chips) return;
    const v = sel.value;
    try { localStorage.setItem(LS_EXPORT_PRESET, v); } catch (e) {}
    if (v === 'custom') {
        chips.classList.add('open');
        vtRenderExportColChips();
    } else {
        chips.classList.remove('open');
    }
}

function vtRenderExportColChips() {
    const chips = document.getElementById('vtExportColChips');
    if (!chips) return;
    let selected = [];
    try {
        const raw = localStorage.getItem(LS_EXPORT_CUSTOM);
        const a = raw ? JSON.parse(raw) : null;
        selected = Array.isArray(a) && a.length ? a : VT_EXPORT_ALL_KEYS.slice();
    } catch (e) { selected = VT_EXPORT_ALL_KEYS.slice(); }

    chips.innerHTML = VT_EXPORT_ALL_KEYS.map(k => {
        const on = selected.includes(k) ? ' on' : '';
        const lab = VT_EXPORT_LABELS[k] || k;
        return `<span class="vt-col-chip${on}" data-key="${escHtml(k)}" onclick="vtToggleExportColChip(this)"><input type="checkbox" ${selected.includes(k)?'checked':''} onclick="event.stopPropagation();vtToggleExportColChip(this.parentElement)"/> ${escHtml(lab)}</span>`;
    }).join('');
}

function vtToggleExportColChip(el) {
    const k = el.getAttribute('data-key');
    if (!k) return;
    let selected = [];
    try {
        const raw = localStorage.getItem(LS_EXPORT_CUSTOM);
        const a = raw ? JSON.parse(raw) : VT_EXPORT_ALL_KEYS;
        selected = Array.isArray(a) && a.length ? a.slice() : VT_EXPORT_ALL_KEYS.slice();
    } catch (e) { selected = VT_EXPORT_ALL_KEYS.slice(); }
    const i = selected.indexOf(k);
    if (i >= 0) selected.splice(i, 1);
    else selected.push(k);
    if (!selected.length) selected = ['ioc'];
    try { localStorage.setItem(LS_EXPORT_CUSTOM, JSON.stringify(selected)); } catch (e) {}
    vtRenderExportColChips();
}

function vtInitExportPresetUI() {
    const sel = document.getElementById('vtExportPreset');
    if (!sel) return;
    try {
        const s = localStorage.getItem(LS_EXPORT_PRESET);
        if (s && ['full','minimal','siem','custom'].includes(s)) sel.value = s;
    } catch (e) {}
    vtOnExportPresetChange();
}

function vtVerdictKeyFromClass(cls) {
    if (cls === 'verdict-clean') return 'clean';
    if (cls === 'verdict-suspicious') return 'suspicious';
    if (cls === 'verdict-malicious') return 'malicious';
    return 'unknown';
}

function vtUpdateSelectedNote() {
    const n = _vtState.items.filter(x => x.selected).length;
    const el = document.getElementById(_vtActiveNoteId || 'vtSelectedNote');
    if (el) el.textContent = `${n} selected`;
}

function vtGetSelectedItems() {
    return _vtState.items.filter(x => x.selected);
}

function vtApplyFilters() {
    const res = document.getElementById(_vtActiveResultsId || 'vtResults');
    if (!res) return;
    const cards = [...res.querySelectorAll('.vt-card')];
    for (const c of cards) {
        const verdictKey = c.getAttribute('data-verdict') || 'unknown';
        const show = verdictKey === 'unknown' || verdictKey === 'blocklist'
            ? true
            : !!_vtState.filters[verdictKey];
        c.style.display = show ? '' : 'none';
    }
}

function vtToggleFilter(key, chipEl) {
    const cb = chipEl?.querySelector('input[type="checkbox"]');
    const next = cb ? !cb.checked : !_vtState.filters[key];
    _vtState.filters[key] = next;
    if (cb) cb.checked = next;
    chipEl?.classList.toggle('on', next);
    vtApplyFilters();
}

function vtSelectVisible(on) {
    const res = document.getElementById(_vtActiveResultsId || 'vtResults');
    if (!res) return;
    const visibleCards = [...res.querySelectorAll('.vt-card')].filter(c => c.style.display !== 'none');
    for (const card of visibleCards) {
        const id = card.getAttribute('data-id');
        const item = _vtState.items.find(x => String(x.id) === String(id));
        if (!item) continue;
        item.selected = !!on;
        const cb = card.querySelector('input.vt-select');
        if (cb) cb.checked = item.selected;
    }
    vtUpdateSelectedNote();
}

function vtSetSelected(id, checked) {
    const item = _vtState.items.find(x => String(x.id) === String(id));
    if (item) item.selected = !!checked;
    vtUpdateSelectedNote();
}

async function vtCopyToClipboard(text) {
    try {
        await navigator.clipboard.writeText(text);
        return true;
    } catch {
        const ta = document.createElement('textarea');
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand('copy'); } finally { ta.remove(); }
        return true;
    }
}

async function vtCopySelected() {
    const items = vtGetSelectedItems();
    if (!items.length) { vtNotify('⚠ Tidak ada item yang dipilih.', 'error'); return; }
    const txt = items.map(x => x.ioc).join('\n');
    await vtCopyToClipboard(txt);
    vtNotify(`✓ Copied ${items.length} IOC(s).`, 'success');
}

function vtToggleExportMenu(ev) {
    ev?.stopPropagation?.();
    const btn = ev?.currentTarget;
    const dd = btn?.closest?.('.vt-dd');
    const menu = dd?.querySelector?.('.vt-dd-menu');
    if (!menu) return;
    document.querySelectorAll('.vt-dd-menu.open').forEach(m => { if (m !== menu) m.classList.remove('open'); });
    menu.classList.toggle('open');
}

function vtCloseExportMenu() {
    document.querySelectorAll('.vt-dd-menu.open').forEach(m => m.classList.remove('open'));
}

document.addEventListener('click', (e) => {
    if (e.target.closest('.vt-dd')) return;
    vtCloseExportMenu();
});

function vtExport(kind) {
    vtCloseExportMenu();
    if (kind === 'csv') return vtExportCSV();
    if (kind === 'pdf') return vtExportPDF();
}

function vtGetSource(item, sourceName) {
    const srcs = item?.correlation?.sources || [];
    return srcs.find(s => String(s.source || '').toLowerCase() === String(sourceName).toLowerCase());
}

function vtGetAbusePercent(item) {
    const s = vtGetSource(item, 'AbuseIPDB');
    const v = s?.meta?.['Abuse Score'];
    if (v === null || v === undefined) return '';
    const m = String(v).match(/(\d{1,3})\s*%/);
    return m ? Number(m[1]) : '';
}

function vtGetOtxPulses(item) {
    const s = vtGetSource(item, 'AlienVault OTX');
    const v = s?.meta?.['Pulse Count'];
    if (v === null || v === undefined) return '';
    const n = Number(v);
    return Number.isFinite(n) ? n : '';
}

function vtGetAbuseChUrlCount(item) {
    const s = vtGetSource(item, 'Abuse.ch');
    const v = s?.meta?.['URL Count'];
    if (v === null || v === undefined) return '';
    const n = Number(v);
    return Number.isFinite(n) ? n : '';
}

function vtGetAbuseChOnlineUrls(item) {
    const s = vtGetSource(item, 'Abuse.ch');
    const v = s?.meta?.['Online URLs'];
    if (v === null || v === undefined) return '';
    const n = Number(v);
    return Number.isFinite(n) ? n : '';
}

function vtExportCSV() {
    const items = vtGetSelectedItems();
    if (!items.length) { vtNotify('⚠ Pilih dulu item yang mau di-export.', 'error'); return; }
    const colKeys = vtGetExportColumnKeys();
    const cols = colKeys.map(k => VT_EXPORT_LABELS[k] || k);
    const esc = (v) => {
        const s = String(v ?? '');
        if (/[",\n]/.test(s)) return `"${s.replace(/"/g,'""')}"`;
        return s;
    };
    const rows = items.map(x => colKeys.map(k => esc(vtExportCellValue(x, k))).join(','));
    const csv = [cols.join(','), ...rows].join('\n');
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = `vt-results-${new Date().toISOString().slice(0,10)}.csv`;
    document.body.appendChild(a);
    a.click();
    a.remove();
    vtNotify(`✓ CSV exported (${items.length} row(s)).`, 'success');
}

function vtExportPDF() {
    const items = vtGetSelectedItems();
    if (!items.length) { vtNotify('⚠ Pilih dulu item yang mau di-export.', 'error'); return; }

    const colKeys = vtGetExportColumnKeys();
    const headLabels = colKeys.map(k => (VT_EXPORT_LABELS[k] || k).toUpperCase());

    // Prefer jsPDF if available; otherwise fallback to print-friendly HTML.
    const hasJsPDF = !!(window.jspdf && window.jspdf.jsPDF);
    if (!hasJsPDF) {
        const win = window.open('', '_blank');
        if (!win) { vtNotify('⚠ Popup blocked: tidak bisa generate PDF window.', 'error'); return; }
        const th = headLabels.map(h => `<th>${escHtml(h)}</th>`).join('');
        const rows = items.map(x => {
            const tds = colKeys.map(k => `<td>${escHtml(String(vtExportPdfCellDisplay(x, k)))}</td>`).join('');
            return `<tr>${tds}</tr>`;
        }).join('');
        // Jangan mengetik tag penutup skrip literal di file HTML — pecah dengan konkatenasi (lihat printHtml di bawah).
        // Kalau tidak, parser HTML memutus blok skrip dan sisa JS bisa jadi teks/HTML rusak di halaman.
        const printHtml = '<!doctype html><html><head><meta charset="utf-8"><title>VT Export</title>' +
            '<style>' +
            'body{font-family:Arial, sans-serif; padding:20px;}' +
            'h2{margin:0 0 10px;}' +
            '.meta{color:#555; font-size:12px; margin-bottom:14px;}' +
            'table{width:100%; border-collapse:collapse; font-size:12px;}' +
            'th,td{border:1px solid #ddd; padding:8px; vertical-align:top;}' +
            'th{background:#f5f5f5; text-align:left;}' +
            '</style></head><body>' +
            '<h2>VirusTotal + Threat Intel Export</h2>' +
            '<div class="meta">Generated: ' + escHtml(new Date().toLocaleString()) + '</div>' +
            '<table><thead><tr>' + th + '</tr></thead><tbody>' + rows + '</tbody></table>' +
            '<div class="meta" style="margin-top:12px;">Tip: pilih “Save as PDF” di dialog print.</div>' +
            '<scr' + 'ipt>window.onload=function(){window.print()}<' + '/scr' + 'ipt>' +
            '</body></html>';
        win.document.write(printHtml);
        win.document.close();
        vtNotify(`✓ Opened print view for PDF (${items.length} item(s)).`, 'success');
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF({ unit:'pt', format:'a4' });
    const margin = 40;
    let y = margin;
    doc.setFont('helvetica','bold'); doc.setFontSize(14);
    doc.text('VirusTotal + Threat Intel Export', margin, y);
    y += 18;
    doc.setFont('helvetica','normal'); doc.setFontSize(10);
    doc.text(`Generated: ${new Date().toLocaleString()}`, margin, y);
    y += 14;
    doc.text(`Items: ${items.length}`, margin, y);
    y += 18;

    const body = items.map(x => colKeys.map(k => String(vtExportPdfCellDisplay(x, k))));

    if (doc.autoTable) {
        doc.autoTable({
            startY: y,
            head: [headLabels],
            body,
            styles: { fontSize: 8, cellPadding: 4, overflow: 'linebreak' },
            headStyles: { fillColor: [14, 24, 41] },
            margin: { left: margin, right: margin }
        });
    } else {
        doc.setFontSize(9);
        for (const row of body) {
            const line = row.join(' | ');
            if (y > 780) { doc.addPage(); y = margin; }
            doc.text(line, margin, y);
            y += 12;
        }
    }

    doc.save(`vt-results-${new Date().toISOString().slice(0,10)}.pdf`);
    vtNotify(`✓ PDF exported (${items.length} item(s)).`, 'success');
}

function makeCard(headerInner, bodyInner, collapsed, trailInner = '') {
    const idx = _cardIdx++;
    const bodyClass = collapsed ? 'vt-card-body collapsed' : 'vt-card-body';
    const chevClass = collapsed ? 'vt-chevron' : 'vt-chevron open';
    return `<div class="vt-card">
        <div class="vt-card-header">
            ${headerInner}
            <span class="vt-card-header-right">
                ${trailInner}
                <button type="button" class="vt-chev-btn" title="Toggle details" onclick="toggleCard(this);event.stopPropagation();">
                    <span class="${chevClass}">▼</span>
                </button>
            </span>
        </div>
        <div class="${bodyClass}">${bodyInner}</div>
    </div>`;
}

function renderHash(ioc, d, collapsed=false) {
    const a = d.data?.attributes || {};
    const s = a.last_analysis_stats || {};
    const mal = s.malicious||0, sus = s.suspicious||0;
    const total = Object.values(s).reduce((x,y)=>x+y,0);
    const v = verdict(mal, sus, total);
    const names = (a.names||[]).slice(0,3).join(', ')||'—';
    const ftype = a.type_description||a.magic||'—';
    const size  = a.size ? (a.size/1024).toFixed(1)+' KB' : '—';
    const first = a.first_submission_date ? new Date(a.first_submission_date*1000).toLocaleDateString('en-GB') : '—';
    const last  = a.last_analysis_date    ? new Date(a.last_analysis_date*1000).toLocaleDateString('en-GB')    : '—';
    const vtUrl = `https://www.virustotal.com/gui/file/${ioc}`;
    const header = `
        <span class="vt-header-actions" onclick="event.stopPropagation()">
            <input class="vt-select" type="checkbox" onclick="event.stopPropagation();vtSetSelected(${_cardIdx}, this.checked)"/>
            <button class="vt-copy-ioc" onclick="event.stopPropagation();vtCopyToClipboard('${escHtml(ioc)}');vtNotify('✓ Copied IOC.','success');">COPY</button>
        </span>
        <span class="vt-type-badge badge-hash">${hashLabel(ioc.length)}</span>
        <span class="vt-ioc-val">${escHtml(ioc)}</span>
        <span class="verdict ${v.cls}">● ${v.label}</span>`;
    const body = `
        ${detBar(mal, sus, total)}
        <div class="meta-grid">
            ${mi('Malicious',  mal,  mal>0?'red':'green')}
            ${mi('Suspicious', sus,  sus>0?'yellow':'')}
            ${mi('Undetected', s.undetected||0)}
            ${mi('File Type',  ftype,'purple')}
            ${mi('Size',       size)}
            ${mi('File Names', names)}
            ${mi('First Seen', first,'cyan')}
            ${mi('Last Scan',  last)}
        </div>
        <a class="vt-open-link" href="${escHtml(vtUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">&#8599; Open in VirusTotal</a>`;
    const html = makeCard(header, body, collapsed);
    // Track item for export/filter
    _vtState.items.push({
        id: _cardIdx - 1,
        ioc, type: 'hash',
        vtVerdict: v.label,
        verdictKey: vtVerdictKeyFromClass(v.cls),
        malicious: mal, suspicious: sus, total,
        reputation: '', country: '', asn: '', asOwner: '',
        vtUrl,
        selected: false,
        correlation: null,
        correlationLabel: ''
    });
    return html;
}

function renderIP(ioc, d, collapsed=false) {
    const a = d.data?.attributes || {};
    const s = a.last_analysis_stats || {};
    const mal = s.malicious||0, sus = s.suspicious||0;
    const total = Object.values(s).reduce((x,y)=>x+y,0);
    const v   = verdict(mal, sus, total);
    const rep = a.reputation !== undefined ? a.reputation : '—';
    const rc  = rep > 0 ? 'green' : rep < 0 ? 'red' : '';
    const vtUrl = `https://www.virustotal.com/gui/ip-address/${ioc}`;
    const flag  = countryFlag(a.country);
    const ctry  = a.country || '—';
    const ctryBadge = `<span style="display:inline-flex;align-items:center;gap:4px;background:rgba(56,189,248,0.08);border:1px solid rgba(56,189,248,0.2);border-radius:5px;padding:2px 8px;font-size:0.75rem;font-family:'JetBrains Mono',monospace;color:var(--cyan);flex-shrink:0;">${flag?flag+'\u00a0':''}${escHtml(ctry)}</span>`;
    const cache = d?._meta?.cache || {};
    const seenBefore = !!cache?.seenBefore;
    const stableId = cache?.stableId || '';
    const seenBadge = seenBefore ? `<span class="vt-seen" title="Already scanned IP">♻️ SCANNED</span>` : '';
    const cachedTrail = stableId
        ? `<a class="vt-cached-btn" href="${escHtml(vtCachedResultHref(stableId))}" target="_blank" rel="noopener noreferrer" title="Open cached result" aria-label="Open cached result" onclick="event.stopPropagation()">↗</a>`
        : '';
    const header = `
        <span class="vt-header-actions" onclick="event.stopPropagation()">
            <input class="vt-select" type="checkbox" onclick="event.stopPropagation();vtSetSelected(${_cardIdx}, this.checked)"/>
            <button class="vt-copy-ioc" onclick="event.stopPropagation();vtCopyToClipboard('${escHtml(ioc)}');vtNotify('✓ Copied IP.','success');">COPY</button>
        </span>
        <span class="vt-type-badge badge-ip">IP ADDRESS</span>
        <span class="vt-ioc-val">${escHtml(ioc)}</span>
        ${seenBadge}
        ${ctryBadge}
        <span class="verdict ${v.cls}">● ${v.label}</span>`;
    const body = `
        ${detBar(mal, sus, total)}
        <div class="meta-grid">
            ${mi('Malicious',  mal,  mal>0?'red':'green')}
            ${mi('Suspicious', sus,  sus>0?'yellow':'')}
            ${mi('Undetected', s.undetected||0)}
            ${mi('Country',    (flag?flag+' ':'')+ctry, 'cyan')}
            ${mi('ASN',        a.asn?'AS'+a.asn:'—', 'purple')}
            ${mi('AS Owner',   a.as_owner||'—')}
            ${mi('Network',    a.network||'—')}
            ${mi('Reputation', rep, rc)}
        </div>
        <a class="vt-open-link" href="${escHtml(vtUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">&#8599; Open in VirusTotal</a>`;
    const html = makeCard(header, body, collapsed, cachedTrail);
    _vtState.items.push({
        id: _cardIdx - 1,
        ioc, type: 'ip',
        vtVerdict: v.label,
        verdictKey: vtVerdictKeyFromClass(v.cls),
        malicious: mal, suspicious: sus, total,
        reputation: rep,
        country: ctry,
        asn: a.asn ? 'AS' + a.asn : '',
        asOwner: a.as_owner || '',
        vtUrl,
        selected: false,
        correlation: null,
        correlationLabel: ''
    });
    return html;
}

function renderDomain(ioc, d, collapsed=false) {
    const a = d.data?.attributes || {};
    const s = a.last_analysis_stats || {};
    const mal = s.malicious||0, sus = s.suspicious||0;
    const total = Object.values(s).reduce((x,y)=>x+y,0);
    const v   = verdict(mal, sus, total);
    const rep = a.reputation !== undefined ? a.reputation : '—';
    const rc  = rep > 0 ? 'green' : rep < 0 ? 'red' : '';
    const registrar = a.registrar || '—';
    const created  = a.creation_date    ? new Date(a.creation_date*1000).toLocaleDateString('en-GB')    : '—';
    const updated  = a.last_update_date ? new Date(a.last_update_date*1000).toLocaleDateString('en-GB') : '—';
    const cats  = Object.values(a.categories||{}).slice(0,2).join(', ') || '—';
    const vtUrl = `https://www.virustotal.com/gui/domain/${ioc}`;
    const header = `
        <span class="vt-header-actions" onclick="event.stopPropagation()">
            <input class="vt-select" type="checkbox" onclick="event.stopPropagation();vtSetSelected(${_cardIdx}, this.checked)"/>
            <button class="vt-copy-ioc" onclick="event.stopPropagation();vtCopyToClipboard('${escHtml(ioc)}');vtNotify('✓ Copied domain.','success');">COPY</button>
        </span>
        <span class="vt-type-badge badge-domain">DOMAIN</span>
        <span class="vt-ioc-val">${escHtml(ioc)}</span>
        <span class="verdict ${v.cls}">● ${v.label}</span>`;
    const body = `
        ${detBar(mal, sus, total)}
        <div class="meta-grid">
            ${mi('Malicious',  mal,  mal>0?'red':'green')}
            ${mi('Suspicious', sus,  sus>0?'yellow':'')}
            ${mi('Undetected', s.undetected||0)}
            ${mi('Registrar',  registrar, 'purple')}
            ${mi('Created',    created,   'cyan')}
            ${mi('Updated',    updated)}
            ${mi('Categories', cats)}
            ${mi('Reputation', rep, rc)}
        </div>
        <a class="vt-open-link" href="${escHtml(vtUrl)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">&#8599; Open in VirusTotal</a>`;
    const html = makeCard(header, body, collapsed);
    _vtState.items.push({
        id: _cardIdx - 1,
        ioc, type: 'domain',
        vtVerdict: v.label,
        verdictKey: vtVerdictKeyFromClass(v.cls),
        malicious: mal, suspicious: sus, total,
        reputation: rep,
        country: '', asn: '', asOwner: '',
        vtUrl,
        selected: false,
        correlation: null,
        correlationLabel: ''
    });
    return html;
}

function renderErr(ioc, type, err, collapsed=false, correlationData=null) {
    const is429 = err && (err.status === 429 || (String(err.message || '').toLowerCase().includes('rate limit') || String(err.message || '').toLowerCase().includes('quota')));
    const vtLabel = err.status === 404 ? 'NOT FOUND' : is429 ? 'VT: RATE LIMITED' : 'VT: ERROR';
    const msg = err.detail || err.message || String(err);

    // Use threat intel as indicator when VT fails
    const hasCorr = correlationData && !correlationData.error && (correlationData.sources || []).length > 0;
    const conf = hasCorr ? correlationData.confidence : null;
    const riskLabel = hasCorr ? confLabel(conf) : null;
    const riskCls = hasCorr ? confClass(conf).replace('conf-', 'verdict-') : ''; // conf-low -> verdict-low etc, but we use conf-low/conf-high for badges
    const verdictCls = hasCorr ? (conf >= 70 ? 'verdict-malicious' : conf >= 40 ? 'verdict-suspicious' : conf >= 15 ? 'verdict-suspicious' : 'verdict-clean') : 'verdict-unknown';
    const displayVerdict = hasCorr ? riskLabel : vtLabel;
    const hint = err.status === 404
        ? '<span style="color:var(--text-sec);font-size:0.72rem;display:block;margin-top:4px;">IOC tidak ada di database VT.</span>'
        : err.status === 401
        ? '<span style="color:var(--text-sec);font-size:0.72rem;display:block;margin-top:4px;">Cek VT_API_KEY di Vercel env variables.</span>'
        : err.status === 503 || err.status === 0
        ? '<span style="color:var(--text-sec);font-size:0.72rem;display:block;margin-top:4px;">VT tidak bisa diakses. Gunakan threat intel di bawah sebagai indikator.</span>'
        : is429
        ? '<span style="color:var(--text-sec);font-size:0.72rem;display:block;margin-top:4px;">VT quota/rate limit. Gunakan threat intel di bawah (AbuseIPDB, OTX, dll) sebagai indikator.</span>'
        : '<span style="color:var(--text-sec);font-size:0.72rem;display:block;margin-top:4px;">Gunakan threat intel di bawah sebagai indikator.</span>';

    const badgeType = type || 'unknown';
    const badgeCls  = badgeType === 'ip' ? 'badge-ip' : badgeType === 'domain' ? 'badge-domain' : badgeType === 'hash' ? 'badge-hash' : 'badge-hash';
    const badgeLbl  = badgeType.toUpperCase();
    const header = `
        <span class="vt-header-actions" onclick="event.stopPropagation()">
            <input class="vt-select" type="checkbox" onclick="event.stopPropagation();vtSetSelected(${_cardIdx}, this.checked)"/>
            <button class="vt-copy-ioc" onclick="event.stopPropagation();vtCopyToClipboard('${escHtml(ioc)}');vtNotify('✓ Copied IOC.','success');">COPY</button>
        </span>
        <span class="vt-type-badge ${badgeCls}">${badgeLbl}</span>
        <span class="vt-ioc-val">${escHtml(ioc)}</span>
        <span class="verdict ${verdictCls}">● ${escHtml(displayVerdict)}</span>`;
    const body = `<div class="vt-error-box">
        <span style="opacity:0.6;font-size:0.7rem;">[VT ${err.status||'?'}]</span> ${escHtml(msg)}${hint}
    </div>`;
    const html = makeCard(header, body, collapsed);
    _vtState.items.push({
        id: _cardIdx - 1,
        ioc, type: badgeType || 'unknown',
        vtVerdict: hasCorr ? displayVerdict : vtLabel,
        verdictKey: hasCorr ? (conf >= 70 ? 'malicious' : conf >= 40 || conf >= 15 ? 'suspicious' : 'clean') : 'unknown',
        malicious: '', suspicious: '', total: '',
        reputation: '', country: '', asn: '', asOwner: '',
        vtUrl: '',
        selected: false,
        correlation: correlationData || null,
        correlationLabel: hasCorr ? riskLabel : ''
    });
    return html;
}

/* ── CORRELATION ─────────────────────────────────────────────────────── */
async function fetchCorrelation(rawIoc) {
    const r = await fetch(`/api/correlate?ioc=${encodeURIComponent(rawIoc)}`);
    return r.json();
}

function confClass(score) {
    if (score === null || score === undefined) return 'conf-none';
    if (score >= 70) return 'conf-critical';
    if (score >= 40) return 'conf-high';
    if (score >= 15) return 'conf-medium';
    return 'conf-low';
}

function confLabel(score) {
    if (score === null || score === undefined) return 'NO DATA';
    if (score >= 70) return 'HIGH RISK';
    if (score >= 40) return 'MEDIUM RISK';
    if (score >= 15) return 'LOW RISK';
    return 'LIKELY CLEAN';
}

function confBarColor(score) {
    if (!score) return 'var(--green)';
    if (score >= 70) return 'var(--red)';
    if (score >= 40) return 'var(--orange)';
    if (score >= 15) return 'var(--yellow)';
    return 'var(--green)';
}

function toggleSourceDetail(el) {
    const row    = el.closest('.source-row');
    const detail = row.querySelector('.source-detail');
    const chev   = row.querySelector('.source-chevron');
    if (!detail) return;
    detail.classList.toggle('open');
    chev.classList.toggle('open');
}

function renderCorrelation(data, panelEl) {
    if (data.error) {
        panelEl.innerHTML = `<div class="corr-loading" style="color:var(--red)">⚠ ${escHtml(data.error)}</div>`;
        return;
    }

    const score   = data.confidence;
    const cls     = confClass(score);
    const label   = confLabel(score);
    const pct     = score !== null ? score.toFixed(0) : '—';
    const barW    = score !== null ? Math.min(score, 100) : 0;
    const barCol  = confBarColor(score);

    const sourceRows = (data.sources || []).map((s, i) => {
        const id = `sd-${Date.now()}-${i}`;
        if (s.skipped) {
            return `<div class="source-row" style="cursor:default;">
                <div class="source-row-top">
                    <span class="source-name">${escHtml(s.source)}</span>
                    <span class="source-verdict sv-skipped">NO KEY</span>
                </div>
            </div>`;
        }
        if (s.error) {
            return `<div class="source-row" style="cursor:default;">
                <div class="source-row-top">
                    <span class="source-name">${escHtml(s.source)}</span>
                    <span class="source-verdict sv-unknown">ERROR</span>
                </div>
                <div style="font-size:0.7rem;color:var(--red);margin-top:4px;font-family:'JetBrains Mono',monospace;">${escHtml(s.error)}</div>
            </div>`;
        }

        const vc  = `sv-${s.verdict || 'unknown'}`;
        const vl  = (s.verdict || 'unknown').toUpperCase();
        const metaItems = Object.entries(s.meta || {}).map(([k, v]) =>
            `<div class="sm-item"><div class="sm-key">${escHtml(k)}</div><div class="sm-val">${escHtml(String(v))}</div></div>`
        ).join('');
        const linkHtml = s.link
            ? `<a class="source-link" href="${escHtml(s.link)}" target="_blank" rel="noopener" onclick="event.stopPropagation()">↗ View on ${escHtml(s.source)}</a>`
            : '';

        return `<div class="source-row" onclick="toggleSourceDetail(this)">
            <div class="source-row-top">
                <span class="source-name">${escHtml(s.source)}</span>
                <span class="source-verdict ${vc}">● ${vl}</span>
                <span class="source-chevron">▼</span>
            </div>
            <div class="source-detail">
                <div class="source-meta">${metaItems}</div>
                ${linkHtml}
            </div>
        </div>`;
    }).join('');

    panelEl.innerHTML = `
        <div class="corr-header">
            <span class="corr-title">🔗 Threat Intel Correlation</span>
            <span class="confidence-badge ${cls}">${label} &nbsp;${pct}%</span>
        </div>
        <div class="conf-bar-track">
            <div class="conf-bar-fill" style="width:${barW}%;background:${barCol};"></div>
        </div>
        <div class="source-grid">${sourceRows || '<span style="color:var(--text-sec);font-size:0.78rem;">No sources available for this IOC type.</span>'}</div>`;
}

async function renderScanBatch(lineResults, opts = {}) {
    const mode = opts.mode || 'lookup';
    const isHistory = mode === 'history';
    const resId = isHistory ? 'historyScanResults' : 'vtResults';
    const countId = isHistory ? 'historyResultCount' : 'vtResultCount';

    _vtState = isHistory ? _vtStateHistory : _vtStateLookup;
    _vtActiveResultsId = resId;
    _vtActiveNoteId = isHistory ? 'historySelectedNote' : 'vtSelectedNote';
    _vtStatusMsgId = isHistory ? 'statusHistory' : 'statusVT';

    if (isHistory) {
        const ph = document.getElementById('historyScanPlaceholder');
        const surf = document.getElementById('historyScanSurface');
        if (ph) ph.style.display = 'none';
        if (surf) surf.style.display = '';
    }

    const res = document.getElementById(resId);
    if (!res) return;

    res.innerHTML = '';
    const countEl = document.getElementById(countId);
    if (countEl) countEl.textContent = '';
    _vtState.items = [];
    vtUpdateSelectedNote();

    const cards = [];
    _cardIdx = 0;
    const multi = lineResults.length > 1;

    for (let i = 0; i < lineResults.length; i++) {
        const line = lineResults[i];
        const { rawIoc, vtResult, corrResult } = line;

        let cardHtml;
        if (vtResult.status === 'fulfilled') {
            const d    = vtResult.value;
            const type = d._meta?.type || 'hash';
            const ioc  = d._meta?.ioc  || rawIoc;
            if (type === 'ip')          cardHtml = renderIP(ioc, d, multi);
            else if (type === 'domain') cardHtml = renderDomain(ioc, d, multi);
            else                        cardHtml = renderHash(ioc, d, multi);
        } else {
            const corrData = corrResult.status === 'fulfilled' ? corrResult.value : null;
            cardHtml = renderErr(rawIoc, null, vtResult.reason, multi, corrData);
        }

        const corrPrefix = isHistory ? 'hcorr-' : 'corr-';
        const corrId = `${corrPrefix}${_cardIdx - 1}`;
        cardHtml = cardHtml.replace(
            '</div>\n    </div>',
            `</div>\n    <div class="corr-panel" id="${corrId}"><div class="corr-loading"><span class="spinner"></span> Loading threat intel...</div></div>\n    </div>`
        );
        cards.push({ html: cardHtml, corrId, corrResult });
    }

    res.innerHTML = cards.map(c => c.html).join('');
    [...res.querySelectorAll('.vt-card')].forEach((card, idx) => {
        const item = _vtState.items[idx];
        if (!item) return;
        card.setAttribute('data-id', String(item.id));
        card.setAttribute('data-verdict', item.verdictKey || 'unknown');
    });
    vtApplyFilters();
    vtSyncFilterUIs();

    for (const { corrId, corrResult } of cards) {
        if (!corrId || !corrResult) continue;
        const panel = document.getElementById(corrId);
        if (!panel) continue;
        if (corrResult.status === 'fulfilled') {
            renderCorrelation(corrResult.value, panel);
            // Best-effort: persist correlation verdicts to vt_ip_cache
            ipCachePostCorrelation(corrResult.value);
            const idNum = Number(String(corrId).replace(/^(corr|hcorr|ycorr)-/, ''));
            const it = _vtState.items.find(x => x.id === idNum);
            if (it) {
                it.correlation = corrResult.value;
                const sc = it.correlation?.confidence;
                it.correlationLabel = sc === null || sc === undefined ? 'NO DATA'
                    : sc >= 70 ? 'HIGH RISK'
                    : sc >= 40 ? 'MEDIUM RISK'
                    : sc >= 15 ? 'LOW RISK'
                    : 'LIKELY CLEAN';
            }
        } else {
            panel.innerHTML = `<div class="corr-loading" style="color:var(--red)">⚠ Correlation failed: ${escHtml(corrResult.reason?.message || 'Unknown error')}</div>`;
        }
    }

    if (countEl) countEl.textContent = `${lineResults.length} result(s)`;
}

/** How many IOC lines to scan in parallel. Use 1 if VirusTotal often returns 429; 2–3 is faster when you have quota or several VT keys. */
const VT_SCAN_CONCURRENCY = 2;

/** Run `fn(item, index)` over `items` with a fixed worker pool; results stay in input order. */
async function vtMapPool(items, concurrency, fn) {
    const n = items.length;
    const out = new Array(n);
    let nextIndex = 0;
    const workers = Math.min(Math.max(1, concurrency), n);

    async function worker() {
        for (;;) {
            const i = nextIndex++;
            if (i >= n) return;
            out[i] = await fn(items[i], i);
        }
    }

    await Promise.all(Array.from({ length: workers }, worker));
    return out;
}

async function runVTLookup() {
    _vtState = _vtStateLookup;
    _vtActiveResultsId = 'vtResults';
    _vtActiveNoteId = 'vtSelectedNote';
    _vtStatusMsgId = 'statusVT';

    const raw = document.getElementById('vtInput').value.trim();
    const btn = document.getElementById('vtRunBtn');
    clearStatus('statusVT');

    if (!raw) { setStatus('statusVT','⚠ Input tidak boleh kosong!','error'); return; }

    const lines = [...new Set(raw.split('\n').map(s=>s.trim()).filter(looksLikeIOC))];
    if (!lines.length) { setStatus('statusVT','⚠ Tidak ada IOC yang valid.','error'); return; }

    const resultsEl = document.getElementById('vtResults');
    btn.disabled = true;
    if (resultsEl) resultsEl.setAttribute('aria-busy', 'true');
    setStatus('statusVT', `<span class="spinner"></span> Scanning 0 / ${lines.length}…`, 'loading');

    try {
        let completed = 0;
        const lineResults = await vtMapPool(lines, VT_SCAN_CONCURRENCY, async (rawIoc) => {
            const [vtResult, corrResult] = await Promise.allSettled([
                vtGet(rawIoc),
                fetchCorrelation(rawIoc),
            ]);
            completed++;
            setStatus('statusVT', `<span class="spinner"></span> Progress: ${completed} / ${lines.length} IOC(s)…`, 'loading');
            return { rawIoc, vtResult, corrResult };
        });

        await renderScanBatch(lineResults);

        setStatus('statusVT', `✓ ${lines.length} IOC(s) scanned.`, 'success');

        if (historySaveEnabled()) {
            try { pushHistoryFromLineResults(raw, lineResults); } catch (e) {}
        }
        renderHistoryListDOM();
    } finally {
        btn.disabled = false;
        if (resultsEl) resultsEl.removeAttribute('aria-busy');
    }
}

function clearVT() {
    document.getElementById('vtInput').value = '';
    document.getElementById('vtResults').innerHTML = '<div class="vt-placeholder">Scan results will appear here...</div>';
    document.getElementById('vtResultCount').textContent = '';
    _vtStateLookup.items.length = 0;
    Object.assign(_vtStateLookup.filters, { clean: true, suspicious: true, malicious: true });
    if (_vtState === _vtStateLookup) vtUpdateSelectedNote();
    vtSyncFilterUIs();
    clearStatus('statusVT');
}

document.addEventListener('DOMContentLoaded', function() {
    try {
        const id = localStorage.getItem(LS_TAB);
        if (id && document.getElementById(id)) {
            const btn = document.querySelector('.tab-btn[data-tab="' + id + '"]');
            if (btn) openTab(id, btn);
        }
    } catch (e) {}

    const ht = document.getElementById('historySaveToggle');
    if (ht) {
        try {
            const s = localStorage.getItem(LS_HISTORY_SAVE);
            if (s === '0') ht.checked = false;
        } catch (e) {}
        ht.addEventListener('change', historyPersistSavePref);
    }
    renderHistoryListDOM();
    vtInitExportPresetUI();
    vtSyncFilterUIs();

    const vtInput = document.getElementById('vtInput');
    if (vtInput) {
        vtInput.addEventListener('keydown', function (ev) {
            const key = String(ev.key || '');
            if (key === 'Enter' && (ev.ctrlKey || ev.metaKey)) {
                const btn = document.getElementById('vtRunBtn');
                if (btn && btn.disabled) return;
                ev.preventDefault();
                runVTLookup();
                return;
            }
            if (key === 'Escape') {
                ev.preventDefault();
                clearVT();
            }
        });
    }

    const mergerTermsPreset = document.getElementById('mergerDbTermsPreset');
    if (mergerTermsPreset) {
        mergerTermsPreset.addEventListener('change', function () {
            mergerDbSyncTermsCustomVisibility();
            mergerDbRebuildOutputs(_mergerDbLastItems);
        });
        mergerDbSyncTermsCustomVisibility();
    }
    let mergerDbTermsTimer;
    const mergerTermsInp = document.getElementById('mergerDbTermsField');
    if (mergerTermsInp) {
        mergerTermsInp.addEventListener('input', function () {
            clearTimeout(mergerDbTermsTimer);
            mergerDbTermsTimer = setTimeout(function () {
                mergerDbRebuildOutputs(_mergerDbLastItems);
            }, 300);
        });
    }
    let mergerDbInputTimer;
    const mergerInp = document.getElementById('mergerDbItemsInput');
    if (mergerInp) {
        mergerInp.addEventListener('input', function () {
            clearTimeout(mergerDbInputTimer);
            mergerDbInputTimer = setTimeout(mergerDbUpdateInputPreview, 280);
        });
        mergerDbUpdateInputPreview();
    }

    // Auth init (passive): show YCCA-only UI when logged in, but don't prompt on load.
    try { authInit(); } catch (e) {}
});
