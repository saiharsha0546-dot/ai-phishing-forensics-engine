// Phishing Forensics Engine — frontend
'use strict';

// ---------- Helpers ----------
const $ = (id) => document.getElementById(id);

// Escape untrusted text (URLs, email headers, page titles) before inserting into HTML
function esc(v) {
    return String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Map a 0-100 probability to a verdict level
function level(p) {
    if (p >= 70) return 'high';
    if (p >= 35) return 'warn';
    return 'safe';
}
const LEVEL_TEXT = { high: 'High risk', warn: 'Suspicious', safe: 'Safe' };
const LEVEL_ICON = { high: 'gpp_bad', warn: 'warning', safe: 'verified_user' };
const LEVEL_COLOR = { high: '#c4320a', warn: '#f79009', safe: '#17b26a' };

function badgeHtml(p, label) {
    const l = level(p);
    return `<span class="badge ${l}"><span class="ms">${LEVEL_ICON[l]}</span>${esc(label || LEVEL_TEXT[l])}</span>`;
}

function setBadge(el, p, label) {
    const l = level(p);
    el.className = `badge ${l}`;
    el.innerHTML = `<span class="ms">${LEVEL_ICON[l]}</span>${esc(label || LEVEL_TEXT[l])}`;
}

function setScore(numEl, meterEl, p) {
    const l = level(p);
    numEl.textContent = `${p}%`;
    numEl.className = `num t-${l}`;
    meterEl.style.width = `${Math.max(2, Math.min(100, p))}%`;
    meterEl.style.background = LEVEL_COLOR[l];
}

function toast(msg, isError = false) {
    const t = document.createElement('div');
    t.className = `toast${isError ? ' err' : ''}`;
    t.textContent = msg;
    $('toasts').appendChild(t);
    setTimeout(() => t.remove(), 4500);
}

function setBusy(btn, busy, label) {
    if (busy) {
        btn.dataset.label = btn.innerHTML;
        btn.disabled = true;
        btn.innerHTML = `<span class="spinner"></span>${esc(label || 'Working…')}`;
    } else {
        btn.disabled = false;
        if (btn.dataset.label) btn.innerHTML = btn.dataset.label;
    }
}

async function postJSON(url, body) {
    const res = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}) });
    const data = await res.json().catch(() => ({ error: `Server returned ${res.status}` }));
    if (!res.ok && !data.error) data.error = `Server returned ${res.status}`;
    return data;
}

function timeAgo(ts) {
    const s = Math.round((Date.now() - ts) / 1000);
    if (s < 60) return 'just now';
    if (s < 3600) return `${Math.floor(s / 60)} min ago`;
    return `${Math.floor(s / 3600)} h ago`;
}

function findingsHtml(items, p) {
    const l = level(p);
    const icon = l === 'safe' ? 'check_circle' : 'error';
    return (items || []).map(t => `<li><span class="ms t-${l}">${icon}</span><span>${esc(t)}</span></li>`).join('');
}

function shapHtml(shap) {
    if (!shap) return '<div class="muted">No explanation available.</div>';
    const rows = [];
    (shap.positive_forces || []).forEach(f => rows.push({ name: f.name, v: Math.abs(f.contribution), pos: true }));
    (shap.negative_forces || []).forEach(f => rows.push({ name: f.name, v: Math.abs(f.contribution), pos: false }));
    if (!rows.length) return '<div class="muted">No strong drivers.</div>';
    rows.sort((a, b) => b.v - a.v);
    const max = Math.max(...rows.map(r => r.v), 1);
    return rows.slice(0, 7).map(r => `
        <div class="shap-row" title="${esc(r.name)}">
            <span class="name">${esc(r.name)}</span>
            <div class="shap-track"><span style="width:${(r.v / max) * 100}%;background:${r.pos ? LEVEL_COLOR.high : LEVEL_COLOR.safe}"></span></div>
            <span class="val ${r.pos ? 't-high' : 't-safe'}">${r.pos ? '+' : '−'}${r.v}%</span>
        </div>`).join('');
}

// ---------- Navigation ----------
const PAGE_TITLES = {
    overview: 'Overview', url: 'URL scanner', email: 'Email analyzer', inbox: 'Inbox scan',
    history: 'Browser history', network: 'Network monitor', password: 'Password breach check'
};

function showPage(name) {
    if (!PAGE_TITLES[name]) name = 'overview';
    document.querySelectorAll('.page').forEach(p => p.classList.toggle('hidden', p.id !== `page-${name}`));
    document.querySelectorAll('.nav-link').forEach(n => n.classList.toggle('active', n.dataset.page === name));
    $('page-title').textContent = PAGE_TITLES[name];
    document.body.classList.remove('nav-open');
    if (location.hash !== `#${name}`) history.replaceState(null, '', `#${name}`);
    window.scrollTo(0, 0);
    if (name === 'overview' && map) setTimeout(() => map.invalidateSize(), 50);
}

function initNav() {
    document.querySelectorAll('.nav-link').forEach(n => n.addEventListener('click', () => showPage(n.dataset.page)));
    document.querySelectorAll('[data-goto]').forEach(b => b.addEventListener('click', () => showPage(b.dataset.goto)));
    try { if (localStorage.getItem('sidebarCollapsed') === '1') document.body.classList.add('sidebar-collapsed'); } catch { /* storage unavailable */ }
    $('menu-btn').addEventListener('click', () => {
        if (window.innerWidth <= 860) {
            document.body.classList.toggle('nav-open');
            return;
        }
        const collapsed = document.body.classList.toggle('sidebar-collapsed');
        try { localStorage.setItem('sidebarCollapsed', collapsed ? '1' : '0'); } catch { /* storage unavailable */ }
        setTimeout(() => { if (map) map.invalidateSize(); if (netChart) netChart.resize(); }, 250);
    });
    $('scrim').addEventListener('click', () => document.body.classList.remove('nav-open'));
    showPage(location.hash.slice(1) || 'overview');
}

// ---------- Session activity (real data only) ----------
const activity = [];
const KIND_ICON = { url: 'link', email: 'mail', inbox: 'inbox', history: 'history', network: 'lan' };
const KIND_TEXT = { url: 'URL scan', email: 'Email', inbox: 'Inbox', history: 'Browser history', network: 'Network' };

function recordActivity(kind, target, probability, geo) {
    activity.unshift({ kind, target: String(target || ''), p: Number(probability) || 0, ts: Date.now() });
    if (geo) addMapMarker(geo, target, probability);
    renderOverview();
}

function renderOverview() {
    const counts = { high: 0, warn: 0, safe: 0 };
    activity.forEach(a => counts[level(a.p)]++);
    const total = activity.length;
    $('stat-total').textContent = total;
    $('stat-high').textContent = counts.high;
    $('stat-warn').textContent = counts.warn;
    $('stat-safe').textContent = counts.safe;

    const bars = $('mix-bar').children;
    ['high', 'warn', 'safe'].forEach((k, i) => {
        const pct = total ? Math.round((counts[k] / total) * 100) : 0;
        bars[i].style.width = `${pct}%`;
        $(`mix-${k}`).textContent = `${pct}%`;
    });

    $('feed-count').textContent = total ? `${total} item${total === 1 ? '' : 's'} this session` : 'No scans yet';
    $('feed-empty').classList.toggle('hidden', total > 0);
    const feed = $('activity-feed');
    feed.innerHTML = '';
    activity.slice(0, 8).forEach(a => {
        const li = document.createElement('li');
        const l = level(a.p);
        li.innerHTML = `
            <div class="kind"><span class="ms sm">${KIND_ICON[a.kind] || 'search'}</span></div>
            <div class="target"><div title="${esc(a.target)}">${esc(a.target)}</div><div>${KIND_TEXT[a.kind] || ''} · ${timeAgo(a.ts)}</div></div>
            ${badgeHtml(a.p)}
            <div class="score t-${l}">${a.p}%</div>`;
        if (a.kind !== 'email' && a.kind !== 'inbox') {
            li.style.cursor = 'pointer';
            li.title = 'Open full URL report';
            li.addEventListener('click', () => inspectUrl(a.target));
        }
        feed.appendChild(li);
    });
}

// ---------- Map ----------
let map = null, mapLayer = null;
function initMap() {
    if (typeof L === 'undefined' || !$('threatMap')) return;
    map = L.map('threatMap', { center: [25, 10], zoom: 1, minZoom: 1, worldCopyJump: true, zoomControl: true, attributionControl: true });
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', { maxZoom: 18, attribution: '&copy; OpenStreetMap' }).addTo(map);
    mapLayer = L.layerGroup().addTo(map);
    setTimeout(() => map.invalidateSize(), 300);
}

function addMapMarker(geo, label, p) {
    if (!map || !geo || geo.lat == null || geo.lon == null) return;
    const l = level(p);
    const icon = L.divIcon({ className: '', html: `<div class="map-dot ${l}"></div>`, iconSize: [14, 14], iconAnchor: [7, 7] });
    const place = [geo.city, geo.country].filter(Boolean).join(', ');
    L.marker([geo.lat, geo.lon], { icon }).addTo(mapLayer)
        .bindTooltip(`<b>${esc(LEVEL_TEXT[l])} · ${esc(p)}%</b><br>${esc(String(label).slice(0, 60))}${place ? `<br>${esc(place)}` : ''}`);
    const layers = mapLayer.getLayers();
    if (layers.length > 60) mapLayer.removeLayer(layers[0]);
}

// ---------- URL scanner ----------
function inspectUrl(url) {
    showPage('url');
    $('url-input').value = url;
    analyzeUrl();
}

async function analyzeUrl() {
    const url = $('url-input').value.trim();
    if (!url) { toast('Enter a URL to analyze.', true); return; }
    const btn = $('url-btn');
    setBusy(btn, true, 'Analyzing…');
    try {
        const data = await postJSON('/api/analyze/url', { url });
        if (data.error) { toast(data.error, true); return; }
        const p = data.probability;
        $('url-empty').classList.add('hidden');
        $('url-result').classList.remove('hidden');
        setBadge($('url-badge'), p, data.risk_level);
        $('url-target').textContent = data.url;
        setScore($('url-score'), $('url-meter'), p);
        $('url-findings').innerHTML = findingsHtml(data.risk_factors, p);

        const f = data.features || {};
        $('sig-age').textContent = typeof f.domain_age_days === 'number' ? `${f.domain_age_days} days` : (f.domain_age_days || 'Unknown');
        $('sig-https').textContent = f.is_https ? 'Yes' : 'No';
        $('sig-ip').textContent = f.has_ip ? 'Yes' : 'No';
        $('sig-sub').textContent = f.subdomain_count ?? '–';
        $('sig-kw').textContent = f.suspicious_keywords_count ?? '–';
        $('sig-ent').textContent = f.entropy ?? '–';

        const g = data.geo || {};
        const place = [g.city, g.country].filter(Boolean).join(', ');
        $('url-geo').textContent = place ? `${place}${g.asn ? ` · ${g.asn}` : ''}` : 'Unknown';

        $('url-shap').innerHTML = shapHtml(data.shap);

        const vt = data.virustotal;
        if (vt && vt.status === 'success') {
            const vp = vt.positives > 0 ? 80 : 0;
            $('url-vt').innerHTML = `<div class="vt"><span class="num t-${level(vp)}">${esc(vt.positives)} / ${esc(vt.total)}</span><span>security vendors flagged this URL</span></div>`;
        } else {
            $('url-vt').textContent = (vt && vt.message) || 'Not checked.';
        }
        recordActivity('url', data.url, p, data.geo);
    } catch (err) {
        toast(`Couldn't reach the analysis engine: ${err.message}`, true);
    } finally {
        setBusy(btn, false);
    }
}

// ---------- Email analyzer ----------
async function loadSamples() {
    const list = $('sample-list');
    try {
        const data = await (await fetch('/api/samples')).json();
        list.innerHTML = '';
        (data.samples || []).forEach(s => {
            const isPhish = s.type === 'Phishing';
            const b = document.createElement('button');
            b.className = 'sample';
            b.innerHTML = `<span class="ms sm ${isPhish ? 't-high' : 't-safe'}">${isPhish ? 'report' : 'mark_email_read'}</span>
                <span class="name">${esc(s.title)}</span>${badgeHtml(isPhish ? 90 : 0, isPhish ? 'Phishing' : 'Legitimate')}`;
            b.addEventListener('click', () => analyzeEmail({ raw_email: s.content, filename: s.name }));
            list.appendChild(b);
        });
        if (!list.children.length) list.innerHTML = '<span class="muted">No samples available.</span>';
    } catch {
        list.innerHTML = '<span class="muted">Couldn\'t load samples.</span>';
    }
}

async function analyzeEmail(payload) {
    $('email-empty').classList.add('hidden');
    $('email-result').classList.remove('hidden');
    $('email-name').textContent = `${payload.filename || 'Email'} — analyzing…`;
    try {
        let data;
        if (payload.file) {
            const fd = new FormData();
            fd.append('file', payload.file);
            const res = await fetch('/api/analyze/email', { method: 'POST', body: fd });
            data = await res.json();
        } else {
            data = await postJSON('/api/analyze/email', payload);
        }
        if (data.error) { toast(data.error, true); return; }
        renderEmail(data);
    } catch (err) {
        toast(`Email analysis failed: ${err.message}`, true);
    }
}

function renderEmail(d) {
    const p = d.probability;
    const h = d.headers_summary || {};
    const f = d.features || {};
    setBadge($('email-badge'), p, d.risk_level);
    $('email-name').textContent = d.filename;
    setScore($('email-score'), $('email-meter'), p);

    const authCls = v => v === 'PASS' ? 't-safe' : (v === 'FAIL' || v === 'SOFTFAIL' ? 't-high' : '');
    $('em-spf').textContent = h.SPF; $('em-spf').className = authCls(h.SPF);
    $('em-dkim').textContent = h.DKIM; $('em-dkim').className = authCls(h.DKIM);
    $('em-hops').textContent = h.Received_Count;
    $('em-urgency').textContent = f.urgency_score;
    $('em-from').textContent = h.From;
    $('em-return').textContent = h['Return-Path'];
    $('em-subject').textContent = h.Subject;
    $('em-ips').textContent = (f.received_ips || []).join(', ') || 'None found';
    $('email-findings').innerHTML = findingsHtml(d.threat_indicators, p);
    $('email-shap').innerHTML = shapHtml(d.shap);
    $('em-body').textContent = d.body_preview || 'No readable plain-text body.';
    recordActivity('email', h.Subject && h.Subject !== 'N/A' ? h.Subject : d.filename, p, d.geo);
}

function initEmail() {
    const input = $('eml-input');
    const dz = $('dropzone');
    input.addEventListener('change', () => { if (input.files[0]) analyzeEmail({ file: input.files[0], filename: input.files[0].name }); input.value = ''; });
    ['dragenter', 'dragover'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.add('drag'); }));
    ['dragleave', 'drop'].forEach(ev => dz.addEventListener(ev, e => { e.preventDefault(); dz.classList.remove('drag'); }));
    dz.addEventListener('drop', e => { const file = e.dataTransfer.files[0]; if (file) analyzeEmail({ file, filename: file.name }); });
    loadSamples();
}

// ---------- Inbox scan ----------
async function scanInbox(e) {
    e.preventDefault();
    const email = $('imap-email').value.trim();
    const password = $('imap-password').value;
    if (!email || !password) { toast('Enter the email address and app password.', true); return; }
    const out = $('imap-results');
    const btn = $('imap-btn');
    setBusy(btn, true, 'Connecting…');
    out.innerHTML = '<div class="empty"><span class="spinner"></span><p style="margin-top:10px">Connecting to the mail server…</p></div>';
    $('imap-count').textContent = '';
    try {
        const data = await postJSON('/api/analyze/imap', { email, password, server: $('imap-server').value.trim(), limit: $('imap-limit').value });
        if (data.error) {
            out.innerHTML = `<div class="empty"><span class="ms t-high">error</span><h4>Couldn't scan the inbox</h4><p>${esc(data.error)}</p></div>`;
            return;
        }
        const results = data.results || [];
        $('imap-count').textContent = `${results.length} message${results.length === 1 ? '' : 's'}`;
        if (!results.length) { out.innerHTML = '<div class="empty"><span class="ms">inbox</span><h4>No messages found</h4></div>'; return; }
        out.innerHTML = '';
        results.forEach(r => {
            const card = document.createElement('div');
            card.className = 'mail-card';
            card.innerHTML = `
                <div class="top"><h4 title="${esc(r.subject)}">${esc(r.subject)}</h4>${badgeHtml(r.probability, r.risk_level)}</div>
                <div class="meta">${esc(r.from)}${r.date ? ` · ${esc(r.date)}` : ''} · <b class="t-${level(r.probability)}">${esc(r.probability)}%</b></div>
                ${(r.threat_indicators || []).length ? `<ul class="findings">${findingsHtml(r.threat_indicators, r.probability)}</ul>` : ''}`;
            out.appendChild(card);
            recordActivity('inbox', r.subject, r.probability);
        });
    } catch (err) {
        out.innerHTML = `<div class="empty"><span class="ms t-high">error</span><h4>Scan failed</h4><p>${esc(err.message)}</p></div>`;
    } finally {
        setBusy(btn, false);
        $('imap-password').value = '';
    }
}

// ---------- Password check ----------
async function checkPassword(e) {
    e.preventDefault();
    const pw = $('pw-input').value;
    const out = $('pw-result');
    if (!pw) { toast('Enter a password to check.', true); return; }
    const btn = $('pw-btn');
    setBusy(btn, true, 'Checking…');
    try {
        const data = await postJSON('/api/analyze/password', { password: pw });
        if (data.error) {
            out.innerHTML = `<div class="result-banner high"><span class="ms">error</span><div>${esc(data.error)}</div></div>`;
        } else if (data.found) {
            out.innerHTML = `<div class="result-banner high"><span class="ms">gpp_bad</span><div>This password has been exposed<div class="sub">Seen ${Number(data.count).toLocaleString()} times in known breaches. Don't use it anywhere.</div></div></div>`;
        } else {
            out.innerHTML = `<div class="result-banner safe"><span class="ms">verified_user</span><div>Not found in known breaches<div class="sub">That doesn't guarantee it's strong. Use a long, unique password.</div></div></div>`;
        }
    } catch (err) {
        out.innerHTML = `<div class="result-banner high"><span class="ms">error</span><div>Couldn't reach the breach service.</div></div>`;
    } finally {
        setBusy(btn, false);
        $('pw-input').value = '';
    }
}

// ---------- Browser extension bridge ----------
const LIVE_SOURCE_MAP = { live_all: 'SOC_GET_COMBINED', live_tabs: 'SOC_GET_LIVE_TABS', live_history: 'SOC_GET_HISTORY' };

const SOCExt = {
    ready: false, version: null, browser: null, _pending: new Map(), _seq: 0,
    request(type, extra = {}, timeoutMs = 25000) {
        return new Promise((resolve) => {
            const requestId = `soc-${Date.now()}-${++this._seq}`;
            const timer = setTimeout(() => {
                if (this._pending.has(requestId)) { this._pending.delete(requestId); resolve({ ok: false, error: 'Extension did not respond.' }); }
            }, timeoutMs);
            this._pending.set(requestId, (response) => { clearTimeout(timer); resolve(response); });
            window.postMessage(Object.assign({ target: 'soc-extension', type, requestId }, extra), window.location.origin);
        });
    },
    _resolve(requestId, response) {
        const cb = this._pending.get(requestId);
        if (!cb) return;
        this._pending.delete(requestId);
        cb(response);
    },
    async detect() {
        const res = await this.request('SOC_PING', {}, 4000);
        this.ready = !!(res && res.ok && res.isEnabled);
        if (this.ready) {
            this.version = res.version;
            this.browser = res.browser;
            this.request('SOC_SET_BACKEND', { origin: window.location.origin }, 4000);
        }
        $('ext-dot').classList.toggle('on', this.ready);
        $('ext-status').textContent = this.ready ? `Extension connected (v${this.version})` : 'Extension not installed';
        return this.ready;
    }
};

window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== 'soc-extension') return;
    if (data.type === 'SOC_RESPONSE') { SOCExt._resolve(data.requestId, data.response); return; }
    if (data.type === 'SOC_EXT_READY') { if (!SOCExt.ready) SOCExt.detect(); return; }
    if (data.payload) handleTraffic([data.payload]);
});

// ---------- Browser history ----------
let historyData = [];
let historySortDesc = true;

function setHistoryMessage(msg) {
    $('history-body').innerHTML = `<tr><td colspan="7" class="empty-cell">${esc(msg)}</td></tr>`;
}

async function loadHistory() {
    const source = $('history-source').value;
    let requestType = LIVE_SOURCE_MAP[source];
    const autoLive = !requestType && source === 'all';
    const btn = $('history-scan');
    setBusy(btn, true, 'Scanning…');
    try {
        if (autoLive) {
            if (!SOCExt.ready) await SOCExt.detect();
            if (SOCExt.ready) requestType = 'SOC_GET_COMBINED';
        }
        if (requestType) {
            setHistoryMessage('Reading tabs and history from the extension…');
            if (!SOCExt.ready) await SOCExt.detect();
            if (SOCExt.ready) {
                const res = await SOCExt.request(requestType, { limit: 45, days: 14 });
                if (res && res.ok) { applyHistory(res.history || []); return; }
                if (!autoLive) { setHistoryMessage(`Extension capture failed: ${(res && res.error) || 'unknown error'}`); return; }
            } else if (!autoLive) {
                setHistoryMessage('Browser extension not detected. Load it from chrome://extensions and try again.');
                return;
            }
        }
        setHistoryMessage('Scanning history…');
        const serverBrowser = LIVE_SOURCE_MAP[source] ? 'all' : source;
        const data = await (await fetch(`/api/history?browser=${encodeURIComponent(serverBrowser)}&limit=45`)).json();
        if (data.error) { setHistoryMessage(data.error); return; }
        applyHistory(data.history || []);
    } catch (err) {
        setHistoryMessage(`History scan failed: ${err.message}`);
    } finally {
        setBusy(btn, false);
    }
}

function applyHistory(items) {
    historyData = items;
    let worst = null;
    items.forEach(it => {
        recordActivity('history', it.url, it.probability, it.geo);
        if (it.probability >= 70 && (!worst || it.probability > worst.probability)) worst = it;
    });
    renderHistory();
    if (worst) showRiskModal(worst);
}

function renderHistory() {
    const q = $('history-filter').value.trim().toLowerCase();
    const rows = historyData.filter(it => !q || (it.url || '').toLowerCase().includes(q) || (it.title || '').toLowerCase().includes(q));
    const body = $('history-body');
    if (!historyData.length) { setHistoryMessage('No history entries found.'); return; }
    if (!rows.length) { setHistoryMessage('No entries match your filter.'); return; }
    body.innerHTML = '';
    rows.forEach(it => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${badgeHtml(it.probability)}</td>
            <td class="num t-${level(it.probability)}">${esc(it.probability)}%</td>
            <td><div class="url" title="${esc(it.url)}">${esc(it.url)}</div></td>
            <td><div class="clip" title="${esc(it.title)}">${esc(it.title)}</div></td>
            <td class="muted">${esc(it.source)}</td>
            <td class="muted" style="white-space:nowrap">${esc(it.time)}</td>
            <td><button class="btn btn-sm">Inspect</button></td>`;
        tr.querySelector('button').addEventListener('click', () => inspectUrl(it.url));
        body.appendChild(tr);
    });
}

function showRiskModal(item) {
    $('risk-url').textContent = item.url;
    $('risk-title').textContent = item.title || '—';
    $('risk-inspect').onclick = () => { hideRiskModal(); inspectUrl(item.url); };
    $('risk-modal').classList.remove('hidden');
}
function hideRiskModal() { $('risk-modal').classList.add('hidden'); }

// ---------- Network monitor ----------
let netChart = null;
let liveTimer = null;
let netRows = 0;

function initNetChart() {
    if (typeof Chart === 'undefined' || !$('net-chart')) return;
    netChart = new Chart($('net-chart'), {
        type: 'bar',
        data: {
            labels: [],
            datasets: [
                { label: 'Flagged', data: [], backgroundColor: LEVEL_COLOR.high, borderRadius: 4, borderSkipped: 'bottom', maxBarThickness: 28 },
                { label: 'Normal', data: [], backgroundColor: LEVEL_COLOR.safe, borderRadius: 4, borderSkipped: 'bottom', maxBarThickness: 28 }
            ]
        },
        options: {
            responsive: true, maintainAspectRatio: false,
            interaction: { mode: 'index', intersect: false },
            scales: {
                x: { stacked: true, grid: { display: false }, ticks: { color: '#667085' } },
                y: { stacked: true, beginAtZero: true, grid: { color: '#eef0f3' }, border: { display: false }, ticks: { color: '#667085', precision: 0 } }
            },
            plugins: { legend: { display: false }, tooltip: { backgroundColor: '#101828', padding: 10 } }
        }
    });
}

function setNetStatus(text, on) {
    $('net-status').textContent = text;
    $('net-dot').classList.toggle('on', !!on);
}

function handleTraffic(items) {
    const body = $('net-body');
    if (netRows === 0) body.innerHTML = '';
    items.forEach(pkt => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${badgeHtml(pkt.probability)}</td>
            <td class="num t-${level(pkt.probability)}">${esc(pkt.probability)}%</td>
            <td><div class="url" title="${esc(pkt.uri)}">${esc(pkt.uri)}</div></td>
            <td><button class="btn btn-sm">Inspect</button></td>`;
        tr.querySelector('button').addEventListener('click', () => inspectUrl(pkt.uri));
        body.insertBefore(tr, body.firstChild);
        netRows++;
        if (body.children.length > 60) body.removeChild(body.lastChild);
        recordActivity('network', pkt.uri, pkt.probability, pkt.geo);
    });
    $('net-count').textContent = `${netRows} total`;
}

function pushNetPoint(items) {
    if (!netChart) return;
    const flagged = items.filter(x => x.probability >= 35).length;
    const label = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
    netChart.data.labels.push(label);
    netChart.data.datasets[0].data.push(flagged);
    netChart.data.datasets[1].data.push(items.length - flagged);
    if (netChart.data.labels.length > 10) {
        netChart.data.labels.shift();
        netChart.data.datasets.forEach(d => d.data.shift());
    }
    netChart.update();
}

async function runCapture(timeout) {
    const data = await postJSON('/api/sniff', { timeout });
    if (data.error) throw new Error(data.error);
    const traffic = data.traffic || [];
    return { traffic, mode: data.mode };
}

async function startCapture() {
    const btn = $('net-capture');
    const secs = $('net-duration').value;
    setBusy(btn, true, `Capturing ${secs}s…`);
    setNetStatus('Capturing…', true);
    try {
        const { traffic, mode } = await runCapture(secs);
        handleTraffic([...traffic].reverse());
        pushNetPoint(traffic);
        setNetStatus(`Done · ${traffic.length} destinations${mode ? ` · ${mode}` : ''}`, false);
    } catch (err) {
        setNetStatus('Capture failed', false);
        toast(err.message, true);
    } finally {
        setBusy(btn, false);
    }
}

function toggleLive() {
    const btn = $('net-live');
    if (liveTimer) {
        clearInterval(liveTimer);
        liveTimer = null;
        btn.innerHTML = '<span class="ms sm">stream</span>Live mode';
        setNetStatus('Live mode stopped', false);
        return;
    }
    btn.innerHTML = '<span class="ms sm">stop_circle</span>Stop live mode';
    setNetStatus('Live mode running', true);
    const tick = async () => {
        try {
            const { traffic } = await runCapture(1.2);
            const slice = traffic.slice(0, 3);
            if (slice.length) { handleTraffic(slice); pushNetPoint(slice); }
        } catch { /* keep polling */ }
    };
    tick();
    liveTimer = setInterval(tick, 3000);
}

// ---------- Retrain ----------
async function retrain() {
    const btn = $('btn-retrain');
    setBusy(btn, true, 'Retraining…');
    try {
        const data = await postJSON('/api/retrain');
        if (data.error) toast(data.error, true);
        else toast('Models retrained.');
    } catch (err) {
        toast(`Retraining failed: ${err.message}`, true);
    } finally {
        setBusy(btn, false);
    }
}

// ---------- Boot ----------
document.addEventListener('DOMContentLoaded', () => {
    const safe = (fn, name) => { try { fn(); } catch (e) { console.warn(`${name} init failed:`, e); } };
    safe(initMap, 'Map');
    safe(initNav, 'Navigation');
    safe(initEmail, 'Email');
    safe(initNetChart, 'Network chart');
    safe(renderOverview, 'Overview');

    $('quick-form').addEventListener('submit', e => {
        e.preventDefault();
        const u = $('quick-url').value.trim();
        if (!u) { toast('Paste a URL to scan.', true); return; }
        $('quick-url').value = '';
        inspectUrl(u);
    });
    $('url-form').addEventListener('submit', e => { e.preventDefault(); analyzeUrl(); });
    document.querySelectorAll('[data-example]').forEach(b => b.addEventListener('click', () => { $('url-input').value = b.dataset.example; analyzeUrl(); }));
    $('imap-form').addEventListener('submit', scanInbox);
    $('pw-form').addEventListener('submit', checkPassword);
    $('history-scan').addEventListener('click', loadHistory);
    $('history-filter').addEventListener('input', renderHistory);
    $('history-sort').addEventListener('click', () => {
        historySortDesc = !historySortDesc;
        historyData.sort((a, b) => historySortDesc ? b.probability - a.probability : a.probability - b.probability);
        renderHistory();
    });
    $('net-capture').addEventListener('click', startCapture);
    $('net-live').addEventListener('click', toggleLive);
    $('btn-retrain').addEventListener('click', retrain);
    $('risk-dismiss').addEventListener('click', hideRiskModal);
    $('risk-modal').addEventListener('click', e => { if (e.target.id === 'risk-modal') hideRiskModal(); });
    document.addEventListener('keydown', e => { if (e.key === 'Escape') hideRiskModal(); });

    SOCExt.detect();
    setInterval(renderOverview, 60000); // keep "x min ago" fresh
});
