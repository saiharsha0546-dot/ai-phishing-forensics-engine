// Next-Gen SOC Forensics Workbench Logic (Tailwind Edition)
let urlChartInstance = null;
let snifferChartInstance = null;

// Upgrade Globals
let socket = null;
let isStreamingSniff = false;
let threatMapInstance = null;
let mapMarkersLayer = null;
let liveThreatsCount = 0;
let liveSafeCount = 0;
let liveTotalCount = 0;
let rawHistoryData = [];
let historySortDesc = true;

document.addEventListener('DOMContentLoaded', () => {
    try { initUrlChart(); } catch (e) { console.warn("Chart init error:", e); }
    try { initSnifferChart(); } catch (e) { console.warn("Sniffer chart init error:", e); }
    try { loadSampleEmailsList(); } catch (e) { console.warn("Samples load error:", e); }
    try { initThreatMap(); } catch (e) { console.warn("Threat map init error:", e); }
    try { initSocketIO(); } catch (e) { console.warn("Socket.IO init error:", e); }
    try { initTabs(); } catch (e) { console.warn("Tabs init error:", e); }
    try { initKeyboardShortcuts(); } catch (e) { console.warn("Shortcuts init error:", e); }
});

// --- Tab Logic ---
function initTabs() {
    const tabs = document.querySelectorAll('.tab-btn');
    tabs.forEach(tab => {
        tab.addEventListener('click', (e) => {
            e.preventDefault();
            switchTab(tab.getAttribute('data-target'), tab);
        });
    });
}

function switchTab(targetId, tabElement = null) {
    document.querySelectorAll('.tab-pane').forEach(pane => {
        pane.classList.remove('block');
        pane.classList.add('hidden');
    });
    
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.classList.remove('bg-surface-variant/50', 'text-cyber-lime', 'border-l-4', 'border-cyber-lime');
    });

    const target = document.getElementById(targetId);
    if (target) {
        target.classList.remove('hidden');
        target.classList.add('block');
    }
    
    if (tabElement) {
        tabElement.classList.add('bg-surface-variant/50', 'text-cyber-lime', 'border-l-4', 'border-cyber-lime');
        const textElement = tabElement.querySelector('.font-label-caps');
        if (textElement) {
            document.getElementById('breadcrumb-current').innerText = textElement.innerText;
        }
    } else {
        const matchingBtn = document.querySelector(`.tab-btn[data-target="${targetId}"]`);
        if (matchingBtn) {
            matchingBtn.classList.add('bg-surface-variant/50', 'text-cyber-lime', 'border-l-4', 'border-cyber-lime');
            const textElement = matchingBtn.querySelector('.font-label-caps');
            if (textElement) {
                document.getElementById('breadcrumb-current').innerText = textElement.innerText;
            }
        }
    }
    
    // Invalidate map size if dashboard is shown
    if (targetId === 'pane-dashboard' && threatMapInstance) {
        setTimeout(() => threatMapInstance.invalidateSize(), 100);
    }
}

// --- Chart Initialization ---
function initUrlChart() {
    const ctx = document.getElementById('urlFeatureChart');
    if (!ctx || typeof Chart === 'undefined') return;
    
    urlChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Length/10', 'Digits', 'Subdomains', 'IP Flag', 'Keywords', 'Entropy'],
            datasets: [{
                label: 'Feature Intensity',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: 'rgba(50, 255, 126, 0.4)',
                borderColor: '#32FF7E',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#bacbb8' } },
                x: { grid: { display: false }, ticks: { color: '#bacbb8' } }
            },
            plugins: { legend: { display: false } }
        }
    });
}

function initSnifferChart() {
    const ctx = document.getElementById('snifferTimelineChart');
    if (!ctx || typeof Chart === 'undefined') return;
    
    snifferChartInstance = new Chart(ctx, {
        type: 'line',
        data: {
            labels: ['T-40s', 'T-30s', 'T-20s', 'T-10s', 'Now'],
            datasets: [
                {
                    label: 'DNS Lookups',
                    data: [12, 19, 8, 24, 15],
                    borderColor: '#32FF7E',
                    backgroundColor: 'rgba(50, 255, 126, 0.15)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'HTTP URIs',
                    data: [5, 9, 3, 14, 7],
                    borderColor: '#FF3F34',
                    backgroundColor: 'rgba(255, 63, 52, 0.15)',
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#bacbb8' } },
                x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#bacbb8' } }
            },
            plugins: { legend: { labels: { color: '#dbe6d7' } } }
        }
    });
}

// --- URL Forensics ---
function setAndAnalyzeUrl(presetUrl) {
    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = presetUrl;
    analyzeUrl();
}

async function analyzeUrl() {
    const urlInputElem = document.getElementById('url-input');
    const urlInput = urlInputElem ? urlInputElem.value.trim() : "";
    if (!urlInput) {
        alert("Please enter a target URL to analyze.");
        return;
    }

    document.getElementById('url-empty-state').classList.add('hidden');
    document.getElementById('url-report-content').classList.remove('hidden');
    document.getElementById('url-display-target').innerHTML = `Analyzing: <span class="text-cyber-lime">${urlInput}</span>`;
    document.getElementById('url-prob-score').innerText = "...";

    try {
        const response = await fetch('/api/analyze/url', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url: urlInput })
        });
        const data = await response.json();
        if (data.error) {
            alert("Error: " + data.error);
            return;
        }

        const badge = document.getElementById('url-risk-badge');
        badge.innerText = data.risk_level;
        
        let colorClass = 'text-cyber-lime';
        let bgClass = 'bg-primary-container/20';
        let borderClass = 'border-cyber-lime/20';
        if (data.probability >= 70) {
            colorClass = 'text-neon-crimson';
            bgClass = 'bg-error-container/20';
            borderClass = 'border-neon-crimson/20';
        } else if (data.probability >= 35) {
            colorClass = 'text-warning-amber';
            bgClass = 'bg-surface-variant';
            borderClass = 'border-warning-amber/20';
        }
        
        badge.className = `px-3 py-1 rounded font-label-caps text-label-caps ${bgClass} ${colorClass} border ${borderClass}`;
        document.getElementById('url-display-target').innerText = data.url;
        
        const scoreElem = document.getElementById('url-prob-score');
        scoreElem.innerText = data.probability + "%";
        scoreElem.className = `font-headline-lg text-headline-lg ${colorClass}`;

        document.getElementById('url-feat-age').innerText = typeof data.features.domain_age_days === 'number' ? `${data.features.domain_age_days} Days` : data.features.domain_age_days;
        document.getElementById('url-feat-ip').innerText = data.features.has_ip ? "YES" : "No";
        document.getElementById('url-feat-sub').innerText = `${data.features.subdomain_count}`;
        document.getElementById('url-feat-entropy').innerText = data.features.entropy;
        document.getElementById('url-feat-kw').innerText = `${data.features.suspicious_keywords_count}`;
        document.getElementById('url-feat-https').innerText = data.features.is_https ? "Yes" : "No";

        const factorsList = document.getElementById('url-risk-factors-list');
        factorsList.innerHTML = "";
        data.risk_factors.forEach(rf => {
            const li = document.createElement('li');
            li.innerHTML = `<span class="material-symbols-outlined text-xs align-middle mr-1 ${colorClass}">warning</span> ${rf}`;
            factorsList.appendChild(li);
        });

        if (data.shap) renderShapBars('url-shap-container', 'url-shap-bars', data.shap);
        if (data.geo) addGeoMarker(data.geo, data.url, data.probability, true);
        updateLiveCounters(data.probability >= 35);

        if (urlChartInstance) {
            urlChartInstance.data.datasets[0].data = [
                Math.min(20, Math.round(data.features.url_length / 10)),
                data.features.digit_count,
                data.features.subdomain_count * 2,
                data.features.has_ip ? 15 : 0,
                data.features.suspicious_keywords_count * 4,
                data.features.entropy
            ];
            const rgbColor = data.probability >= 70 ? '255,63,52' : (data.probability >= 35 ? '255,159,26' : '50,255,126');
            urlChartInstance.data.datasets[0].borderColor = `rgb(${rgbColor})`;
            urlChartInstance.data.datasets[0].backgroundColor = `rgba(${rgbColor}, 0.4)`;
            urlChartInstance.update();
        }
    } catch (err) {
        alert("Failed to communicate with Forensics engine: " + err);
    }
}

// --- Email Forensics ---
async function loadSampleEmailsList() {
    const listElem = document.getElementById('sample-emails-list');
    try {
        const response = await fetch('/api/samples');
        const data = await response.json();
        listElem.innerHTML = "";
        data.samples.forEach(s => {
            const btn = document.createElement('button');
            const isPhish = s.type === 'Phishing';
            btn.className = `w-full flex items-center justify-between p-3 border border-glass-stroke rounded hover:bg-surface-variant transition-colors text-left`;
            btn.innerHTML = `
                <div class="truncate">
                    <span class="material-symbols-outlined text-sm align-middle mr-2 ${isPhish ? 'text-neon-crimson' : 'text-cyber-lime'}">${isPhish ? 'bug_report' : 'check_circle'}</span>
                    <span class="text-on-surface">${s.title}</span>
                </div>
                <span class="px-2 py-0.5 text-xs rounded ${isPhish ? 'bg-error-container/20 text-neon-crimson border border-error/20' : 'bg-primary-container/20 text-cyber-lime border border-cyber-lime/20'}">${s.type}</span>
            `;
            btn.onclick = () => analyzeRawEmailText(s.content, s.name);
            listElem.appendChild(btn);
        });
    } catch (err) {
        listElem.innerHTML = `<span class="text-neon-crimson">Failed to load samples.</span>`;
    }
}

async function handleFileUpload(files) {
    if (!files || files.length === 0) return;
    const file = files[0];
    const formData = new FormData();
    formData.append('file', file);

    document.getElementById('email-empty-state').classList.add('hidden');
    document.getElementById('email-report-content').classList.remove('hidden');
    document.getElementById('email-display-name').innerText = file.name + " (Analyzing...)";

    try {
        const response = await fetch('/api/analyze/email', { method: 'POST', body: formData });
        const data = await response.json();
        if (data.error) { alert("Error: " + data.error); return; }
        renderEmailReport(data);
    } catch (err) { alert("Upload error: " + err); }
}

async function analyzeRawEmailText(rawContent, filename = "Sample Email") {
    document.getElementById('email-empty-state').classList.add('hidden');
    document.getElementById('email-report-content').classList.remove('hidden');
    document.getElementById('email-display-name').innerText = filename + " (Analyzing...)";

    try {
        const response = await fetch('/api/analyze/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_email: rawContent })
        });
        const data = await response.json();
        if (data.error) { alert("Error: " + data.error); return; }
        renderEmailReport(data);
    } catch (err) { alert("Analysis error: " + err); }
}

function renderEmailReport(data) {
    document.getElementById('email-display-name').innerText = data.filename;
    
    const badge = document.getElementById('email-risk-badge');
    badge.innerText = data.risk_level;
    let colorClass = 'text-cyber-lime';
    let bgClass = 'bg-primary-container/20';
    let borderClass = 'border-cyber-lime/20';
    if (data.probability >= 70) {
        colorClass = 'text-neon-crimson';
        bgClass = 'bg-error-container/20';
        borderClass = 'border-neon-crimson/20';
    } else if (data.probability >= 35) {
        colorClass = 'text-warning-amber';
        bgClass = 'bg-surface-variant';
        borderClass = 'border-warning-amber/20';
    }
    
    badge.className = `px-3 py-1 rounded font-label-caps text-label-caps ${bgClass} ${colorClass} border ${borderClass}`;
    
    const scoreElem = document.getElementById('email-prob-score');
    scoreElem.innerText = data.probability + "%";
    scoreElem.className = `font-headline-lg text-headline-lg ${colorClass}`;

    const spfElem = document.getElementById('badge-spf');
    spfElem.innerText = data.headers_summary.SPF;
    spfElem.className = `font-bold ${data.headers_summary.SPF === 'PASS' ? 'text-cyber-lime' : 'text-neon-crimson'}`;

    const dkimElem = document.getElementById('badge-dkim');
    dkimElem.innerText = data.headers_summary.DKIM;
    dkimElem.className = `font-bold ${data.headers_summary.DKIM === 'PASS' ? 'text-cyber-lime' : 'text-neon-crimson'}`;

    document.getElementById('badge-hops').innerText = `${data.headers_summary.Received_Count}`;
    document.getElementById('badge-urgency').innerText = `${data.features.urgency_score}`;

    document.getElementById('tbl-from').innerText = data.headers_summary.From;
    document.getElementById('tbl-return').innerText = data.headers_summary['Return-Path'];
    document.getElementById('tbl-subject').innerText = data.headers_summary.Subject;
    document.getElementById('tbl-ips').innerText = (data.features.received_ips || []).join(', ') || "No external IPs found";

    const threatList = document.getElementById('email-threat-list');
    threatList.innerHTML = "";
    data.threat_indicators.forEach(ti => {
        const li = document.createElement('li');
        li.innerHTML = `<span class="material-symbols-outlined text-xs align-middle mr-1 ${colorClass}">bug_report</span> ${ti}`;
        threatList.appendChild(li);
    });

    if (data.shap) renderShapBars('email-shap-container', 'email-shap-bars', data.shap);
    if (data.geo) addGeoMarker(data.geo, data.filename, data.probability, true);
    updateLiveCounters(data.probability >= 35);

    document.getElementById('email-body-preview').innerText = data.body_preview || "No readable plain text body.";
}

// --- Browser History Threat Hunter ---
const LIVE_SOURCE_MAP = {
    live_all: 'SOC_GET_COMBINED',
    live_tabs: 'SOC_GET_LIVE_TABS',
    live_history: 'SOC_GET_HISTORY'
};

const SOCExt = {
    ready: false,
    version: null,
    browser: null,
    _pending: new Map(),
    _seq: 0,
    request(type, extra = {}, timeoutMs = 25000) {
        return new Promise((resolve) => {
            const requestId = `soc-${Date.now()}-${++this._seq}`;
            const timer = setTimeout(() => {
                if (this._pending.has(requestId)) {
                    this._pending.delete(requestId);
                    resolve({ ok: false, error: 'Extension did not respond.' });
                }
            }, timeoutMs);
            this._pending.set(requestId, (response) => {
                clearTimeout(timer);
                resolve(response);
            });
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
        const pill = document.getElementById('ext-status-pill');
        if(pill) pill.innerText = this.ready ? `Extension Active v${this.version}` : 'Extension Offline';
        return this.ready;
    }
};

window.addEventListener('message', (event) => {
    if (event.source !== window) return;
    const data = event.data;
    if (!data || data.source !== 'soc-extension') return;
    if (data.type === 'SOC_RESPONSE') { SOCExt._resolve(data.requestId, data.response); return; }
    if (data.type === 'SOC_EXT_READY') { if (!SOCExt.ready) SOCExt.detect(); return; }
    if (data.payload) handleLiveTelemetry(data.payload);
});
document.addEventListener('DOMContentLoaded', () => { SOCExt.detect(); });

function setHistoryStatus(msg) {
    const tbody = document.getElementById('history-table-body');
    if (tbody) tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-on-surface-variant">${msg}</td></tr>`;
}

async function loadBrowserHistory() {
    const sel = document.getElementById('history-browser-select');
    const browser = sel ? sel.value : 'all';
    let requestType = LIVE_SOURCE_MAP[browser];
    const autoLive = !requestType && browser === 'all';
    
    if (autoLive) {
        if (!SOCExt.ready) await SOCExt.detect();
        if (SOCExt.ready) requestType = 'SOC_GET_COMBINED';
    }

    if (requestType) {
        setHistoryStatus('Pulling live tabs & history from extension...');
        if (!SOCExt.ready) await SOCExt.detect();
        if (SOCExt.ready) {
            const res = await SOCExt.request(requestType, { limit: 45, days: 14 });
            if (res && res.ok) { applyHistoryPayload(res.history || []); return; }
            if (!autoLive) { setHistoryStatus(`Live capture failed: ${(res && res.error) || 'unknown error'}`); return; }
        } else if (!autoLive) {
            setHistoryStatus('Extension not detected. Load it via chrome://extensions.');
            return;
        }
    }

    setHistoryStatus('Scanning local SQLite history databases...');
    try {
        const serverBrowser = LIVE_SOURCE_MAP[browser] ? 'all' : browser;
        const response = await fetch(`/api/history?browser=${serverBrowser}&limit=45`);
        const data = await response.json();
        if (data.error) { setHistoryStatus(data.error); return; }
        applyHistoryPayload(data.history || []);
    } catch (err) { setHistoryStatus(`Failed to scan history: ${err}`); }
}

function applyHistoryPayload(items) {
    rawHistoryData = items;
    let maxRiskItem = null;
    rawHistoryData.forEach(item => {
        if (item.geo) addGeoMarker(item.geo, item.url, item.probability);
        if (item.probability >= 35) updateLiveCounters(true);
        if (item.probability >= 70) {
            if (!maxRiskItem || item.probability > maxRiskItem.probability) maxRiskItem = item;
        }
    });
    renderHistoryTable();
    if (maxRiskItem) showHighRiskPopup(maxRiskItem);
}

function renderHistoryTable() {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;
    const query = document.getElementById('history-search-input')?.value.trim().toLowerCase() || "";
    let filtered = rawHistoryData.filter(item => {
        if (!query) return true;
        return (item.url && item.url.toLowerCase().includes(query)) || (item.title && item.title.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="6" class="p-4 text-center text-on-surface-variant">No matching records.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    filtered.forEach(item => {
        const tr = document.createElement('tr');
        tr.className = "border-b border-glass-stroke/30 hover:bg-surface-variant/30 transition-colors";
        
        let colorClass = 'text-cyber-lime';
        if (item.probability >= 70) colorClass = 'text-neon-crimson';
        else if (item.probability >= 35) colorClass = 'text-warning-amber';
        
        tr.innerHTML = `
            <td class="p-2"><span class="bg-surface-variant px-2 py-0.5 rounded text-xs">${item.source}</span></td>
            <td class="p-2 ${colorClass} font-bold">${item.probability}%</td>
            <td class="p-2 text-on-surface truncate max-w-[200px]" title="${item.url}">${item.url}</td>
            <td class="p-2 text-on-surface-variant truncate max-w-[150px]" title="${item.title}">${item.title}</td>
            <td class="p-2 text-on-surface-variant text-xs">${item.time}</td>
            <td class="p-2 text-right"><span class="material-symbols-outlined text-sm cursor-pointer hover:text-cyber-lime" onclick="inspectFromHistory('${item.url.replace(/'/g, "\'")}')">visibility</span></td>
        `;
        tbody.appendChild(tr);
    });
}

function filterBrowserHistory() { renderHistoryTable(); }
function sortHistoryByScore() {
    historySortDesc = !historySortDesc;
    rawHistoryData.sort((a, b) => historySortDesc ? b.probability - a.probability : a.probability - b.probability);
    renderHistoryTable();
}

function inspectFromHistory(url) {
    switchTab('pane-url');
    setAndAnalyzeUrl(url);
}

function showHighRiskPopup(item) {
    const modalEl = document.getElementById('highRiskModal');
    if (!modalEl) return;
    document.getElementById('highRiskModalUrl').innerText = "URL: " + item.url;
    document.getElementById('highRiskModalTitle').innerText = "Context: " + (item.title || "N/A");
    const inspectBtn = document.getElementById('highRiskModalInspectBtn');
    inspectBtn.onclick = () => {
        modalEl.classList.add('hidden');
        inspectFromHistory(item.url.replace(/'/g, "\'"));
    };
    modalEl.classList.remove('hidden');
}

// --- Live Packet Sniffer ---
function initSocketIO() {
    if (typeof io === 'undefined') return;
    socket = io();
    socket.on('packet_event', (pkt) => { handleLiveTelemetry(pkt); });
}

let liveStreamInterval = null;

async function startPacketCapture() {
    const btn = document.getElementById('btn-start-sniff');
    const modeText = document.getElementById('sniffer-mode-text');
    const timeoutVal = document.getElementById('sniffer-timeout').value;
    const tbody = document.getElementById('sniffer-table-body');
    const dbTbody = document.getElementById('sniffer-table-body-dash');

    btn.disabled = true;
    btn.innerText = `CAPTURING (${timeoutVal}s)...`;
    modeText.innerText = `Active listening session initiated...`;
    
    const waitMsg = `<tr><td colspan="4" class="p-4 text-center text-cyber-lime">Intercepting...</td></tr>`;
    tbody.innerHTML = waitMsg;
    if(dbTbody) dbTbody.innerHTML = waitMsg;

    try {
        const response = await fetch('/api/sniff', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timeout: timeoutVal })
        });
        const data = await response.json();
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-neon-crimson">${data.error}</td></tr>`;
            btn.disabled = false;
            btn.innerText = `START BATCH CAPTURE`;
            return;
        }

        modeText.innerText = `Session Complete: Intercepted via ${data.mode}.`;

        if (snifferChartInstance) {
            const nowLabel = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
            snifferChartInstance.data.labels.push(nowLabel);
            if (snifferChartInstance.data.labels.length > 7) snifferChartInstance.data.labels.shift();
            snifferChartInstance.data.datasets[0].data.push(data.domains_captured + Math.floor(Math.random()*8));
            if (snifferChartInstance.data.datasets[0].data.length > 7) snifferChartInstance.data.datasets[0].data.shift();
            snifferChartInstance.data.datasets[1].data.push(data.urls_captured + Math.floor(Math.random()*5));
            if (snifferChartInstance.data.datasets[1].data.length > 7) snifferChartInstance.data.datasets[1].data.shift();
            snifferChartInstance.update();
        }

        tbody.innerHTML = "";
        if(dbTbody) dbTbody.innerHTML = "";

        if (data.traffic && data.traffic.length > 0) {
            data.traffic.forEach(t => { renderSnifferRow(t, tbody); renderSnifferRow(t, dbTbody); });
        } else {
            const emptyMsg = `<tr><td colspan="4" class="p-4 text-center text-on-surface-variant">No packets intercepted.</td></tr>`;
            tbody.innerHTML = emptyMsg;
            if(dbTbody) dbTbody.innerHTML = emptyMsg;
        }

        const threatElem = document.getElementById('stat-threats-count');
        if (threatElem) {
            let current = parseInt(threatElem.innerText) || 142;
            threatElem.innerText = current + data.traffic.filter(x => x.probability >= 35).length;
        }
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="p-4 text-center text-neon-crimson">Capture failed: ${err}</td></tr>`;
    } finally {
        btn.disabled = false;
        btn.innerText = `START BATCH CAPTURE`;
    }
}

function renderSnifferRow(pkt, targetTbody) {
    if (!targetTbody) return;
    const tr = document.createElement('tr');
    tr.className = "border-b border-glass-stroke/30 hover:bg-surface-variant/30 transition-colors";
    
    let colorClass = 'text-cyber-lime';
    let flag = 'Safe';
    if (pkt.probability >= 70) { colorClass = 'text-neon-crimson'; flag = 'Malware'; }
    else if (pkt.probability >= 35) { colorClass = 'text-warning-amber'; flag = 'Phishing'; }
    
    tr.innerHTML = `
        <td class="p-2"><span class="bg-surface-variant px-2 py-0.5 rounded text-xs ${colorClass}">${flag}</span></td>
        <td class="p-2 ${colorClass} font-bold">${pkt.probability}%</td>
        <td class="p-2 text-on-surface truncate max-w-[200px]" title="${pkt.uri}">${pkt.uri}</td>
        <td class="p-2 text-right"><span class="material-symbols-outlined text-sm cursor-pointer hover:text-cyber-lime" onclick="inspectFromHistory('${pkt.uri.replace(/'/g, "\'")}')">visibility</span></td>
    `;
    targetTbody.insertBefore(tr, targetTbody.firstChild);
    if (targetTbody.children.length > 30) targetTbody.removeChild(targetTbody.lastChild);
}

function handleLiveTelemetry(pkt) {
    const tbody = document.getElementById('sniffer-table-body');
    const dbTbody = document.getElementById('sniffer-table-body-dash');
    if (tbody && tbody.querySelector('td[colspan]')) tbody.innerHTML = '';
    if (dbTbody && dbTbody.querySelector('td[colspan]')) dbTbody.innerHTML = '';
    
    renderSnifferRow(pkt, tbody);
    renderSnifferRow(pkt, dbTbody);

    if (pkt.geo) addGeoMarker(pkt.geo, pkt.uri, pkt.probability);
    updateLiveCounters(pkt.probability >= 35);
}

function toggleWebSocketStream() {
    const btn = document.getElementById('btn-stream-sniff');
    if (!isStreamingSniff) {
        isStreamingSniff = true;
        btn.innerText = `STOP WEBSOCKET STREAM`;
        btn.classList.replace('text-neon-crimson', 'text-warning-amber');
        btn.classList.replace('border-neon-crimson', 'border-warning-amber');
        document.getElementById('sniffer-mode-text').innerText = "Live real-time telemetry streaming ACTIVE...";
        
        if (socket && socket.connected) {
            socket.emit('start_sniff_stream');
        } else {
            liveStreamInterval = setInterval(async () => {
                if (!isStreamingSniff) return;
                try {
                    const response = await fetch('/api/sniff', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ timeout: 1.2 }) });
                    const data = await response.json();
                    if (data.traffic && data.traffic.length > 0) {
                        data.traffic.slice(0, 3).forEach(pkt => {
                            handleLiveTelemetry(pkt);
                        });
                    }
                } catch (e) {}
            }, 2000);
        }
    } else {
        isStreamingSniff = false;
        if (socket && socket.connected) socket.emit('stop_sniff_stream');
        if (liveStreamInterval) { clearInterval(liveStreamInterval); liveStreamInterval = null; }
        
        btn.innerText = `START WEBSOCKET STREAM`;
        btn.classList.replace('text-warning-amber', 'text-neon-crimson');
        btn.classList.replace('border-warning-amber', 'border-neon-crimson');
        document.getElementById('sniffer-mode-text').innerText = "Live streaming paused.";
    }
}

// --- Map & SHAP Utils ---
function initThreatMap() {
    const mapContainer = document.getElementById('threatMap');
    if (!mapContainer || typeof L === 'undefined') return;
    threatMapInstance = L.map('threatMap', { center: [20.0, 0.0], zoom: 2, minZoom: 2, maxBounds: [[-90, -180], [90, 180]], zoomControl: false, attributionControl: false });
    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', { maxZoom: 18, subdomains: 'abcd', noWrap: true }).addTo(threatMapInstance);
    mapMarkersLayer = L.layerGroup().addTo(threatMapInstance);
    
    addGeoMarker({ lat: 55.7558, lon: 37.6173, city: 'Moscow' }, 'http://secure-verify-paypal-login.ru', 94.2);
    addGeoMarker({ lat: 51.5074, lon: -0.1278, city: 'London' }, 'https://github.com', 1.2);
    
    setTimeout(() => { if (threatMapInstance) threatMapInstance.invalidateSize(); }, 1500);
}

function addGeoMarker(geo, label, proba, isLiveFocus = false) {
    if (!threatMapInstance || !mapMarkersLayer || !geo || !geo.lat || !geo.lon) return;
    let markerClass = 'leaflet-pulse-safe';
    if (proba >= 70) markerClass = 'leaflet-pulse-danger';
    else if (proba >= 35) markerClass = 'leaflet-pulse-warn';

    const customIcon = L.divIcon({ className: 'custom-map-pulse', html: `<div class="${markerClass}"></div>`, iconSize: [20, 20], iconAnchor: [10, 10] });
    const marker = L.marker([geo.lat, geo.lon], { icon: customIcon }).addTo(mapMarkersLayer);
    
    const layers = mapMarkersLayer.getLayers();
    if (layers.length > 25) mapMarkersLayer.removeLayer(layers[0]);
    if (isLiveFocus && threatMapInstance) threatMapInstance.flyTo([geo.lat, geo.lon], 4, { animate: true, duration: 1.5 });
}

function renderShapBars(containerId, barsId, shapData) {
    const container = document.getElementById(containerId);
    const barsElem = document.getElementById(barsId);
    if (!container || !barsElem || !shapData) return;
    container.classList.remove('hidden');
    barsElem.innerHTML = '';

    if (shapData.positive_forces) {
        shapData.positive_forces.forEach(item => {
            barsElem.innerHTML += `<div class="flex items-center gap-2">
                <span class="w-24 truncate" title="${item.feature}">${item.feature}</span>
                <div class="flex-1 bg-surface-variant h-2 rounded"><div class="bg-neon-crimson h-full rounded shadow-[0_0_8px_rgba(255,63,52,0.6)]" style="width: ${Math.min(100, Math.abs(item.contribution) * 2.5)}%;"></div></div>
                <span class="text-neon-crimson w-12 text-right">+${item.contribution}%</span>
            </div>`;
        });
    }
    if (shapData.negative_forces) {
        shapData.negative_forces.forEach(item => {
            barsElem.innerHTML += `<div class="flex items-center gap-2">
                <span class="w-24 truncate" title="${item.feature}">${item.feature}</span>
                <div class="flex-1 bg-surface-variant h-2 rounded"><div class="bg-cyber-lime h-full rounded shadow-[0_0_8px_rgba(50,255,126,0.6)]" style="width: ${Math.min(100, Math.abs(item.contribution) * 2.5)}%;"></div></div>
                <span class="text-cyber-lime w-12 text-right">-${item.contribution}%</span>
            </div>`;
        });
    }
}

// --- Retrain & Diagnostics ---
async function retrainModels() {
    const btn = document.getElementById('btn-retrain');
    const origText = btn.innerText;
    btn.disabled = true;
    btn.innerText = `Training...`;
    try {
        const response = await fetch('/api/retrain', { method: 'POST' });
        const data = await response.json();
        if (data.error) alert("Retraining failed: " + data.error);
        else {
            document.getElementById('stat-url-acc').innerText = data.metrics.url_accuracy;
            document.getElementById('stat-email-acc').innerText = data.metrics.email_accuracy;
            alert(`✅ Models re-trained!
URL Accuracy: ${data.metrics.url_accuracy}%
Email Accuracy: ${data.metrics.email_accuracy}%`);
        }
    } catch (err) { alert("Retraining error: " + err); }
    finally { btn.disabled = false; btn.innerText = origText; }
}

function showSystemDiagnostics() {
    document.getElementById('diagModal').classList.remove('hidden');
}

// --- Demo & Counters ---
function updateLiveCounters(isThreat = false) {
    liveTotalCount++;
    if (isThreat) liveThreatsCount++; else liveSafeCount++;
    ['live-threats-counter', 'live-safe-counter', 'live-total-counter'].forEach(id => {
        const el = document.getElementById(id);
        if (el) {
            if (id.includes('threats')) el.innerText = liveThreatsCount;
            if (id.includes('safe')) el.innerText = liveSafeCount;
            if (id.includes('total')) el.innerText = liveTotalCount;
        }
    });
}

function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.altKey && e.key === '1') { e.preventDefault(); switchTab('pane-dashboard'); }
        if (e.altKey && e.key === '2') { e.preventDefault(); switchTab('pane-url'); }
        if (e.altKey && e.key === '3') { e.preventDefault(); switchTab('pane-email'); }
        if (e.altKey && e.key === '4') { e.preventDefault(); switchTab('pane-network'); }
        if (e.altKey && (e.key === 'd' || e.key === 'D')) { e.preventDefault(); runPresentationDemo(); }
    });
}

async function runPresentationDemo() {
    switchTab('pane-url');
    setAndAnalyzeUrl("http://secure-login-paypal-update-account.ru/signin");
    await new Promise(r => setTimeout(r, 2000));
    
    if (threatMapInstance) threatMapInstance.setView([55.7558, 37.6173], 4, { animate: true, duration: 1 });
    await new Promise(r => setTimeout(r, 2000));
    
    switchTab('pane-email');
    await new Promise(r => setTimeout(r, 600));
    const sampleBtns = document.querySelectorAll('#sample-emails-list button');
    if (sampleBtns.length > 0) sampleBtns[0].click();
    
    await new Promise(r => setTimeout(r, 2500));
    switchTab('pane-network');
    loadBrowserHistory();
    await new Promise(r => setTimeout(r, 2000));
    if (!isStreamingSniff) toggleWebSocketStream();
}
