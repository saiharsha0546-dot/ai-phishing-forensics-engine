// Next-Gen SOC Forensics Workbench Logic
let urlChartInstance = null;
let snifferChartInstance = null;
let snifferLabels = [];
let snifferDnsCounts = [];
let snifferUrlCounts = [];

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
    try { initKeyboardShortcuts(); } catch (e) { console.warn("Shortcuts init error:", e); }
    
    // Restore saved theme
    if (localStorage.getItem('soc_theme') === 'light') {
        toggleSocTheme(false, true);
    }
});

// --- Chart Initialization ---
function initUrlChart() {
    const ctx = document.getElementById('urlFeatureChart');
    if (!ctx || typeof Chart === 'undefined') {
        console.warn("Chart.js library not loaded or canvas missing.");
        return;
    }
    urlChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Length/10', 'Digits', 'Subdomains', 'IP Flag', 'Keywords', 'Entropy'],
            datasets: [{
                label: 'Feature Intensity',
                data: [0, 0, 0, 0, 0, 0],
                backgroundColor: 'rgba(0, 243, 255, 0.4)',
                borderColor: '#00f3ff',
                borderWidth: 1.5,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { display: false }, ticks: { color: '#94a3b8' } }
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
                    borderColor: '#00f3ff',
                    backgroundColor: 'rgba(0, 243, 255, 0.15)',
                    fill: true,
                    tension: 0.3
                },
                {
                    label: 'HTTP URI Requests',
                    data: [5, 9, 3, 14, 7],
                    borderColor: '#ff0055',
                    backgroundColor: 'rgba(255, 0, 85, 0.15)',
                    fill: true,
                    tension: 0.3
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#94a3b8' } },
                x: { grid: { color: 'rgba(255,255,255,0.06)' }, ticks: { color: '#94a3b8' } }
            },
            plugins: { legend: { labels: { color: '#cbd5e1' } } }
        }
    });
}

// --- URL Forensics ---
function setAndAnalyzeUrl(presetUrl) {
    const urlInput = document.getElementById('url-input');
    if (urlInput) urlInput.value = presetUrl;
    analyzeUrl();
    setTimeout(() => {
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 50);
}

async function analyzeUrl() {
    const urlInputElem = document.getElementById('url-input');
    const urlInput = urlInputElem ? urlInputElem.value.trim() : "";
    if (!urlInput) {
        alert("Please enter a target URL to analyze.");
        return;
    }

    const emptyState = document.getElementById('url-empty-state');
    const reportContent = document.getElementById('url-report-content');
    
    emptyState.classList.add('d-none');
    reportContent.classList.remove('d-none');
    
    // Show immediate loading with the exact provided URL so user sees it right away
    document.getElementById('url-display-target').innerHTML = `<span class="spinner-border spinner-border-sm me-2 text-cyan"></span> Analyzing: <span class="text-info">${urlInput}</span>`;
    document.getElementById('url-prob-score').innerText = "...";

    const resultBox = document.getElementById('url-result-box');
    if (resultBox) {
        resultBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }

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

        // Update UI Badge
        const badge = document.getElementById('url-risk-badge');
        badge.innerText = data.risk_level;
        badge.className = `badge text-uppercase px-3 py-2 font-monospace fs-6 bg-${data.color_class} text-light`;

        // Display Data
        document.getElementById('url-display-target').innerText = data.url;
        const scoreElem = document.getElementById('url-prob-score');
        scoreElem.innerText = data.probability + "%";
        scoreElem.className = `probability-score font-monospace text-${data.color_class}`;

        // Flash border/glow so user immediately sees exact result update
        if (resultBox) {
            resultBox.style.boxShadow = '0 0 40px rgba(0, 243, 255, 0.6)';
            resultBox.style.borderColor = '#00f3ff';
            setTimeout(() => {
                resultBox.style.boxShadow = '';
                resultBox.style.borderColor = '';
            }, 1200);
        }

        // Feature grids
        document.getElementById('url-feat-age').innerText = typeof data.features.domain_age_days === 'number' ? `${data.features.domain_age_days} Days` : data.features.domain_age_days;
        document.getElementById('url-feat-ip').innerText = data.features.has_ip ? "YES (Flagged)" : "No";
        document.getElementById('url-feat-sub').innerText = `${data.features.subdomain_count} Subdomains`;
        document.getElementById('url-feat-entropy').innerText = data.features.entropy;
        document.getElementById('url-feat-kw').innerText = `${data.features.suspicious_keywords_count} High-Risk Words`;
        document.getElementById('url-feat-https').innerText = data.features.is_https ? "Yes (Secured)" : "No (Cleartext HTTP)";

        // Risk factors list
        const factorsList = document.getElementById('url-risk-factors-list');
        factorsList.innerHTML = "";
        data.risk_factors.forEach(rf => {
            const li = document.createElement('li');
            li.className = 'list-group-item d-flex align-items-center gap-2';
            li.innerHTML = `<i class="fa-solid fa-triangle-exclamation text-${data.color_class}"></i> <span>${rf}</span>`;
            factorsList.appendChild(li);
        });

        // Upgrade 4 & 3: Render SHAP & Geo-IP marker
        if (data.shap) renderShapBars('url-shap-container', 'url-shap-bars', data.shap);
        if (data.geo) addGeoMarker(data.geo, data.url, data.probability, true);
        updateLiveCounters(data.probability >= 35);

        // Update Chart
        if (urlChartInstance) {
            urlChartInstance.data.datasets[0].data = [
                Math.min(20, Math.round(data.features.url_length / 10)),
                data.features.digit_count,
                data.features.subdomain_count * 2,
                data.features.has_ip ? 15 : 0,
                data.features.suspicious_keywords_count * 4,
                data.features.entropy
            ];
            urlChartInstance.data.datasets[0].borderColor = data.probability >= 70 ? '#ff0055' : (data.probability >= 35 ? '#ff9d00' : '#00ff66');
            urlChartInstance.data.datasets[0].backgroundColor = data.probability >= 70 ? 'rgba(255, 0, 85, 0.4)' : (data.probability >= 35 ? 'rgba(255, 157, 0, 0.4)' : 'rgba(0, 255, 102, 0.4)');
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
            btn.type = 'button';
            const isPhish = s.type === 'Phishing';
            btn.className = `btn btn-sm ${isPhish ? 'btn-outline-danger' : 'btn-outline-success'} text-start d-flex align-items-center justify-content-between p-2 rounded`;
            btn.innerHTML = `
                <div class="text-truncate">
                    <i class="fa-solid ${isPhish ? 'fa-skull-crossbones' : 'fa-check-double'} me-2"></i>
                    <span class="fw-semibold">${s.title}</span>
                </div>
                <span class="badge ${isPhish ? 'bg-danger' : 'bg-success'} font-monospace small">${s.type}</span>
            `;
            btn.onclick = () => analyzeRawEmailText(s.content, s.name);
            listElem.appendChild(btn);
        });
    } catch (err) {
        listElem.innerHTML = `<small class="text-danger">Failed to load samples.</small>`;
    }
}

async function handleFileUpload(files) {
    if (!files || files.length === 0) return;
    const file = files[0];
    
    const formData = new FormData();
    formData.append('file', file);

    document.getElementById('email-empty-state').classList.add('d-none');
    document.getElementById('email-report-content').classList.remove('d-none');
    document.getElementById('email-display-name').innerText = file.name + " (Analyzing...)";

    try {
        const response = await fetch('/api/analyze/email', {
            method: 'POST',
            body: formData
        });
        const data = await response.json();
        if (data.error) {
            alert("Error: " + data.error);
            return;
        }
        renderEmailReport(data);
    } catch (err) {
        alert("Upload error: " + err);
    }
}

async function analyzeRawEmailText(rawContent, filename = "Sample Email") {
    document.getElementById('email-empty-state').classList.add('d-none');
    document.getElementById('email-report-content').classList.remove('d-none');
    document.getElementById('email-display-name').innerText = filename + " (Analyzing...)";

    try {
        const response = await fetch('/api/analyze/email', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_email: rawContent })
        });
        const data = await response.json();
        if (data.error) {
            alert("Error: " + data.error);
            return;
        }
        renderEmailReport(data);
    } catch (err) {
        alert("Analysis error: " + err);
    }
}

function renderEmailReport(data) {
    document.getElementById('email-display-name').innerText = data.filename;
    
    const badge = document.getElementById('email-risk-badge');
    badge.innerText = data.risk_level;
    badge.className = `badge text-uppercase px-3 py-2 font-monospace fs-6 bg-${data.color_class} text-light`;

    const scoreElem = document.getElementById('email-prob-score');
    scoreElem.innerText = data.probability + "%";
    scoreElem.className = `probability-score font-monospace text-${data.color_class}`;

    // Badges
    const spfElem = document.getElementById('badge-spf');
    spfElem.innerText = data.headers_summary.SPF;
    spfElem.className = `badge font-monospace ${data.headers_summary.SPF === 'PASS' ? 'bg-success' : 'bg-danger'}`;

    const dkimElem = document.getElementById('badge-dkim');
    dkimElem.innerText = data.headers_summary.DKIM;
    dkimElem.className = `badge font-monospace ${data.headers_summary.DKIM === 'PASS' ? 'bg-success' : 'bg-danger'}`;

    document.getElementById('badge-hops').innerText = `${data.headers_summary.Received_Count} Hops`;
    document.getElementById('badge-urgency').innerText = `Urgency: ${data.features.urgency_score}`;

    // Table
    document.getElementById('tbl-from').innerText = data.headers_summary.From;
    document.getElementById('tbl-return').innerText = data.headers_summary['Return-Path'];
    document.getElementById('tbl-subject').innerText = data.headers_summary.Subject;
    document.getElementById('tbl-ips').innerText = (data.features.received_ips || []).join(', ') || "No external IPv4 hops found";

    // Threat list
    const threatList = document.getElementById('email-threat-list');
    threatList.innerHTML = "";
    data.threat_indicators.forEach(ti => {
        const li = document.createElement('li');
        li.className = 'list-group-item d-flex align-items-center gap-2';
        li.innerHTML = `<i class="fa-solid fa-shield-virus text-${data.color_class}"></i> <span>${ti}</span>`;
        threatList.appendChild(li);
    });

    // Upgrade 4 & 3: Render SHAP & Geo-IP marker
    if (data.shap) renderShapBars('email-shap-container', 'email-shap-bars', data.shap);
    if (data.geo) addGeoMarker(data.geo, data.filename, data.probability, true);
    updateLiveCounters(data.probability >= 35);

    document.getElementById('email-body-preview').innerText = data.body_preview || "No readable plain text body.";
}

// --- Browser History Threat Hunter ---
async function loadBrowserHistory() {
    const browser = document.getElementById('history-browser-select') ? document.getElementById('history-browser-select').value : 'all';
    const tbody = document.getElementById('history-table-body');
    tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted"><span class="spinner-border spinner-border-sm text-cyan me-2"></span> Scanning local SQLite history databases...</td></tr>`;

    try {
        const response = await fetch(`/api/history?browser=${browser}&limit=45`);
        const data = await response.json();
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-danger">${data.error}</td></tr>`;
            return;
        }

        rawHistoryData = data.history || [];
        rawHistoryData.forEach(item => {
            if (item.geo) addGeoMarker(item.geo, item.url, item.probability);
            if (item.probability >= 35) updateLiveCounters(true);
        });
        renderHistoryTable();
    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-danger">Failed to scan history: ${err}</td></tr>`;
    }
}

function renderHistoryTable() {
    const tbody = document.getElementById('history-table-body');
    if (!tbody) return;
    const searchInput = document.getElementById('history-search-input');
    const query = searchInput ? searchInput.value.trim().toLowerCase() : "";

    let filtered = rawHistoryData.filter(item => {
        if (!query) return true;
        return (item.url && item.url.toLowerCase().includes(query)) ||
               (item.title && item.title.toLowerCase().includes(query));
    });

    if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="7" class="text-center py-4 text-muted">No matching browser history records found.</td></tr>`;
        return;
    }

    tbody.innerHTML = "";
    filtered.forEach(item => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td><span class="badge bg-${item.badge_class} font-monospace">${item.badge}</span></td>
            <td class="text-${item.badge_class} fw-bold font-monospace fs-6">${item.probability}%</td>
            <td class="text-truncate text-light fw-medium" style="max-width: 260px;" title="${item.url}">${item.url}</td>
            <td class="text-truncate text-light" style="max-width: 220px;" title="${item.title}">${item.title}</td>
            <td class="text-light font-monospace small">${item.time}</td>
            <td><span class="badge bg-dark border border-cyan text-cyan">${item.source}</span></td>
            <td class="text-end">
                <button class="btn btn-sm btn-outline-cyan py-1 px-2" onclick="inspectFromHistory('${item.url.replace(/'/g, "\\'")}')">
                    <i class="fa-solid fa-crosshairs me-1"></i> Inspect
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

function filterBrowserHistory() {
    renderHistoryTable();
}

function sortHistoryByScore() {
    historySortDesc = !historySortDesc;
    rawHistoryData.sort((a, b) => historySortDesc ? b.probability - a.probability : a.probability - b.probability);
    renderHistoryTable();
}

function inspectFromHistory(url) {
    // Switch to URL tab and analyze
    const urlTabBtn = document.getElementById('url-tab');
    if (urlTabBtn) {
        const tab = new bootstrap.Tab(urlTabBtn);
        tab.show();
    }
    setAndAnalyzeUrl(url);
    setTimeout(() => {
        const resultBox = document.getElementById('url-result-box');
        if (resultBox) {
            resultBox.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 150);
}

// --- Live Packet Sniffer ---
async function startPacketCapture() {
    const btn = document.getElementById('btn-start-sniff');
    const modeText = document.getElementById('sniffer-mode-text');
    const timeoutVal = document.getElementById('sniffer-timeout').value;
    const tbody = document.getElementById('sniffer-table-body');

    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-2"></span> CAPTURING PACKETS FOR ${timeoutVal}s...`;
    modeText.classList.add('sniffing-active');
    modeText.innerText = `Active listening session initiated on network interface (${timeoutVal} seconds)...`;
    tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-cyan"><span class="spinner-border spinner-border-sm me-2"></span> Intercepting live DNS queries and HTTP request URIs...</td></tr>`;

    try {
        const response = await fetch('/api/sniff', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ timeout: timeoutVal })
        });
        const data = await response.json();
        modeText.classList.remove('sniffing-active');
        if (data.error) {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-danger">${data.error}</td></tr>`;
            btn.disabled = false;
            btn.innerHTML = `<i class="fa-solid fa-tower-broadcast fa-fade"></i> START PACKET SNIFFER`;
            return;
        }

        modeText.innerText = `Session Complete: Intercepted via ${data.mode}. (${data.domains_captured} Domains, ${data.urls_captured} URIs)`;

        // Update timeline chart with animated point additions
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
        if (data.traffic && data.traffic.length > 0) {
            data.traffic.forEach(t => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><span class="badge bg-${t.badge_class} font-monospace">${t.badge}</span></td>
                    <td class="text-${t.badge_class} fw-bold font-monospace">${t.probability}%</td>
                    <td class="text-truncate text-light fw-medium" style="max-width: 320px;" title="${t.uri}">${t.uri}</td>
                    <td class="text-end">
                        <button class="btn btn-sm btn-outline-cyan py-0 px-2" onclick="inspectFromHistory('${t.uri.replace(/'/g, "\\'")}')">Analyze</button>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        } else {
            tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-muted">No clear HTTP/DNS packets intercepted during window. Try again.</td></tr>`;
        }

        // Update top counter
        const threatElem = document.getElementById('stat-threats-count');
        if (threatElem) {
            let current = parseInt(threatElem.innerText) || 142;
            threatElem.innerText = current + data.traffic.filter(x => x.probability >= 35).length;
        }

    } catch (err) {
        tbody.innerHTML = `<tr><td colspan="4" class="text-center py-4 text-danger">Capture failed: ${err}</td></tr>`;
    } finally {
        modeText.classList.remove('sniffing-active');
        btn.disabled = false;
        btn.innerHTML = `<i class="fa-solid fa-tower-broadcast fa-fade"></i> START PACKET SNIFFER`;
    }
}

// --- Re-Train & Diagnostics ---
async function retrainModels() {
    const btn = document.getElementById('btn-retrain');
    const origHTML = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = `<span class="spinner-border spinner-border-sm me-1"></span> Training...`;

    try {
        const response = await fetch('/api/retrain', { method: 'POST' });
        const data = await response.json();
        if (data.error) {
            alert("Retraining failed: " + data.error);
        } else {
            document.getElementById('stat-url-acc').innerText = data.metrics.url_accuracy + "%";
            document.getElementById('stat-email-acc').innerText = data.metrics.email_accuracy + "%";
            alert(`✅ Models successfully re-trained & reloaded into memory!\nURL Accuracy: ${data.metrics.url_accuracy}%\nEmail Accuracy: ${data.metrics.email_accuracy}%`);
        }
    } catch (err) {
        alert("Retraining request error: " + err);
    } finally {
        btn.disabled = false;
        btn.innerHTML = origHTML;
    }
}

function showSystemDiagnostics() {
    const modal = new bootstrap.Modal(document.getElementById('diagModal'));
    modal.show();
}

/* =========================================================
   UPGRADES 1-10 + BONUS + PRESENTATION ENGINE LOGIC
   ========================================================= */

// Upgrade 1: SocketIO Live Streaming Client
function initSocketIO() {
    if (typeof io === 'undefined') {
        console.warn("Socket.IO client library not loaded.");
        return;
    }
    socket = io();
    
    socket.on('connect', () => {
        console.log("⚡ Connected to live WebSocket SOC telemetry stream.");
    });

    socket.on('packet_event', (pkt) => {
        // Handle incoming live stream packet
        const tbody = document.getElementById('sniffer-table-body');
        if (tbody) {
            // Remove placeholder if present
            if (tbody.querySelector('td[colspan]')) tbody.innerHTML = '';
            
            const tr = document.createElement('tr');
            tr.className = 'live-ticker-box';
            tr.innerHTML = `
                <td><span class="badge bg-${pkt.badge_class} font-monospace">${pkt.badge}</span></td>
                <td class="text-${pkt.badge_class} fw-bold font-monospace">${pkt.probability}%</td>
                <td class="text-truncate text-light fw-medium" style="max-width: 320px;" title="${pkt.uri}">${pkt.uri}</td>
                <td class="text-end">
                    <button class="btn btn-sm btn-outline-cyan py-0 px-2" onclick="inspectFromHistory('${pkt.uri.replace(/'/g, "\\'")}')">Analyze</button>
                </td>
            `;
            tbody.insertBefore(tr, tbody.firstChild);
            if (tbody.children.length > 30) tbody.removeChild(tbody.lastChild);
        }

        // Add to map if geo available
        if (pkt.geo) {
            addGeoMarker(pkt.geo, pkt.uri, pkt.probability);
        }

        // Increment Live Ticker Counters
        updateLiveCounters(pkt.probability >= 35);
    });
}

function toggleWebSocketStream() {
    const btn = document.getElementById('btn-stream-sniff');
    if (!socket) {
        alert("WebSocket client not connected to server.");
        return;
    }
    
    if (!isStreamingSniff) {
        isStreamingSniff = true;
        socket.emit('start_sniff_stream');
        btn.innerHTML = `<i class="fa-solid fa-satellite-dish fa-spin"></i> STOP LIVE WEBSOCKET STREAM`;
        btn.classList.remove('btn-glow-danger');
        btn.classList.add('btn-outline-danger');
        document.getElementById('sniffer-mode-text').innerText = "⚡ Live WebSocket streaming ACTIVE. Intercepting queries continuously...";
    } else {
        isStreamingSniff = false;
        socket.emit('stop_sniff_stream');
        btn.innerHTML = `<i class="fa-solid fa-satellite-dish fa-spin"></i> START LIVE WEBSOCKET STREAM`;
        btn.classList.remove('btn-outline-danger');
        btn.classList.add('btn-glow-danger');
        document.getElementById('sniffer-mode-text').innerText = "Live streaming paused.";
    }
}

// Upgrade 3: Leaflet Geo-IP Threat Heatmap
function initThreatMap() {
    const mapContainer = document.getElementById('threatMap');
    if (!mapContainer || typeof L === 'undefined') return;

    threatMapInstance = L.map('threatMap', {
        center: [20.0, 0.0],
        zoom: 2,
        minZoom: 2,
        maxBounds: [[-90, -180], [90, 180]],
        maxBoundsViscosity: 1.0,
        zoomControl: false,
        attributionControl: false
    });

    L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
        maxZoom: 18,
        subdomains: 'abcd',
        noWrap: true
    }).addTo(threatMapInstance);

    mapMarkersLayer = L.layerGroup().addTo(threatMapInstance);

    // Add initial anchor markers across global centers for immediate RED, ORANGE, and GREEN radar visibility
    addGeoMarker({ lat: 55.7558, lon: 37.6173, city: 'Moscow', country: 'Russia', asn: 'AS12389' }, 'http://secure-verify-paypal-login.ru', 94.2);
    addGeoMarker({ lat: 50.1109, lon: 8.6821, city: 'Frankfurt', country: 'Germany', asn: 'AS6830' }, 'http://verify-bank-security-check.de', 58.4);
    addGeoMarker({ lat: 39.9042, lon: 116.4074, city: 'Beijing', country: 'China', asn: 'AS4134' }, 'http://login-verification-portal.cn', 64.2);
    addGeoMarker({ lat: 51.5074, lon: -0.1278, city: 'London', country: 'United Kingdom', asn: 'AS2856' }, 'https://github.com', 1.2);
    addGeoMarker({ lat: 35.6762, lon: 139.6503, city: 'Tokyo', country: 'Japan', asn: 'AS2516' }, 'https://microsoft.com', 0.8);
    addGeoMarker({ lat: 37.7749, lon: -122.4194, city: 'San Francisco', country: 'United States', asn: 'AS15169' }, 'https://google.com', 0.5);

    // Invalidate map size once opening animations/loader finish so tiles render cleanly
    setTimeout(() => {
        if (threatMapInstance) threatMapInstance.invalidateSize();
    }, 1500);
}

function addGeoMarker(geo, label, proba, isLiveFocus = false) {
    if (!threatMapInstance || !mapMarkersLayer || !geo || !geo.lat || !geo.lon) return;

    let markerClass = 'leaflet-pulse-safe';
    let badgeColor = 'success';
    if (proba >= 70) {
        markerClass = 'leaflet-pulse-danger';
        badgeColor = 'danger';
    } else if (proba >= 35) {
        markerClass = 'leaflet-pulse-warn';
        badgeColor = 'warning';
    }

    const customIcon = L.divIcon({
        className: 'custom-map-pulse',
        html: `<div class="${markerClass}"></div>`,
        iconSize: [20, 20],
        iconAnchor: [10, 10]
    });

    const marker = L.marker([geo.lat, geo.lon], { icon: customIcon }).addTo(mapMarkersLayer);
    marker.bindPopup(`
        <div class="font-monospace small text-dark p-1">
            <strong class="d-block text-truncate mb-1" style="max-width: 200px;">${label}</strong>
            <div>📍 <strong>${geo.city || 'Unknown'}, ${geo.country || 'Global'}</strong></div>
            <div>🌐 ASN: ${geo.asn || 'AS-Cloud'}</div>
            <div>🖥️ IP: ${geo.ip || 'Resolved Dynamic'}</div>
            <div class="mt-1"><span class="badge bg-${badgeColor}">Risk: ${proba}%</span></div>
        </div>
    `);

    // Keep max 25 markers to keep performance smooth
    const layers = mapMarkersLayer.getLayers();
    if (layers.length > 25) {
        mapMarkersLayer.removeLayer(layers[0]);
    }

    if (isLiveFocus && threatMapInstance) {
        threatMapInstance.flyTo([geo.lat, geo.lon], 4, {
            animate: true,
            duration: 1.5
        });
        setTimeout(() => {
            marker.openPopup();
        }, 1600);
    }
}

// Upgrade 4: SHAP TreeExplainer Force Breakdown
function renderShapBars(containerId, barsId, shapData) {
    const container = document.getElementById(containerId);
    const barsElem = document.getElementById(barsId);
    if (!container || !barsElem || !shapData) return;

    container.style.display = 'block';
    barsElem.innerHTML = '';

    // Render positive (phishing-pushing) forces
    if (shapData.positive_forces && shapData.positive_forces.length > 0) {
        const titlePos = document.createElement('div');
        titlePos.className = 'text-neon-red small fw-bold mb-1 mt-2';
        titlePos.innerHTML = `<i class="fa-solid fa-arrow-up-right-dots me-1"></i> Factors Increasing Phishing Probability:`;
        barsElem.appendChild(titlePos);

        shapData.positive_forces.forEach(item => {
            const row = document.createElement('div');
            row.className = 'shap-bar-row';
            row.innerHTML = `
                <span class="text-light text-truncate" style="width: 140px;" title="${item.feature}">${item.feature}</span>
                <div class="shap-bar-track">
                    <div class="shap-bar-fill shap-fill-positive" style="width: ${Math.min(100, Math.abs(item.contribution) * 2.5)}%;"></div>
                </div>
                <span class="text-neon-red fw-bold" style="width: 50px; text-align: right;">+${item.contribution}%</span>
            `;
            barsElem.appendChild(row);
        });
    }

    // Render negative (legitimacy-pushing) forces
    if (shapData.negative_forces && shapData.negative_forces.length > 0) {
        const titleNeg = document.createElement('div');
        titleNeg.className = 'text-success small fw-bold mb-1 mt-3';
        titleNeg.innerHTML = `<i class="fa-solid fa-arrow-down-right-dots me-1"></i> Factors Decreasing Phishing Probability:`;
        barsElem.appendChild(titleNeg);

        shapData.negative_forces.forEach(item => {
            const row = document.createElement('div');
            row.className = 'shap-bar-row';
            row.innerHTML = `
                <span class="text-light text-truncate" style="width: 140px;" title="${item.feature}">${item.feature}</span>
                <div class="shap-bar-track">
                    <div class="shap-bar-fill shap-fill-negative" style="width: ${Math.min(100, Math.abs(item.contribution) * 2.5)}%;"></div>
                </div>
                <span class="text-success fw-bold" style="width: 50px; text-align: right;">-${item.contribution}%</span>
            `;
            barsElem.appendChild(row);
        });
    }
}

// Upgrade 5: Clean Minimalist Light/Dark Theme Switcher
function toggleSocTheme(save = true, forceLight = false) {
    const btn = document.getElementById('themeToggleBtn');
    const isDark = !document.body.classList.contains('soc-light-theme');

    if ((isDark && save) || forceLight) {
        document.body.classList.add('soc-light-theme');
        if (btn) btn.innerHTML = `<i class="fa-solid fa-moon"></i> Dark Mode`;
        if (save) localStorage.setItem('soc_theme', 'light');
    } else {
        document.body.classList.remove('soc-light-theme');
        if (btn) btn.innerHTML = `<i class="fa-solid fa-sun"></i> Light Mode`;
        if (save) localStorage.setItem('soc_theme', 'dark');
    }

    // Update Chart grid lines based on theme
    const gridColor = document.body.classList.contains('soc-light-theme') ? 'rgba(0,0,0,0.08)' : 'rgba(255,255,255,0.06)';
    const textColor = document.body.classList.contains('soc-light-theme') ? '#334155' : '#94a3b8';
    
    [urlChartInstance, snifferChartInstance].forEach(chart => {
        if (chart && chart.options && chart.options.scales) {
            if (chart.options.scales.y) {
                chart.options.scales.y.grid.color = gridColor;
                chart.options.scales.y.ticks.color = textColor;
            }
            if (chart.options.scales.x) {
                chart.options.scales.x.grid.color = gridColor;
                chart.options.scales.x.ticks.color = textColor;
            }
            chart.update();
        }
    });
}

// Upgrade 7: Keyboard Shortcuts Engine
function initKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        // Alt+1..4 to switch tabs
        if (e.altKey && e.key === '1') { e.preventDefault(); const t = document.getElementById('url-tab'); if(t) new bootstrap.Tab(t).show(); }
        if (e.altKey && e.key === '2') { e.preventDefault(); const t = document.getElementById('email-tab'); if(t) new bootstrap.Tab(t).show(); }
        if (e.altKey && e.key === '3') { e.preventDefault(); const t = document.getElementById('history-tab'); if(t) new bootstrap.Tab(t).show(); }
        if (e.altKey && e.key === '4') { e.preventDefault(); const t = document.getElementById('sniffer-tab'); if(t) new bootstrap.Tab(t).show(); }
        
        // Ctrl+Enter to trigger URL check
        if (e.ctrlKey && e.key === 'Enter') {
            const activeTab = document.querySelector('.nav-link.active');
            if (activeTab && activeTab.id === 'url-tab') {
                e.preventDefault();
                analyzeUrl();
            }
        }

        // Alt+T for theme toggle
        if (e.altKey && (e.key === 't' || e.key === 'T')) {
            e.preventDefault();
            toggleSocTheme();
        }

        // Alt+D for Demo mode
        if (e.altKey && (e.key === 'd' || e.key === 'D')) {
            e.preventDefault();
            runPresentationDemo();
        }
    });
}

// Upgrade 9: Live Ticker Counters
function updateLiveCounters(isThreat = false) {
    liveTotalCount++;
    if (isThreat) liveThreatsCount++;
    else liveSafeCount++;

    const tElem = document.getElementById('live-threats-counter');
    const sElem = document.getElementById('live-safe-counter');
    const totElem = document.getElementById('live-total-counter');

    if (tElem) tElem.innerText = liveThreatsCount;
    if (sElem) sElem.innerText = liveSafeCount;
    if (totElem) totElem.innerText = liveTotalCount;
}

// Upgrade 11: Automated Presentation Demo Mode
async function runPresentationDemo() {
    const demoBtn = document.getElementById('demoModeBtn');
    if (demoBtn) demoBtn.innerHTML = `<i class="fa-solid fa-spinner fa-spin me-1"></i> Demo Running...`;

    // Step 1: Switch to URL Tab and enter target
    const urlTab = document.getElementById('url-tab');
    if (urlTab) new bootstrap.Tab(urlTab).show();
    
    const urlInput = document.getElementById('url-input');
    if (urlInput) {
        urlInput.value = "http://secure-login-paypal-update-account.ru/signin";
        urlInput.classList.add('demo-active-glow');
    }

    await new Promise(r => setTimeout(r, 800));
    analyzeUrl();

    await new Promise(r => setTimeout(r, 2200));
    if (urlInput) urlInput.classList.remove('demo-active-glow');

    // Step 2: Highlight Map marker
    if (threatMapInstance) {
        threatMapInstance.setView([55.7558, 37.6173], 4, { animate: true, duration: 1 });
    }

    await new Promise(r => setTimeout(r, 2000));

    // Step 3: Switch to Email tab and trigger sample analysis
    const emailTab = document.getElementById('email-tab');
    if (emailTab) new bootstrap.Tab(emailTab).show();

    await new Promise(r => setTimeout(r, 600));
    const sampleBtns = document.querySelectorAll('#sample-emails-list button');
    if (sampleBtns.length > 0) sampleBtns[0].click();

    await new Promise(r => setTimeout(r, 2500));

    // Step 4: Switch to History Tab and scan
    const historyTab = document.getElementById('history-tab');
    if (historyTab) new bootstrap.Tab(historyTab).show();

    await new Promise(r => setTimeout(r, 600));
    loadBrowserHistory();

    await new Promise(r => setTimeout(r, 2000));

    // Step 5: Switch to Sniffer and trigger batch or stream
    const snifferTab = document.getElementById('sniffer-tab');
    if (snifferTab) new bootstrap.Tab(snifferTab).show();

    await new Promise(r => setTimeout(r, 600));
    if (!isStreamingSniff) toggleWebSocketStream();

    if (demoBtn) demoBtn.innerHTML = `<i class="fa-solid fa-bolt me-1"></i> Presentation Demo`;
}
