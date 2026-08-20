/* =========================================================================
 * SOC Forensics Real-time Telemetry - Service Worker (MV3)
 * -------------------------------------------------------------------------
 * Responsibilities:
 *   1. Report every main-frame navigation to the backend for scoring.
 *   2. Answer data pulls from the dashboard page (live tabs / real history).
 *   3. Push scored events into the dashboard via the content-script bridge.
 * ========================================================================= */

const DEFAULT_BACKEND = "https://ai-phishing-forensics-engine-9dq6.vercel.app";

// Any origin that is allowed to host the dashboard / receive bridged events.
const DASHBOARD_MATCHES = [
    "*://*.vercel.app/*",
    "http://127.0.0.1:5000/*",
    "http://localhost:5000/*"
];

let backendUrl = DEFAULT_BACKEND;
let isEnabled = true;

/* ------------------------------------------------------------------ config */

chrome.storage.local.get(["backendUrl", "isEnabled"], (result) => {
    // Migration: older builds shipped a localhost default that silently failed
    // for anyone running the dashboard on Vercel. Treat it as "unset".
    const stored = (result.backendUrl || "").trim();
    const isStaleLocalDefault = stored === "http://127.0.0.1:5000" || stored === "";
    backendUrl = isStaleLocalDefault ? DEFAULT_BACKEND : stored.replace(/\/+$/, "");
    if (isStaleLocalDefault) chrome.storage.local.set({ backendUrl });
    if (result.isEnabled !== undefined) isEnabled = result.isEnabled;
    updateIcon();
});

chrome.storage.onChanged.addListener((changes) => {
    if (changes.backendUrl) backendUrl = (changes.backendUrl.newValue || DEFAULT_BACKEND).replace(/\/+$/, "");
    if (changes.isEnabled) {
        isEnabled = changes.isEnabled.newValue;
        updateIcon();
    }
});

function updateIcon() {
    chrome.action.setBadgeText({ text: isEnabled ? "ON" : "OFF" });
    chrome.action.setBadgeBackgroundColor({ color: isEnabled ? "#00f3ff" : "#475569" });
}

function flashBadge(text, color, ms = 5000) {
    chrome.action.setBadgeText({ text });
    chrome.action.setBadgeBackgroundColor({ color });
    setTimeout(updateIcon, ms);
}

/* --------------------------------------------------------- keep SW awake */
// MV3 service workers idle out after ~30s. An alarm keeps the event loop
// warm so the dashboard's data pulls do not hit a cold, unresponsive worker.
chrome.runtime.onInstalled.addListener(() => {
    chrome.alarms.create("soc-keepalive", { periodInMinutes: 0.4 });
    injectIntoOpenDashboards();
});
chrome.runtime.onStartup.addListener(() => {
    chrome.alarms.create("soc-keepalive", { periodInMinutes: 0.4 });
});
chrome.alarms.onAlarm.addListener(() => { /* wake-up only */ });

/* ------------------------------------------------------------- utilities */

function browserLabel() {
    const ua = (self.navigator && self.navigator.userAgent) || "";
    if (ua.includes("Edg/")) return "Edge";
    if (ua.includes("OPR/")) return "Opera";
    if (ua.includes("Brave")) return "Brave";
    return "Chrome";
}

function isReportableUrl(url) {
    if (!url) return false;
    if (!/^https?:\/\//i.test(url)) return false;          // skip chrome://, about:, file://
    if (/^https?:\/\/(newtab|new-tab-page)\b/i.test(url)) return false;
    return true;
}

function fmtTime(ms) {
    const d = new Date(ms);
    const p = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
           `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

/* ------------------------------------------------ dashboard bridge (push) */

// Fire-and-forget send that tolerates tabs with no content script yet.
// This is the fix for "Could not establish connection. Receiving end does
// not exist." - tabs opened BEFORE the extension was installed/reloaded have
// no injected content script, so we inject on demand and then retry once.
async function sendToTab(tabId, message, allowInject = true) {
    try {
        await chrome.tabs.sendMessage(tabId, message);
        return true;
    } catch (err) {
        if (!allowInject) return false;
        try {
            await chrome.scripting.executeScript({
                target: { tabId, allFrames: false },
                files: ["content_script.js"]
            });
            await chrome.tabs.sendMessage(tabId, message);
            return true;
        } catch (injectErr) {
            // Tab is gone, is a restricted page, or navigated away. Not fatal.
            return false;
        }
    }
}

async function broadcastToDashboards(message) {
    let tabs = [];
    try {
        tabs = await chrome.tabs.query({ url: DASHBOARD_MATCHES });
    } catch (e) {
        return;
    }
    await Promise.all(tabs.map((t) => sendToTab(t.id, message)));
}

async function injectIntoOpenDashboards() {
    try {
        const tabs = await chrome.tabs.query({ url: DASHBOARD_MATCHES });
        for (const t of tabs) {
            try {
                await chrome.scripting.executeScript({
                    target: { tabId: t.id, allFrames: false },
                    files: ["content_script.js"]
                });
            } catch (e) { /* restricted or already injected */ }
        }
    } catch (e) { /* no tabs permission yet */ }
}

/* ----------------------------------------------------------- backend I/O */

async function scoreOne(url) {
    const res = await fetch(`${backendUrl}/api/extension/report`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
    });
    if (!res.ok) throw new Error(`Backend returned HTTP ${res.status}`);
    return res.json();
}

// Batch scoring keeps a 50-entry history pull to a single round trip.
// Falls back to sequential single-URL scoring if the backend has not been
// redeployed with /api/analyze/batch yet.
async function scoreMany(items) {
    const urls = items.map((i) => i.url);
    if (!urls.length) return [];

    try {
        const res = await fetch(`${backendUrl}/api/analyze/batch`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ urls })
        });
        if (res.ok) {
            const data = await res.json();
            const byUrl = new Map((data.results || []).map((r) => [r.url, r]));
            return items.map((item) => mergeScore(item, byUrl.get(item.url)));
        }
        if (res.status !== 404) throw new Error(`Backend returned HTTP ${res.status}`);
    } catch (e) {
        if (!/HTTP 404/.test(String(e))) {
            // Network-level failure: surface it rather than hammering one-by-one.
            throw e;
        }
    }

    // Legacy fallback - cap concurrency so we do not flood the backend.
    const out = [];
    const CONCURRENCY = 5;
    for (let i = 0; i < items.length; i += CONCURRENCY) {
        const slice = items.slice(i, i + CONCURRENCY);
        const scored = await Promise.all(slice.map(async (item) => {
            try {
                return mergeScore(item, await scoreOne(item.url));
            } catch (e) {
                return mergeScore(item, null);
            }
        }));
        out.push(...scored);
    }
    return out;
}

function mergeScore(item, score) {
    if (!score || score.error) {
        return {
            url: item.url,
            title: item.title || "(no title)",
            time: item.time,
            source: item.source,
            probability: 0,
            badge: "Unscored",
            badge_class: "secondary",
            features: {},
            geo: null
        };
    }
    const p = score.probability != null ? score.probability : 0;
    let badge = "Safe", badge_class = "success";
    if (p >= 70) { badge = "High Risk"; badge_class = "danger"; }
    else if (p >= 35) { badge = "Suspicious"; badge_class = "warning"; }

    return {
        url: item.url,
        title: item.title || "(no title)",
        time: item.time,
        source: item.source,
        probability: p,
        badge,
        badge_class,
        features: score.features || {},
        geo: score.geo || null
    };
}

/* ------------------------------------------------------ data collectors */

async function collectLiveTabs() {
    const label = browserLabel();
    const tabs = await chrome.tabs.query({});
    const now = Date.now();
    const seen = new Set();
    const items = [];
    for (const t of tabs) {
        if (!isReportableUrl(t.url) || seen.has(t.url)) continue;
        seen.add(t.url);
        items.push({
            url: t.url,
            title: t.title || "(no title)",
            time: fmtTime(t.lastAccessed || now),
            source: `${label} (Live Tab)`
        });
    }
    return items;
}

async function collectHistory(limit = 45, days = 14) {
    const label = browserLabel();
    const startTime = Date.now() - days * 24 * 60 * 60 * 1000;
    const results = await chrome.history.search({
        text: "",
        startTime,
        maxResults: Math.max(limit * 3, 150)
    });
    const seen = new Set();
    const items = [];
    for (const h of results) {
        if (!isReportableUrl(h.url) || seen.has(h.url)) continue;
        seen.add(h.url);
        items.push({
            url: h.url,
            title: h.title || "(no title)",
            time: fmtTime(h.lastVisitTime || Date.now()),
            source: `${label} (Live History)`
        });
        if (items.length >= limit) break;
    }
    return items;
}

/* ------------------------------------------------- dashboard pull handler */

async function handleDashboardRequest(request) {
    switch (request.type) {
        case "SOC_PING":
            return {
                ok: true,
                version: chrome.runtime.getManifest().version,
                browser: browserLabel(),
                backendUrl,
                isEnabled
            };

        case "SOC_GET_LIVE_TABS": {
            const items = await collectLiveTabs();
            return { ok: true, history: await scoreMany(items), count: items.length };
        }

        case "SOC_GET_HISTORY": {
            const items = await collectHistory(request.limit || 45, request.days || 14);
            return { ok: true, history: await scoreMany(items), count: items.length };
        }

        case "SOC_GET_COMBINED": {
            const [tabs, hist] = await Promise.all([
                collectLiveTabs(),
                collectHistory(request.limit || 40, request.days || 14)
            ]);
            const seen = new Set();
            const merged = [];
            for (const it of [...tabs, ...hist]) {
                if (seen.has(it.url)) continue;
                seen.add(it.url);
                merged.push(it);
            }
            return { ok: true, history: await scoreMany(merged), count: merged.length };
        }

        case "SOC_SET_BACKEND": {
            // The dashboard tells us its own origin so the popup never has to
            // be configured by hand.
            const origin = (request.origin || "").replace(/\/+$/, "");
            if (/^https?:\/\//i.test(origin) && origin !== backendUrl) {
                backendUrl = origin;
                chrome.storage.local.set({ backendUrl: origin });
            }
            return { ok: true, backendUrl };
        }

        default:
            return { ok: false, error: `Unknown request type: ${request.type}` };
    }
}

// Content-script relay (page -> content script -> here -> back).
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (!request || !request.type || !request.type.startsWith("SOC_")) return false;
    handleDashboardRequest(request)
        .then(sendResponse)
        .catch((err) => sendResponse({ ok: false, error: String(err && err.message || err) }));
    return true; // keep the message channel open for the async reply
});

/* ------------------------------------------------- navigation telemetry */

async function reportAndBridge(url, modeLabel) {
    if (!isEnabled || !isReportableUrl(url)) return;
    // Never report the dashboard's own origin back to itself.
    if (backendUrl && url.startsWith(backendUrl)) return;

    let data;
    try {
        data = await scoreOne(url);
    } catch (error) {
        console.error("SOC Telemetry Error:", error);
        flashBadge("ERR", "#ffaa00");
        return;
    }

    if (data.risk_level === "High Risk (Phishing)") {
        try {
            chrome.notifications.create({
                type: "basic",
                iconUrl: chrome.runtime.getURL("icons/icon128.png"),
                title: "SOC Forensics Alert",
                message: `Phishing Threat Detected: ${url}\nProbability: ${data.probability}%`,
                priority: 2
            }, () => void chrome.runtime.lastError);
        } catch (e) { /* notifications unavailable */ }
        flashBadge("DANGER", "#ff3366");
    }

    await broadcastToDashboards({
        type: "LIVE_TELEMETRY_EVENT",
        payload: {
            uri: data.url,
            probability: data.probability,
            badge: data.badge,
            badge_class: data.badge_class,
            features: data.features,
            geo: data.geo,
            mode: modeLabel || data.mode
        }
    });
}

chrome.webNavigation.onCommitted.addListener((details) => {
    if (details.frameId !== 0) return;
    reportAndBridge(details.url, "chrome-extension");
});

// Live tab activity: a tab finishing a load, or the user switching to one,
// counts as live telemetry even when webNavigation did not fire (bfcache,
// restored sessions, tabs opened from another profile window).
const recentlySeen = new Map();
function throttled(url, ms = 60000) {
    const now = Date.now();
    const last = recentlySeen.get(url) || 0;
    if (now - last < ms) return true;
    recentlySeen.set(url, now);
    if (recentlySeen.size > 500) recentlySeen.clear();
    return false;
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete") return;
    if (!isReportableUrl(tab.url) || throttled(tab.url)) return;
    reportAndBridge(tab.url, "live-tab");
});

// Re-inject the bridge whenever a dashboard tab finishes loading.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status !== "complete" || !tab.url) return;
    if (!/^https?:\/\/([^/]*\.vercel\.app|127\.0\.0\.1:5000|localhost:5000)\//.test(tab.url)) return;
    chrome.scripting.executeScript({
        target: { tabId, allFrames: false },
        files: ["content_script.js"]
    }).catch(() => { /* already injected */ });
});
