/* =========================================================================
 * SOC Forensics - Content Script Bridge
 * -------------------------------------------------------------------------
 * The dashboard page cannot call chrome.* APIs directly, so this script sits
 * in between:
 *
 *   page  --window.postMessage-->  content script  --sendMessage-->  worker
 *   page  <--window.postMessage--  content script  <--response----   worker
 *
 * It is idempotent: the service worker re-injects it into tabs that were open
 * before the extension was installed, so guard against running twice.
 * ========================================================================= */

(() => {
    if (window.__SOC_BRIDGE_INSTALLED__) return;
    window.__SOC_BRIDGE_INSTALLED__ = true;

    const TAG = "soc-extension";

    function post(msg) {
        window.postMessage(Object.assign({ source: TAG }, msg), window.location.origin);
    }

    /* ---------------- worker -> page (pushed telemetry) ---------------- */
    chrome.runtime.onMessage.addListener((request) => {
        if (request && request.type === "LIVE_TELEMETRY_EVENT") {
            post({ payload: request.payload });
        }
    });

    /* ---------------- page -> worker (data pulls) ---------------------- */
    window.addEventListener("message", (event) => {
        // Only accept requests from this page itself.
        if (event.source !== window) return;
        const data = event.data;
        if (!data || data.target !== TAG || !data.type || !String(data.type).startsWith("SOC_")) return;

        const requestId = data.requestId;
        let responded = false;
        const reply = (response) => {
            if (responded) return;
            responded = true;
            post({ type: "SOC_RESPONSE", requestId, response });
        };

        try {
            chrome.runtime.sendMessage(data, (response) => {
                // Swallow "Receiving end does not exist" / worker restarts and
                // turn them into a clean error the dashboard can render.
                if (chrome.runtime.lastError) {
                    reply({ ok: false, error: chrome.runtime.lastError.message });
                    return;
                }
                reply(response || { ok: false, error: "Empty response from service worker" });
            });
        } catch (err) {
            // Extension context invalidated (reloaded/updated mid-session).
            reply({ ok: false, error: String((err && err.message) || err) });
        }

        // Cold service worker start can take a moment; do not hang forever.
        setTimeout(() => reply({ ok: false, error: "Extension service worker timed out" }), 20000);
    });

    /* ---------------- announce presence -------------------------------- */
    // The dashboard listens for this so it can flip its badge from
    // "SOC Simulation" to "Live" without polling.
    const announce = () => post({ type: "SOC_EXT_READY", version: chrome.runtime.getManifest().version });
    announce();
    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", announce, { once: true });
    }
    window.addEventListener("load", announce, { once: true });
})();
