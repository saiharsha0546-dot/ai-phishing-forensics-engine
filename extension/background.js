// Default configuration
let backendUrl = "http://127.0.0.1:5000";
let isEnabled = true;

// Load initial configuration
chrome.storage.local.get(['backendUrl', 'isEnabled'], (result) => {
    if (result.backendUrl) {
        backendUrl = result.backendUrl;
    }
    if (result.isEnabled !== undefined) {
        isEnabled = result.isEnabled;
    }
    updateIcon();
});

// Listen for config changes from popup
chrome.storage.onChanged.addListener((changes, namespace) => {
    if (changes.backendUrl) {
        backendUrl = changes.backendUrl.newValue;
    }
    if (changes.isEnabled) {
        isEnabled = changes.isEnabled.newValue;
        updateIcon();
    }
});

function updateIcon() {
    if (isEnabled) {
        chrome.action.setBadgeText({text: "ON"});
        chrome.action.setBadgeBackgroundColor({color: "#00f3ff"});
    } else {
        chrome.action.setBadgeText({text: "OFF"});
        chrome.action.setBadgeBackgroundColor({color: "#475569"});
    }
}

// Intercept navigation events in the main frame
chrome.webNavigation.onCommitted.addListener((details) => {
    // Only capture main frame navigation
    if (details.frameId === 0 && isEnabled) {
        const url = details.url;
        
        // Ignore internal chrome extensions, blank pages, etc.
        if (!url.startsWith('http')) return;

        // Send URL to backend for live SOC telemetry analysis
        fetch(`${backendUrl}/api/extension/report`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ url: url })
        })
        .then(response => response.json())
        .then(data => {
            console.log("Telemetry sent successfully:", data);
            
            // If the threat is High Risk, show a warning notification
            if (data.risk_level === "High Risk (Phishing)") {
                chrome.notifications.create({
                    type: 'basic',
                    iconUrl: 'icon.png', // Fallback to default if doesn't exist
                    title: 'SOC Forensics Alert',
                    message: `Phishing Threat Detected: ${url}\nProbability: ${data.probability}%`,
                    priority: 2
                });
                chrome.action.setBadgeText({text: "DANGER"});
                chrome.action.setBadgeBackgroundColor({color: "#ff3366"});
                
                // Reset badge after 5 seconds
                setTimeout(() => {
                    updateIcon();
                }, 5000);
            }

            // Bridge data to the dashboard tab
            chrome.tabs.query({ url: "*://*.vercel.app/*" }, (tabs) => {
                tabs.forEach(tab => {
                    chrome.tabs.sendMessage(tab.id, {
                        type: 'LIVE_TELEMETRY_EVENT',
                        payload: {
                            uri: data.url,
                            probability: data.probability,
                            badge: data.badge,
                            badge_class: data.badge_class,
                            features: data.features,
                            geo: data.geo,
                            mode: data.mode
                        }
                    });
                });
            });
            // Also bridge to local dashboard for local testing
            chrome.tabs.query({ url: "*://127.0.0.1:5000/*" }, (tabs) => {
                tabs.forEach(tab => {
                    chrome.tabs.sendMessage(tab.id, {
                        type: 'LIVE_TELEMETRY_EVENT',
                        payload: {
                            uri: data.url,
                            probability: data.probability,
                            badge: data.badge,
                            badge_class: data.badge_class,
                            features: data.features,
                            geo: data.geo,
                            mode: data.mode
                        }
                    });
                });
            });
        })
        .catch(error => {
            console.error("SOC Telemetry Error:", error);
            chrome.action.setBadgeText({text: "ERR"});
            chrome.action.setBadgeBackgroundColor({color: "#ffaa00"});
            setTimeout(() => { updateIcon(); }, 5000);
        });
    }
});
