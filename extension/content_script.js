// Listen for messages from the extension background script
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === 'LIVE_TELEMETRY_EVENT') {
        // Forward the message to the webpage's window context
        window.postMessage({
            source: 'soc-extension',
            payload: request.payload
        }, '*');
    }
});
