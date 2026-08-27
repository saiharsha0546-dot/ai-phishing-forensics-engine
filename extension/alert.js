document.addEventListener('DOMContentLoaded', () => {
    const params = new URLSearchParams(window.location.search);
    const url = params.get('url');
    const prob = params.get('prob');
    const tabId = params.get('tabId'); // The original tab id to close

    if (url) {
        document.getElementById('malicious-url').textContent = url;
    }
    
    if (prob) {
        document.getElementById('probability-score').textContent = prob;
    }

    document.getElementById('btn-block').addEventListener('click', () => {
        if (!url) return;
        
        chrome.runtime.sendMessage({
            type: "BLOCK_URL",
            payload: { url, tabId: tabId ? parseInt(tabId) : null }
        }, () => {
            // Close the alert tab after blocking
            window.close();
        });
    });

    document.getElementById('btn-ignore').addEventListener('click', () => {
        window.close();
    });
});
