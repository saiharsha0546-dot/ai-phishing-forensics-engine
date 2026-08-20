document.addEventListener('DOMContentLoaded', () => {
    const backendUrlInput = document.getElementById('backendUrl');
    const enableToggle = document.getElementById('enableToggle');
    const saveBtn = document.getElementById('saveBtn');
    const statusDiv = document.getElementById('status');

    // Load saved config
    chrome.storage.local.get(['backendUrl', 'isEnabled'], (result) => {
        if (result.backendUrl) {
            backendUrlInput.value = result.backendUrl;
        } else {
            backendUrlInput.value = "https://ai-phishing-forensics-engine-9dq6.vercel.app";
        }
        
        if (result.isEnabled !== undefined) {
            enableToggle.checked = result.isEnabled;
        } else {
            enableToggle.checked = true;
        }
    });

    // Save config
    saveBtn.addEventListener('click', () => {
        const url = backendUrlInput.value.trim().replace(/\/$/, ""); // remove trailing slash
        const enabled = enableToggle.checked;

        chrome.storage.local.set({
            backendUrl: url,
            isEnabled: enabled
        }, () => {
            statusDiv.textContent = 'Configuration saved!';
            statusDiv.style.color = '#10b981'; // Green
            setTimeout(() => {
                statusDiv.textContent = '';
            }, 2000);
        });
    });
});
