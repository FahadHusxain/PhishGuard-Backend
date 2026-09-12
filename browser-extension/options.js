import {
    BACKEND_STORAGE_KEY,
    loadBackendUrl,
    normalizeBackendUrl,
    permissionPattern,
} from "./lib/config.js";

const form = document.getElementById("settings-form");
const input = document.getElementById("backend-url");
const status = document.getElementById("save-status");
let savedBackendUrl = null;

function showStatus(message, isError = false) {
    status.textContent = message;
    status.className = isError ? "error" : "";
}

async function initialize() {
    try {
        savedBackendUrl = await loadBackendUrl();
        input.value = savedBackendUrl;
    } catch (error) {
        showStatus(error.message, true);
    }
}

async function saveSettings(event) {
    event.preventDefault();
    showStatus("");
    try {
        const backendUrl = normalizeBackendUrl(input.value);
        if (backendUrl.startsWith("https://")) {
            const origins = [permissionPattern(backendUrl)];
            const granted = await chrome.permissions.request({origins});
            if (!granted) {
                throw new Error("Permission was not granted, so the backend was not changed.");
            }
        }
        await chrome.storage.local.set({[BACKEND_STORAGE_KEY]: backendUrl});
        if (savedBackendUrl?.startsWith("https://") && savedBackendUrl !== backendUrl) {
            await chrome.permissions.remove({
                origins: [permissionPattern(savedBackendUrl)],
            });
        }
        savedBackendUrl = backendUrl;
        input.value = backendUrl;
        showStatus("Backend saved. You can return to the extension popup.");
    } catch (error) {
        showStatus(error.message, true);
    }
}

form.addEventListener("submit", saveSettings);
initialize();
