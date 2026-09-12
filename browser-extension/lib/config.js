export const DEFAULT_BACKEND_URL = "http://127.0.0.1:8000";
export const BACKEND_STORAGE_KEY = "backendUrl";

const LOOPBACK_HOSTS = new Set(["127.0.0.1", "localhost", "[::1]"]);

export function normalizeBackendUrl(value) {
    const candidate = String(value || "").trim();
    let parsed;
    try {
        parsed = new URL(candidate);
    } catch {
        throw new Error("Enter a complete backend URL, such as http://127.0.0.1:8000.");
    }

    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error("The backend must use HTTP or HTTPS.");
    }
    if (parsed.protocol === "http:" && !LOOPBACK_HOSTS.has(parsed.hostname)) {
        throw new Error("Remote backends must use HTTPS. HTTP is allowed only for local testing.");
    }
    if (parsed.username || parsed.password) {
        throw new Error("Backend URLs cannot contain credentials.");
    }
    if (parsed.pathname !== "/" || parsed.search || parsed.hash) {
        throw new Error("Enter only the backend origin, without a path, query, or fragment.");
    }
    return parsed.origin;
}

export function permissionPattern(backendUrl) {
    return `${normalizeBackendUrl(backendUrl)}/*`;
}

export function predictionEndpoint(backendUrl) {
    return new URL("/api/v1/predict/", `${normalizeBackendUrl(backendUrl)}/`).href;
}

export async function loadBackendUrl(storageArea = chrome.storage.local) {
    const stored = await storageArea.get(BACKEND_STORAGE_KEY);
    return normalizeBackendUrl(stored[BACKEND_STORAGE_KEY] || DEFAULT_BACKEND_URL);
}
