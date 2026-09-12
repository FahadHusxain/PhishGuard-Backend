import {predictionEndpoint} from "./config.js";

export function normalizeTargetUrl(value) {
    const candidate = String(value || "").trim();
    let parsed;
    try {
        parsed = new URL(candidate);
    } catch {
        throw new Error("Enter a complete web address beginning with http:// or https://.");
    }
    if (!['http:', 'https:'].includes(parsed.protocol)) {
        throw new Error("Only HTTP and HTTPS pages can be analyzed.");
    }
    if (parsed.username || parsed.password) {
        throw new Error("Links containing embedded credentials are not accepted.");
    }
    if (candidate.length > 500) {
        throw new Error("The URL cannot exceed 500 characters.");
    }
    return parsed.href;
}

function errorMessage(payload, status) {
    return payload?.error?.message || `The PhishGuard service returned HTTP ${status}.`;
}

export async function analyzeUrl({
    backendUrl,
    targetUrl,
    fetchImpl = fetch,
    timeoutMs = 10000,
}) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), timeoutMs);
    let response;
    try {
        response = await fetchImpl(predictionEndpoint(backendUrl), {
            method: "POST",
            headers: {Accept: "application/json", "Content-Type": "application/json"},
            body: JSON.stringify({url: normalizeTargetUrl(targetUrl)}),
            cache: "no-store",
            credentials: "omit",
            signal: controller.signal,
        });
    } catch (error) {
        if (error?.name === "AbortError") {
            throw new Error("The analysis timed out. Check the backend and try again.");
        }
        throw new Error("Cannot reach the PhishGuard backend. Check its address and status.");
    } finally {
        clearTimeout(timeout);
    }

    let payload = null;
    try {
        payload = await response.json();
    } catch {
        // A controlled fallback below avoids exposing an untrusted response body.
    }
    if (!response.ok) {
        const error = new Error(errorMessage(payload, response.status));
        error.retryAfter = response.headers.get("Retry-After");
        throw error;
    }
    if (!payload || !["SAFE", "PHISHING", "UNKNOWN"].includes(payload.status)) {
        throw new Error("The backend returned an invalid analysis response.");
    }
    if (
        (payload.domain_listed !== undefined && typeof payload.domain_listed !== "boolean")
        || (payload.domain_context !== undefined && typeof payload.domain_context !== "string")
    ) {
        throw new Error("The backend returned invalid domain context.");
    }
    return payload;
}
