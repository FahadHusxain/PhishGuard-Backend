"use strict";

const API_ROOT = "/api/v1";

function byId(id) {
    return document.getElementById(id);
}

function replaceChildren(element, ...children) {
    if (element) {
        element.replaceChildren(...children);
    }
}

function setText(id, value) {
    const element = byId(id);
    if (element) {
        element.textContent = String(value);
    }
}

async function requestJson(url, options = {}) {
    const response = await fetch(url, {
        credentials: "same-origin",
        ...options,
        headers: {Accept: "application/json", ...(options.headers || {})},
    });
    let payload;
    try {
        payload = await response.json();
    } catch {
        payload = null;
    }
    if (!response.ok) {
        const error = new Error(payload?.error?.message || `Request failed (${response.status}).`);
        error.details = payload?.error?.details;
        error.retryAfter = response.headers.get("Retry-After");
        throw error;
    }
    return payload;
}

function percentage(value, total) {
    return total > 0 ? Math.round((value / total) * 100) : 0;
}

function updateProgress(id, value) {
    const progress = byId(`${id}-progress`);
    const label = byId(`${id}-percent`);
    if (progress) {
        progress.value = value;
        progress.textContent = `${value}%`;
    }
    if (label) {
        label.textContent = `${value}%`;
    }
}

function activityItem(log) {
    const item = document.createElement("li");
    item.className = "activity-item";

    const status = document.createElement("span");
    const normalizedStatus = String(log.status || "UNKNOWN").toLowerCase();
    status.className = `activity-status ${normalizedStatus}`;
    status.textContent = log.status || "UNKNOWN";

    const domain = document.createElement("span");
    domain.className = "activity-domain";
    domain.textContent = log.domain || "Unknown domain";

    const metadata = document.createElement("span");
    metadata.className = "activity-meta";
    const timestamp = new Date(log.timestamp);
    const time = Number.isNaN(timestamp.valueOf()) ? "Unknown time" : timestamp.toLocaleTimeString();
    metadata.textContent = `${log.country || "Unknown"} · ${time}`;

    item.append(status, domain, metadata);
    return item;
}

function renderActivity(data) {
    const list = byId("recent-scans");
    if (!list) {
        return;
    }
    if (!data.recent_logs_visible) {
        const item = document.createElement("li");
        item.className = "empty-state";
        item.textContent = "Recent targets require an authorized analyst session.";
        replaceChildren(list, item);
        return;
    }
    if (!data.recent_logs.length) {
        const item = document.createElement("li");
        item.className = "empty-state";
        item.textContent = "No recent activity.";
        replaceChildren(list, item);
        return;
    }
    replaceChildren(list, ...data.recent_logs.map(activityItem));
}

async function refreshStats() {
    const status = byId("stats-status");
    const started = performance.now();
    try {
        const data = await requestJson(`${API_ROOT}/stats/`);
        setText("total-scans", data.total_scans);
        setText("phishing-count", data.phishing_count);
        setText("safe-count", data.safe_count);
        setText("unknown-count", data.unknown_count);
        setText("whitelist-count", `${data.whitelist_count.toLocaleString()} domains`);
        updateProgress("safe", percentage(data.safe_count, data.total_scans));
        updateProgress("phishing", percentage(data.phishing_count, data.total_scans));
        updateProgress("unknown", percentage(data.unknown_count, data.total_scans));
        renderActivity(data);
        if (status) {
            status.textContent = `Online · ${Math.round(performance.now() - started)} ms`;
            status.className = "status-chip online";
        }
    } catch (error) {
        if (status) {
            status.textContent = "Unavailable";
            status.className = "status-chip offline";
            status.title = error.message;
        }
    }
}

function renderScanResult(result, kind, title, message) {
    result.hidden = false;
    result.className = `result result-${kind}`;
    const heading = document.createElement("strong");
    heading.textContent = title;
    const detail = document.createElement("span");
    detail.textContent = message;
    replaceChildren(result, heading, detail);
}

async function submitScan(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = byId("manual-url");
    const button = byId("scan-button");
    const result = byId("scan-result");
    if (!form.reportValidity() || !input || !button || !result) {
        return;
    }

    button.disabled = true;
    button.textContent = "Analyzing…";
    renderScanResult(result, "unknown", "Analyzing URL", "Evaluating structural signals.");
    try {
        const data = await requestJson(`${API_ROOT}/predict/`, {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify({url: input.value.trim()}),
        });
        const confidence = Number.isFinite(Number(data.confidence)) ? `${Number(data.confidence).toFixed(1)}% confidence. ` : "";
        const status = String(data.status || "UNKNOWN").toUpperCase();
        const presentations = {
            SAFE: ["safe", "No strong phishing indicators", confidence + (data.message || "The URL matched a trusted signal.")],
            PHISHING: ["danger", "High-risk URL", confidence + (data.message || "Phishing indicators were detected.")],
            UNKNOWN: ["unknown", "Inconclusive result", data.message || "There is not enough evidence for a reliable verdict."],
        };
        renderScanResult(result, ...(presentations[status] || presentations.UNKNOWN));
        await refreshStats();
    } catch (error) {
        const retry = error.retryAfter ? ` Try again in ${error.retryAfter} seconds.` : "";
        renderScanResult(result, "error", "Unable to analyze URL", `${error.message}${retry}`);
    } finally {
        button.disabled = false;
        button.textContent = "Analyze URL";
    }
}

function resultRow(item) {
    const row = document.createElement("tr");
    const rank = document.createElement("td");
    rank.textContent = `#${item.rank}`;
    const domain = document.createElement("td");
    domain.textContent = item.domain;
    row.append(rank, domain);
    return row;
}

async function submitSearch(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const input = byId("domain-query");
    const button = byId("search-button");
    const status = byId("search-status");
    const results = byId("domain-results");
    if (!form.reportValidity() || !input || !button || !status || !results) {
        return;
    }

    button.disabled = true;
    status.textContent = "Searching…";
    try {
        const data = await requestJson(`${API_ROOT}/search-db/?q=${encodeURIComponent(input.value.trim())}`);
        if (data.length) {
            replaceChildren(results, ...data.map(resultRow));
            status.textContent = `${data.length} result${data.length === 1 ? "" : "s"} found.`;
        } else {
            const row = document.createElement("tr");
            const cell = document.createElement("td");
            cell.colSpan = 2;
            cell.textContent = "No matching trusted domains.";
            row.append(cell);
            replaceChildren(results, row);
            status.textContent = "No results found.";
        }
    } catch (error) {
        status.textContent = error.message;
    } finally {
        button.disabled = false;
    }
}

const scanForm = byId("scan-form");
if (scanForm) {
    scanForm.addEventListener("submit", submitScan);
}

const searchForm = byId("search-form");
if (searchForm) {
    searchForm.addEventListener("submit", submitSearch);
}

refreshStats();
window.setInterval(refreshStats, 15000);
