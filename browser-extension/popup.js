import {analyzeUrl, isAnalyzeShortcut, normalizeTargetUrl} from "./lib/api.js";
import {loadBackendUrl} from "./lib/config.js";

const byId = (id) => document.getElementById(id);

function replaceText(id, value) {
    byId(id).textContent = String(value ?? "");
}

function setScanButton(text) {
    const label = byId("scan-button").querySelector("span");
    if (label) {
        label.textContent = text;
    }
}

function setScanStage(text, scanning = false) {
    replaceText("scan-stage", text);
    byId("scan-visual").classList.toggle("is-scanning", scanning);
}

function detail(label, value) {
    const wrapper = document.createElement("div");
    const term = document.createElement("dt");
    const description = document.createElement("dd");
    term.textContent = label;
    description.textContent = value;
    wrapper.append(term, description);
    return wrapper;
}

function renderResult(payload) {
    const result = byId("result");
    const status = String(payload.status || "UNKNOWN").toUpperCase();
    const presentations = {
        SAFE: {mark: "✓", title: "Low-risk official address"},
        PHISHING: {mark: "!", title: "High-risk link detected"},
        UNKNOWN: {mark: "?", title: "Result is inconclusive"},
    };
    const presentation = presentations[status] || presentations.UNKNOWN;
    result.hidden = false;
    result.dataset.verdict = status;
    replaceText("verdict-label", status === "UNKNOWN" ? "Use caution" : "Verdict");
    replaceText("verdict-mark", presentation.mark);
    replaceText("verdict-title", presentation.title);
    const confidenceSuffix = payload.confidence_basis === "policy-assurance" ? " policy" : "";
    replaceText("confidence", Number.isFinite(Number(payload.confidence)) ? `${Number(payload.confidence).toFixed(1)}%${confidenceSuffix}` : "");
    replaceText("result-message", payload.message || "No explanation was provided.");
    const domainContext = byId("domain-context");
    domainContext.hidden = !payload.domain_context;
    domainContext.dataset.listed = String(payload.domain_listed === true);
    domainContext.textContent = payload.domain_context || "";

    const details = byId("result-details");
    details.replaceChildren(
        detail("Engine", payload.engine || "not reported"),
        detail("Country", payload.country || "Unknown"),
        detail("Risk", Number.isFinite(Number(payload.risk_score)) ? `${Number(payload.risk_score).toFixed(1)}/100` : "not reported"),
    );
    const signals = Array.isArray(payload.signals) ? payload.signals.slice(0, 6) : [];
    byId("signals").replaceChildren(...signals.map((signal) => {
        const item = document.createElement("li");
        item.textContent = String(signal);
        return item;
    }));
}

function setConnection(message, isError = false) {
    const status = byId("connection-status");
    status.textContent = message;
    status.className = `connection-status${isError ? " error" : ""}`;
}

async function currentTabUrl() {
    const [tab] = await chrome.tabs.query({active: true, currentWindow: true});
    return tab?.url || "";
}

async function initialize() {
    try {
        const backendUrl = await loadBackendUrl();
        setConnection(`Backend: ${backendUrl}`);
    } catch (error) {
        setConnection(error.message, true);
    }
    try {
        const tabUrl = await currentTabUrl();
        byId("target-url").value = normalizeTargetUrl(tabUrl);
    } catch {
        byId("target-url").placeholder = "https://example.com/login";
        setConnection("This browser page cannot be scanned automatically. Paste an HTTP(S) link instead.", true);
    }
}

async function submitScan(event) {
    event.preventDefault();
    const input = byId("target-url");
    const button = byId("scan-button");
    button.disabled = true;
    setScanButton("Analyzing…");
    setScanStage("PARSING TARGET", true);
    const stages = ["MAPPING SIGNALS", "CALCULATING RISK"];
    let stageIndex = 0;
    const stageTimer = window.setInterval(() => {
        setScanStage(stages[Math.min(stageIndex, stages.length - 1)], true);
        stageIndex += 1;
    }, 260);
    byId("result").hidden = true;
    try {
        const backendUrl = await loadBackendUrl();
        const payload = await analyzeUrl({backendUrl, targetUrl: input.value});
        renderResult(payload);
        setScanStage("VERDICT READY");
        setConnection(`Connected securely to ${backendUrl}`);
    } catch (error) {
        const retry = error.retryAfter ? ` Try again in ${error.retryAfter} seconds.` : "";
        setScanStage("ANALYSIS INTERRUPTED");
        setConnection(`${error.message}${retry}`, true);
    } finally {
        window.clearInterval(stageTimer);
        button.disabled = false;
        setScanButton("Analyze URL");
    }
}

byId("scan-form").addEventListener("submit", submitScan);
byId("target-url").addEventListener("keydown", (event) => {
    if (!isAnalyzeShortcut(event)) {
        return;
    }
    event.preventDefault();
    if (!byId("scan-button").disabled) {
        byId("scan-form").requestSubmit();
    }
});
byId("settings-button").addEventListener("click", () => chrome.runtime.openOptionsPage());
initialize();
