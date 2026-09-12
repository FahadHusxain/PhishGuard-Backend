import assert from "node:assert/strict";
import test from "node:test";

import {analyzeUrl, normalizeTargetUrl} from "../lib/api.js";
import {
    normalizeBackendUrl,
    permissionPattern,
    predictionEndpoint,
} from "../lib/config.js";

test("backend configuration accepts loopback HTTP and normalizes origins", () => {
    assert.equal(normalizeBackendUrl(" http://127.0.0.1:8000 "), "http://127.0.0.1:8000");
    assert.equal(permissionPattern("https://guard.example/"), "https://guard.example/*");
    assert.equal(predictionEndpoint("https://guard.example"), "https://guard.example/api/v1/predict/");
});

test("backend configuration rejects unsafe or ambiguous origins", () => {
    assert.throws(() => normalizeBackendUrl("http://guard.example"), /must use HTTPS/);
    assert.throws(() => normalizeBackendUrl("https://user:secret@guard.example"), /credentials/);
    assert.throws(() => normalizeBackendUrl("https://guard.example/base"), /only the backend origin/);
});

test("target URL validation allows only credential-free HTTP(S) URLs", () => {
    assert.equal(normalizeTargetUrl("https://example.com/login"), "https://example.com/login");
    assert.throws(() => normalizeTargetUrl("chrome://settings"), /Only HTTP and HTTPS/);
    assert.throws(() => normalizeTargetUrl("https://user:pass@example.com"), /credentials/);
});

test("analysis sends the versioned request without credentials or caching", async () => {
    let captured;
    const result = await analyzeUrl({
        backendUrl: "http://localhost:8000",
        targetUrl: "https://example.com/login",
        fetchImpl: async (url, options) => {
            captured = {url, options};
            return new Response(JSON.stringify({status: "UNKNOWN", confidence: 0, message: "Insufficient evidence"}), {
                status: 200,
                headers: {"Content-Type": "application/json"},
            });
        },
    });
    assert.equal(captured.url, "http://localhost:8000/api/v1/predict/");
    assert.equal(captured.options.credentials, "omit");
    assert.equal(captured.options.cache, "no-store");
    assert.deepEqual(JSON.parse(captured.options.body), {url: "https://example.com/login"});
    assert.equal(result.status, "UNKNOWN");
});

test("analysis surfaces controlled backend and malformed-response errors", async () => {
    await assert.rejects(
        analyzeUrl({
            backendUrl: "https://guard.example",
            targetUrl: "https://example.com",
            fetchImpl: async () => new Response(JSON.stringify({error: {message: "Slow down"}}), {status: 429, headers: {"Retry-After": "12"}}),
        }),
        (error) => error.message === "Slow down" && error.retryAfter === "12",
    );
    await assert.rejects(
        analyzeUrl({
            backendUrl: "https://guard.example",
            targetUrl: "https://example.com",
            fetchImpl: async () => new Response("{}", {status: 200}),
        }),
        /invalid analysis response/,
    );
});
