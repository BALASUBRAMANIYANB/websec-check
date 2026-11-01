import test from "node:test";
import assert from "node:assert";
import { analyzeHeaders } from "../src/headers.js";
import { scanWebsite } from "../src/scanner.js";

test("headers.js: analyzeHeaders logic", () => {
    // 1. All missing
    const res1 = analyzeHeaders({});
    assert.strictEqual(res1.score, 0);
    assert.ok(res1.findings.some(f => f.id === "missing-hsts"));
    assert.ok(res1.findings.some(f => f.id === "missing-csp"));

    // 2. Weak/Invalid cases
    const res2 = analyzeHeaders({
        "Strict-Transport-Security": "max-age=3600", // too short (1 hour)
        "Content-Security-Policy": "default-src 'self' 'unsafe-inline'", // weak
        "X-Content-Type-Options": "invalid-nosniff", // invalid
        "X-Frame-Options": "ALLOW-FROM https://bad.com", // invalid
        "Referrer-Policy": "unsafe-url", // weak
    });
    // STS (10 pts) + CSP (15 pts) + XCTO (0 pts) + XFO (0 pts) + Ref (3 pts) + Perm (0 pts) = 28 points
    assert.strictEqual(res2.score, 28);
    assert.ok(res2.findings.some(f => f.id === "weak-hsts-short-duration"));
    assert.ok(res2.findings.some(f => f.id === "review-csp-permissive-policy"));
    assert.ok(res2.findings.some(f => f.id === "invalid-xcto"));
    assert.ok(res2.findings.some(f => f.id === "invalid-xfo"));
    assert.ok(res2.findings.some(f => f.id === "weak-ref-policy-unsafe-url"));

    // 3. CSP frame-ancestors mitigates missing X-Frame-Options
    const res3 = analyzeHeaders({
        "Content-Security-Policy": "default-src 'self'; frame-ancestors 'self'",
        "Strict-Transport-Security": "max-age=31536000",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Permissions-Policy": "geolocation=()"
    });
    // STS (20) + CSP (25) + XCTO (15) + XFO (15 - because frame-ancestors mitigates missing XFO!) + Referrer (10) + Perm (15) = 100 points
    assert.strictEqual(res3.score, 100);
    assert.ok(res3.findings.some(f => f.id === "xfo-missing-but-csp-frame-ancestors"));
    assert.strictEqual(res3.findings.some(f => f.id === "missing-xfo"), false);
});

test("scanner.js: Integration & dynamic mock response tests", async (t) => {
    // Mock fetch dispatcher simulating HTTP responses deterministically
    const mockFetch = async (targetUrl, init = {}) => {
        const urlParams = new URL(targetUrl).searchParams;
        const testCase = urlParams.get("case");

        if (testCase === "all-pass") {
            const h = new Headers({
                "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
                "Content-Security-Policy": "default-src 'self'",
                "X-Content-Type-Options": "nosniff",
                "X-Frame-Options": "DENY",
                "Referrer-Policy": "strict-origin-when-cross-origin",
                "Permissions-Policy": "microphone=()",
                "Access-Control-Allow-Origin": "https://trusted.com",
                "Cache-Control": "no-store"
            });
            h.append("Set-Cookie", "session=secret; Secure; HttpOnly; SameSite=Strict");
            return new Response("ALL OK", { status: 200, headers: h });
        }

        if (testCase === "insecure-cookies-cors") {
            const h = new Headers({
                "Content-Type": "text/html",
                "Access-Control-Allow-Origin": "*",
                "Access-Control-Allow-Credentials": "true"
            });
            h.append("Set-Cookie", "auth_token=supersecret");
            h.append("Set-Cookie", "theme=light");
            return new Response("INSECURE", { status: 200, headers: h });
        }

        if (testCase === "redirect-1") {
            const h = new Headers({
                "Location": "https://example.com/?case=redirect-2"
            });
            return new Response(null, { status: 302, headers: h });
        }

        if (testCase === "redirect-2") {
            const h = new Headers({ "Content-Type": "text/plain" });
            return new Response("FINAL LANDING", { status: 200, headers: h });
        }

        if (testCase === "delay") {
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    resolve(new Response("DELAYED RESPONSE", { status: 200 }));
                }, 1000);

                if (init.signal) {
                    init.signal.addEventListener("abort", () => {
                        clearTimeout(timer);
                        const abortErr = new Error("The operation was aborted");
                        abortErr.name = "AbortError";
                        reject(abortErr);
                    });
                }
            });
        }

        return new Response("NOT FOUND", { status: 404 });
    };

    await t.test("Verify ideal headers, cookies, and CORS yield high score", async () => {
        const result = await scanWebsite("https://example.com/?case=all-pass", 5, "1.2.0", 5, {
            skipTls: true,
            fetchFn: mockFetch
        });
        assert.strictEqual(result.status, 200);
        assert.strictEqual(result.score, 100);
        assert.strictEqual(result.riskLevel, "LOW");
        assert.strictEqual(result.cookiesResult.deduction, 0);
        assert.strictEqual(result.corsResult.deduction, 0);
    });

    await t.test("Verify wildcard Cors with credentials and missing HttpOnly deduction", async () => {
        const result = await scanWebsite("https://example.com/?case=insecure-cookies-cors", 5, "1.2.0", 5, {
            skipTls: true,
            fetchFn: mockFetch
        });
        // Headers: STS (0), CSP (0), XCTO (0), XFO (0), Ref (0), Perm (0) -> Header score = 0
        // Cookies: "auth_token" sensitive missing Secure & HttpOnly & SameSite -> deduction = 10 + 10 + 5 = 25 (capped at 20)
        // CORS: wildcard origin + credentials -> deduction = 10
        // scoring calculations: 0 - 20 (cookies) - 10 (cors) -> 0 points (min boundary check)
        assert.strictEqual(result.status, 200);
        assert.strictEqual(result.score, 0);
        assert.strictEqual(result.riskLevel, "HIGH");
        assert.ok(result.cookiesResult.findings.some(f => f.id.includes("auth-token") || f.id.includes("auth_token")));
        assert.strictEqual(result.cookiesResult.deduction, 20); // capped
        assert.strictEqual(result.corsResult.deduction, 10);
    });

    await t.test("Verify redirection chain is tracked", async () => {
        const result = await scanWebsite("https://example.com/?case=redirect-1", 5, "1.2.0", 5, {
            skipTls: true,
            fetchFn: mockFetch
        });
        assert.strictEqual(result.status, 200);
        assert.strictEqual(result.redirectChain.length, 1);
        assert.ok(result.redirectChain[0].url.includes("case=redirect-2"));
    });

    await t.test("Verify timeout aborts request", async () => {
        await assert.rejects(
            scanWebsite("https://example.com/?case=delay", 0.05, "1.2.0", 5, {
                skipTls: true,
                fetchFn: mockFetch
            }),
            (err) => err.name === "AbortError" || err.message.includes("abort")
        );
    });
});
