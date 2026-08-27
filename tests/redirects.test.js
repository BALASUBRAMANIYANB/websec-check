import test from "node:test";
import assert from "node:assert";
import { analyzeRedirects } from "../src/redirects.js";

test("redirects.js: analyzeRedirects logic", () => {
    // 1. Ideal HTTPS state (no redirect)
    const res1 = analyzeRedirects([], "https://example.com", "https://example.com");
    assert.strictEqual(res1.deduction, 0);

    // 2. HTTP specifying upgrade (not local)
    const res2 = analyzeRedirects(
        [{ url: "https://example.com", status: 301, headers: {} }],
        "http://example.com",
        "https://example.com"
    );
    assert.strictEqual(res2.deduction, 0);
    assert.ok(res2.findings.some(f => f.id === "redirect-http-to-https"));

    // 3. HTTP target missing upgrade
    const res3 = analyzeRedirects(
        [],
        "http://example.com",
        "http://example.com"
    );
    assert.strictEqual(res3.deduction, 5);
    assert.ok(res3.findings.some(f => f.id === "redirect-missing-http-upgrade"));

    // 4. HTTPS to HTTP downgrade
    const res4 = analyzeRedirects(
        [{ url: "http://example.com/login", status: 302, headers: {} }],
        "https://example.com",
        "http://example.com/login"
    );
    assert.strictEqual(res4.deduction, 10);
    assert.ok(res4.findings.some(f => f.id === "redirect-https-to-http"));

    // 5. Cross-origin redirect
    const res5 = analyzeRedirects(
        [{ url: "https://external.com", status: 302, headers: {} }],
        "https://example.com",
        "https://external.com"
    );
    assert.ok(res5.findings.some(f => f.id === "redirect-cross-origin"));

    // 6. Chain length warning
    const res6 = analyzeRedirects(
        [
            { url: "https://example.com/1", status: 302 },
            { url: "https://example.com/2", status: 302 },
            { url: "https://example.com/3", status: 302 },
            { url: "https://example.com/4", status: 302 },
            { url: "https://example.com/5", status: 302 }
        ],
        "https://example.com",
        "https://example.com/5"
    );
    assert.strictEqual(res6.deduction, 2);
    assert.ok(res6.findings.some(f => f.id === "redirect-chain-long"));
});
