import test from "node:test";
import assert from "node:assert";
import { analyzeSecurityTxt } from "../src/securitytxt.js";

test("securitytxt.js: Passive retrieval integration", async (t) => {
    const mockFetch = async (url) => {
        if (url.includes("/.well-known/security.txt") && !url.includes("missing")) {
            return new Response("Contact: security@example.com\nExpires: 2027-01-01T00:00:00.000Z", {
                status: 200,
                headers: { "Content-Type": "text/plain" }
            });
        }
        return new Response("NOT FOUND", { status: 404 });
    };

    await t.test("Verify successful security.txt find", async () => {
        const res = await analyzeSecurityTxt("https://example.com", 2, mockFetch);
        assert.strictEqual(res.deduction, 0);
        assert.ok(res.findings.some(f => f.id === "securitytxt-ok"));
    });

    await t.test("Verify missing security.txt fallback", async () => {
        const res = await analyzeSecurityTxt("https://missing.example.com", 1, mockFetch);
        assert.strictEqual(res.deduction, 0);
        assert.ok(res.findings.some(f => f.id === "securitytxt-missing"));
    });
});
