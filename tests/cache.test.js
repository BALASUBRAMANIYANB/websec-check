import test from "node:test";
import assert from "node:assert";
import { analyzeCache } from "../src/cache.js";

test("cache.js: analyzeCache logic", () => {
    // 1. Missing Cache-Control
    const res1 = analyzeCache({});
    assert.strictEqual(res1.deduction, 1);
    assert.ok(res1.findings.some(f => f.id === "cache-missing-control"));

    // 2. Cache-Control with public policy
    const res2 = analyzeCache({ "Cache-Control": "public, max-age=3600" });
    assert.strictEqual(res2.deduction, 0);
    assert.ok(res2.findings.some(f => f.id === "cache-policy-public"));

    // 3. Cache-Control private / restrictive policy
    const res3 = analyzeCache({ "Cache-Control": "no-store, private" });
    assert.strictEqual(res3.deduction, 0);
    assert.strictEqual(res3.findings.filter(f => f.id === "cache-policy-public").length, 0);
});
