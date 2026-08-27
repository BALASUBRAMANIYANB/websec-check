import test from "node:test";
import assert from "node:assert";
import { analyzeMethods } from "../src/methods.js";

test("methods.js: analyzeMethods logic", () => {
    // 1. No Allow header
    const res1 = analyzeMethods({});
    assert.strictEqual(res1.deduction, 0);

    // 2. Safe Allow methods
    const res2 = analyzeMethods({ Allow: "GET, POST, OPTIONS" });
    assert.strictEqual(res2.deduction, 0);
    assert.ok(res2.findings.some(f => f.id === "methods-exposed-passive"));

    // 3. Dangerous Allow methods (TRACE)
    const res3 = analyzeMethods({ Allow: "GET, POST, TRACE, OPTIONS" });
    assert.strictEqual(res3.deduction, 2);
    assert.ok(res3.findings.some(f => f.id === "methods-exposed-dangerous"));
});
