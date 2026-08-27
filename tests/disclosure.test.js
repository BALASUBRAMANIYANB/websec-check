import test from "node:test";
import assert from "node:assert";
import { analyzeDisclosure } from "../src/disclosure.js";

test("disclosure.js: analyzeDisclosure logic", () => {
    // 1. None disclosed
    const res1 = analyzeDisclosure({});
    assert.strictEqual(res1.deduction, 0);

    // 2. Generic server disclosure
    const res2 = analyzeDisclosure({ Server: "nginx" });
    assert.strictEqual(res2.deduction, 1);
    assert.ok(res2.findings.some(f => f.id === "server-disclosure-generic"));

    // 3. Detailed server disclosure
    const res3 = analyzeDisclosure({ Server: "Apache/2.4.41 (Ubuntu)" });
    assert.strictEqual(res3.deduction, 4);
    assert.ok(res3.findings.some(f => f.id === "server-disclosure-detailed"));

    // 4. Powered by header
    const res4 = analyzeDisclosure({ "X-Powered-By": "PHP/7.4.3" });
    assert.strictEqual(res4.deduction, 3);
    assert.ok(res4.findings.some(f => f.id === "powered-by-detailed"));

    // 5. ASP.NET framework version
    const res5 = analyzeDisclosure({ "X-AspNet-Version": "4.0.30319" });
    assert.strictEqual(res5.deduction, 3);
    assert.ok(res5.findings.some(f => f.id === "aspnet-version-disclosure"));
});
