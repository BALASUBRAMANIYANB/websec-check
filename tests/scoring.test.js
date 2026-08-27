import test from "node:test";
import assert from "node:assert";
import { calculateScore } from "../src/scoring.js";

test("scoring.js: calculateScore thresholds", () => {
    // 100 -> LOW Risk
    const r1 = calculateScore({ headersScore: 100 });
    assert.strictEqual(r1.score, 100);
    assert.strictEqual(r1.riskLevel, "LOW");

    // 80 -> LOW Risk
    const r2 = calculateScore({ headersScore: 80 });
    assert.strictEqual(r2.score, 80);
    assert.strictEqual(r2.riskLevel, "LOW");

    // 79 -> MEDIUM Risk
    const r3 = calculateScore({ headersScore: 79 });
    assert.strictEqual(r3.score, 79);
    assert.strictEqual(r3.riskLevel, "MEDIUM");

    // 60 -> MEDIUM Risk
    const r4 = calculateScore({ headersScore: 60 });
    assert.strictEqual(r4.score, 60);
    assert.strictEqual(r4.riskLevel, "MEDIUM");

    // 59 -> HIGH Risk
    const r5 = calculateScore({ headersScore: 59 });
    assert.strictEqual(r5.score, 59);
    assert.strictEqual(r5.riskLevel, "HIGH");

    // 0 -> HIGH Risk
    const r6 = calculateScore({ headersScore: 0 });
    assert.strictEqual(r6.score, 0);
    assert.strictEqual(r6.riskLevel, "HIGH");
});

test("scoring.js: calculateScore with deductions", () => {
    // Deductions resulting in Medium risk (e.g. 90 headersScore - 20 cookies - 5 cors = 65 score)
    const r1 = calculateScore({ headersScore: 90, cookieDeduction: 20, corsDeduction: 5 });
    assert.strictEqual(r1.score, 65);
    assert.strictEqual(r1.riskLevel, "MEDIUM");

    // Underflow protection (score below 0 is clamped to 0)
    const r2 = calculateScore({ headersScore: 10, cookieDeduction: 20, corsDeduction: 10 });
    assert.strictEqual(r2.score, 0);
    assert.strictEqual(r2.riskLevel, "HIGH");
});
