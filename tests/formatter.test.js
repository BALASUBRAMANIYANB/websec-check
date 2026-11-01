import test from "node:test";
import assert from "node:assert";
import { formatSarif, formatMarkdown, formatJson, formatTerminal } from "../src/formatter.js";

test("formatter.js: Output formats validation", async (t) => {
    const mockScanResult = {
        url: "https://example.com",
        finalUrl: "https://example.com/",
        status: 200,
        responseTimeMs: 142,
        server: "nginx",
        score: 85,
        riskLevel: "LOW",
        tlsResult: {
            certificate: {
                subject: "example.com",
                issuer: "Let's Encrypt",
                protocol: "TLSv1.3",
                cipher: "TLS_AES_256_GCM_SHA384",
                validTo: "2028-01-01"
            }
        },
        findings: [
            {
                id: "hsts-present",
                category: "Headers",
                name: "Strict-Transport-Security",
                status: "PASS",
                severity: "INFO",
                points: 20,
                maxPoints: 20,
                description: "HSTS header is properly set with max-age >= 180 days.",
                recommendation: null,
                evidence: "max-age=31536000"
            },
            {
                id: "missing-csp",
                category: "Headers",
                name: "Content-Security-Policy",
                status: "MISSING",
                severity: "HIGH",
                points: 0,
                maxPoints: 25,
                description: "Content-Security-Policy header is missing.",
                recommendation: "Implement CSP with default-src 'self'.",
                evidence: null
            }
        ]
    };

    await t.test("formatJson outputs valid JSON adhering to schema", () => {
        const jsonStr = formatJson(mockScanResult, "1.2.0");
        const parsed = JSON.parse(jsonStr);
        assert.strictEqual(parsed.tool.name, "websec-check");
        assert.strictEqual(parsed.score.value, 85);
        assert.strictEqual(parsed.score.risk, "LOW");
        assert.strictEqual(parsed.findings.length, 2);
    });

    await t.test("formatSarif generates valid OASIS SARIF v2.1.0 output", () => {
        const sarifStr = formatSarif(mockScanResult, "1.2.0");
        const sarif = JSON.parse(sarifStr);
        assert.strictEqual(sarif.version, "2.1.0");
        assert.ok(sarif.runs && sarif.runs.length > 0);
        const run = sarif.runs[0];
        assert.strictEqual(run.tool.driver.name, "websec-check");
        assert.ok(run.results.some(r => r.ruleId === "missing-csp"));
        assert.strictEqual(run.results[0].level, "error");
    });

    await t.test("formatMarkdown creates clean GitHub Flavored Markdown report", () => {
        const md = formatMarkdown(mockScanResult, "1.2.0");
        assert.ok(md.includes("# 🛡️ WebSec Check Security Audit Report"));
        assert.ok(md.includes("85/100"));
        assert.ok(md.includes("Content-Security-Policy"));
        assert.ok(md.includes("Remediation Steps"));
        assert.ok(md.includes("TLSv1.3"));
    });

    await t.test("formatTerminal outputs colored/uncolored console logs", () => {
        const term = formatTerminal(mockScanResult, false, true);
        assert.ok(term.includes("WEBSEC CHECK"));
        assert.ok(term.includes("Security Score: 85/100"));
        assert.ok(term.includes("Recommendations"));
    });
});
