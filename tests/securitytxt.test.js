import test from "node:test";
import assert from "node:assert";
import http from "node:http";
import { analyzeSecurityTxt } from "../src/securitytxt.js";

test("securitytxt.js: Passive retrieval integration", async (t) => {
    // Start local server that responds dynamically
    const server = http.createServer((req, res) => {
        if (req.url === "/.well-known/security.txt") {
            res.writeHead(200, { "Content-Type": "text/plain" });
            res.end("Contact: security@example.com");
        } else {
            res.writeHead(404);
            res.end("NOT FOUND");
        }
    });

    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const port = server.address().port;
    const baseUrl = `http://127.0.0.1:${port}`;

    try {
        await t.test("Verify successful security.txt find", async () => {
            const res = await analyzeSecurityTxt(baseUrl, 2);
            assert.strictEqual(res.deduction, 0);
            assert.ok(res.findings.some(f => f.id === "securitytxt-ok"));
        });

        await t.test("Verify missing security.txt fallback", async () => {
            const res = await analyzeSecurityTxt("http://127.0.0.1:9999", 1); // invalid port
            assert.strictEqual(res.deduction, 0);
            assert.ok(res.findings.some(f => f.id === "securitytxt-missing"));
        });
    } finally {
        server.close();
    }
});
