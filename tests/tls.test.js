import test from "node:test";
import assert from "node:assert";
import { EventEmitter } from "node:events";
import { analyzeTls } from "../src/tls.js";

test("tls.js: analyzeTls tests", async (t) => {
    await t.test("Non-HTTPS url returns tls-not-https finding and deduction", async () => {
        const res = await analyzeTls("http://example.com");
        assert.strictEqual(res.deduction, 15);
        assert.ok(res.findings.some(f => f.id === "tls-not-https"));
    });

    await t.test("Valid trusted TLS 1.3 certificate yields 0 deduction", async () => {
        const mockSocket = new EventEmitter();
        mockSocket.destroyed = false;
        mockSocket.authorized = true;
        mockSocket.end = () => {};
        mockSocket.getPeerCertificate = () => ({
            subject: { CN: "example.com" },
            issuer: { O: "Let's Encrypt", CN: "R3" },
            valid_from: "Jan 01 2026 00:00:00 GMT",
            valid_to: "Jan 01 2028 00:00:00 GMT"
        });
        mockSocket.getProtocol = () => "TLSv1.3";
        mockSocket.getCipher = () => ({ name: "TLS_AES_256_GCM_SHA384" });

        const mockConnect = (options, callback) => {
            setImmediate(callback);
            return mockSocket;
        };

        const res = await analyzeTls("https://example.com", 2, mockConnect);
        assert.strictEqual(res.deduction, 0);
        assert.ok(res.findings.some(f => f.id === "tls-trusted-cert"));
        assert.ok(res.findings.some(f => f.id === "tls-protocol-modern"));
        assert.ok(res.findings.some(f => f.id === "tls-cert-validity"));
        assert.strictEqual(res.certificate.subject, "example.com");
    });

    await t.test("Expired and untrusted certificate flags severity and deductions", async () => {
        const mockSocket = new EventEmitter();
        mockSocket.destroyed = false;
        mockSocket.authorized = false;
        mockSocket.authorizationError = "CERT_HAS_EXPIRED";
        mockSocket.end = () => {};
        mockSocket.getPeerCertificate = () => ({
            subject: { CN: "expired.example.com" },
            issuer: { CN: "Self-Signed CA" },
            valid_from: "Jan 01 2020 00:00:00 GMT",
            valid_to: "Jan 01 2021 00:00:00 GMT"
        });
        mockSocket.getProtocol = () => "TLSv1";
        mockSocket.getCipher = () => ({ name: "RC4-SHA" });

        const mockConnect = (options, callback) => {
            setImmediate(callback);
            return mockSocket;
        };

        const res = await analyzeTls("https://expired.example.com", 2, mockConnect);
        assert.ok(res.deduction > 0);
        assert.ok(res.findings.some(f => f.id === "tls-untrusted-cert"));
        assert.ok(res.findings.some(f => f.id === "tls-cert-expired"));
        assert.ok(res.findings.some(f => f.id === "tls-deprecated-protocol"));
    });

    await t.test("Certificate expiring soon flags warning", async () => {
        const soonDate = new Date(Date.now() + 10 * 86400000).toUTCString(); // 10 days in future
        const mockSocket = new EventEmitter();
        mockSocket.destroyed = false;
        mockSocket.authorized = true;
        mockSocket.end = () => {};
        mockSocket.getPeerCertificate = () => ({
            subject: { CN: "renew-soon.com" },
            issuer: { O: "DigiCert" },
            valid_from: "Jan 01 2026 00:00:00 GMT",
            valid_to: soonDate
        });
        mockSocket.getProtocol = () => "TLSv1.2";
        mockSocket.getCipher = () => ({ name: "ECDHE-RSA-AES256-GCM-SHA384" });

        const mockConnect = (options, callback) => {
            setImmediate(callback);
            return mockSocket;
        };

        const res = await analyzeTls("https://renew-soon.com", 2, mockConnect);
        assert.strictEqual(res.deduction, 5);
        assert.ok(res.findings.some(f => f.id === "tls-cert-expiring-soon"));
        assert.ok(res.findings.some(f => f.id === "tls-protocol-secure"));
    });

    await t.test("Handles TLS socket error gracefully without throwing", async () => {
        const mockSocket = new EventEmitter();
        mockSocket.destroyed = false;
        const mockConnect = () => {
            setImmediate(() => mockSocket.emit("error", new Error("ECONNREFUSED")));
            return mockSocket;
        };

        const res = await analyzeTls("https://unreachable.example.com", 2, mockConnect);
        assert.strictEqual(res.deduction, 0);
        assert.ok(res.findings.some(f => f.id === "tls-connection-error"));
    });
});
