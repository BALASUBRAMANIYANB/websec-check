import test from "node:test";
import assert from "node:assert";
import { validateUrl, parseArgs } from "../src/utils.js";

test("utils.js: URL Validation", () => {
    // Valid cases
    assert.strictEqual(validateUrl("http://localhost"), true);
    assert.strictEqual(validateUrl("https://example.com/some/path?query=1"), true);

    // Invalid cases
    assert.strictEqual(validateUrl("hello"), false);
    assert.strictEqual(validateUrl("example.com"), false);
    assert.strictEqual(validateUrl("ftp://example.com"), false);
    assert.strictEqual(validateUrl("file:///etc/passwd"), false);
    assert.strictEqual(validateUrl("javascript:alert(1)"), false);
});

test("utils.js: Option Parsing", () => {
    // Basic URL parsing without options
    const res1 = parseArgs(["https://example.com"]);
    assert.strictEqual(res1.url, "https://example.com");
    assert.strictEqual(res1.options.help, false);
    assert.strictEqual(res1.options.version, false);
    assert.strictEqual(res1.options.json, false);
    assert.strictEqual(res1.options.verbose, false);
    assert.strictEqual(res1.options.timeout, 10);
    assert.strictEqual(res1.error, null);

    // Options after URL
    const res2 = parseArgs(["https://example.com", "--verbose", "--json"]);
    assert.strictEqual(res2.url, "https://example.com");
    assert.strictEqual(res2.options.verbose, true);
    assert.strictEqual(res2.options.json, true);
    assert.strictEqual(res2.error, null);

    // Options before URL
    const res3 = parseArgs(["--verbose", "https://example.com"]);
    assert.strictEqual(res3.url, "https://example.com");
    assert.strictEqual(res3.options.verbose, true);
    assert.strictEqual(res3.error, null);

    // Timeout option override
    const res4 = parseArgs(["https://example.com", "--timeout", "15"]);
    assert.strictEqual(res4.options.timeout, 15);
    assert.strictEqual(res4.error, null);

    // Invalid timeout option
    const res5 = parseArgs(["https://example.com", "--timeout", "abc"]);
    assert.ok(res5.error !== null);
    assert.ok(res5.error.includes("Invalid timeout"));

    // Negative timeout option
    const res6 = parseArgs(["https://example.com", "--timeout", "-5"]);
    assert.ok(res6.error !== null);

    // Unknown option
    const res7 = parseArgs(["https://example.com", "--abc"]);
    assert.strictEqual(res7.error, "Unknown option: --abc");
});
