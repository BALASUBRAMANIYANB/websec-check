#!/usr/bin/env node

import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { validateUrl, parseArgs } from "../src/utils.js";
import { scanWebsite } from "../src/scanner.js";
import { formatTerminal, formatJson, formatError } from "../src/formatter.js";

// Read version dynamically from package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, "../package.json"), "utf8"));
const version = pkg.version;

const args = process.argv.slice(2);
const { url, options, error } = parseArgs(args);

const USAGE = `WebSec Check

Usage:
  websec-check <URL> [options]

Options:
  --help                 Show help
  --version              Show version
  --json                 Output machine-readable JSON
  --verbose              Show additional response information
  --timeout <seconds>    Set request timeout (default: 10)
  --no-color             Disable colored console output
  --max-redirects <num>  Set maximum redirect hops limit (default: 5)

Examples:
  websec-check https://example.com
  websec-check https://example.com --json
  websec-check https://example.com --verbose
  websec-check https://example.com --timeout 15
  websec-check https://example.com --no-color
  websec-check https://example.com --max-redirects 5`;

// 1. Handle command line argument parsing errors
if (error) {
    formatError(`[ERROR] ${error}\n\n${USAGE}`, options.json);
    process.exit(2); // CLI usage error
}

// 2. Handle --help option
if (options.help) {
    if (options.json) {
        formatError(`[ERROR] --help is incompatible with --json output mode`, true);
        process.exit(2);
    }
    console.log(USAGE);
    process.exit(0);
}

// 3. Handle --version option
if (options.version) {
    if (options.json) {
        console.log(JSON.stringify({ version }, null, 2));
    } else {
        console.log(version);
    }
    process.exit(0);
}

// 4. Validate URL presence
if (!url) {
    formatError(`[ERROR] Missing target URL.\n\n${USAGE}`, options.json);
    process.exit(2); // CLI usage error
}

// 5. Validate URL protocol, structure, and check SSRF rules
if (!validateUrl(url)) {
    const errorMsg = `[ERROR] Invalid URL.

Please provide a valid, public HTTP or HTTPS URL (local/private IPs are restricted).

Example:
  websec-check https://example.com`;
    formatError(errorMsg, options.json);
    process.exit(2); // CLI usage error
}

// 6. Execute vulnerability assessment scan
async function run() {
    try {
        const result = await scanWebsite(url, options.timeout, version, options.maxRedirects);

        if (options.json) {
            formatJson(result, version);
        } else {
            formatTerminal(result, options.verbose, options.noColor);
        }
        process.exit(0);
    } catch (err) {
        let errorMsg = `[ERROR] Unable to connect to target: ${url}`;

        if (err.name === "AbortError") {
            errorMsg = `[ERROR] Request timed out after ${options.timeout} seconds.`;
        } else if (err.code === "ENOTFOUND") {
            errorMsg = `[ERROR] Could not resolve the target hostname.`;
        } else if (err.code === "ECONNREFUSED") {
            errorMsg = `[ERROR] Connection refused by target server.`;
        } else if (err.code === "EPROTO" || err.message.includes("TLS") || err.message.includes("ssl")) {
            errorMsg = `[ERROR] TLS connection failed.`;
        } else if (err.message) {
            errorMsg = `[ERROR] Connection failed: ${err.message}`;
        }

        formatError(errorMsg, options.json);
        process.exit(1); // runtime error
    }
}

run();
