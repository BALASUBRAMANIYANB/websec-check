#!/usr/bin/env node

import { readFileSync, writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { validateUrl, parseArgs } from "../src/utils.js";
import { scanWebsite } from "../src/scanner.js";
import { formatTerminal, formatJson, formatSarif, formatMarkdown, formatError } from "../src/formatter.js";

// Read version dynamically from package.json
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const pkg = JSON.parse(readFileSync(join(__dirname, "../package.json"), "utf8"));
const version = pkg.version;

const args = process.argv.slice(2);
const { url, options, error } = parseArgs(args);

const USAGE = `WebSec Check v${version}
A zero-dependency CLI tool for passive web security and TLS configuration audits.

Usage:
  websec-check <URL> [options]

Options:
  -h, --help                 Show help
  -v, --version              Show version
  --format <type>            Output format: terminal, json, sarif, markdown (default: terminal)
  --json                     Output JSON (alias for --format json)
  -o, --output <path>        Write report to specified file path
  --fail-below <score>       Exit with code 1 if security score is below threshold (0-100)
  --skip-tls                 Bypass TLS/SSL certificate verification
  --verbose                  Show handshake details, response timings, and evidence
  --timeout <seconds>        Set connection timeout in seconds (default: 10)
  --no-color                 Disable colored terminal styling output
  --max-redirects <num>      Set maximum redirection hops limit (default: 5)

Examples:
  # Standard audit
  websec-check https://example.com

  # CI/CD Quality Gate (fail if score < 80)
  websec-check https://example.com --fail-below 80

  # Export SARIF for GitHub Code Scanning
  websec-check https://example.com --format sarif -o results.sarif

  # Generate Markdown summary for CI PR comment
  websec-check https://example.com --format markdown -o report.md`;

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
        const result = await scanWebsite(
            url,
            options.timeout,
            version,
            options.maxRedirects,
            { skipTls: options.skipTls }
        );

        let reportText = "";
        switch (options.format) {
            case "sarif":
                reportText = formatSarif(result, version);
                break;
            case "markdown":
                reportText = formatMarkdown(result, version);
                break;
            case "json":
                reportText = formatJson(result, version);
                break;
            case "terminal":
            default:
                reportText = formatTerminal(result, options.verbose, options.noColor);
                break;
        }

        // Save report to file if -o/--output is provided
        if (options.output) {
            try {
                writeFileSync(options.output, reportText, "utf8");
            } catch (writeErr) {
                formatError(`[ERROR] Failed to write report to file: ${writeErr.message}`, options.json);
                process.exit(1);
            }
        }

        // CI/CD Threshold Enforcement
        if (options.failBelow !== null && result.score < options.failBelow) {
            if (!options.json) {
                console.error(`\n[FAIL] Score (${result.score}) is below the required threshold of ${options.failBelow}.`);
            }
            process.exit(1);
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
        } else if (err.code === "EPROTO" || err.message?.includes("TLS") || err.message?.includes("ssl")) {
            errorMsg = `[ERROR] TLS connection failed.`;
        } else if (err.message) {
            errorMsg = `[ERROR] Connection failed: ${err.message}`;
        }

        formatError(errorMsg, options.json);
        process.exit(1); // runtime error
    }
}

run();
