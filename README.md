# 🛡️ WebSec Check

[![Node.js Version](https://img.shields.io/badge/node-%3E%3D18.0.0-brightgreen.svg)](https://nodejs.org/)
[![Dependencies](https://img.shields.io/badge/dependencies-0%20(zero)-blue.svg)](package.json)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Output Formats](https://img.shields.io/badge/formats-Terminal%20%7C%20JSON%20%7C%20SARIF%20%7C%20Markdown-informational.svg)](#output-formats)
[![CI](https://github.com/balasubramaniyan/websec-check/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)

A zero-dependency CLI tool and GitHub Action for passive web security, TLS certificate, and HTTP configuration audits. Designed for developers, AppSec, and DevSecOps pipelines to verify defensive configurations against OWASP guidelines.

---

## Highlights

- **⚡ Zero External Dependencies**: Powered entirely by native Node.js 18+ APIs (`node:tls`, `fetch`, `node:test`). Lightweight, secure, and fast.
- **🔒 TLS & SSL Certificate Auditing**: Inspects certificate trust chains, expiration dates, remaining validity, and flags deprecated protocols (TLS 1.0/1.1).
- **📋 OWASP Security Headers**: Evaluates HSTS, CSP (with `frame-ancestors` mitigation awareness), X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **🍪 Cookie & CORS Hardening**: Scans for `Secure`, `HttpOnly`, `SameSite`, and cookie prefixes (`__Host-`, `__Secure-`), and detects permissive CORS misconfigurations.
- **🛡️ SSRF Guardrails**: Built-in validation prevents private, loopback, and local IP scanning (`127.0.0.1`, RFC 1918 ranges).
- **📊 Multi-Format Reporting**: Outputs colored terminal views, machine-readable JSON, GitHub Flavored Markdown, and **OASIS SARIF v2.1.0** for GitHub Code Scanning.
- **🚦 CI/CD Quality Gate**: Enforces minimum score thresholds (`--fail-below <score>`) to block insecure builds before deployment.

---

## Quick Start

Run instantly without installation using `npx`:

```bash
npx websec-check https://example.com
```

Or install globally:

```bash
npm install -g websec-check
```

---

## Usage

```bash
websec-check <URL> [options]
```

### CLI Options

| Option | Shorthand | Default | Description |
| :--- | :---: | :---: | :--- |
| `--help` | `-h` | - | Display help menu and usage examples |
| `--version` | `-v` | - | Display installed version |
| `--format <type>` | - | `terminal` | Report output format: `terminal`, `json`, `sarif`, `markdown` |
| `--json` | - | - | Alias for `--format json` |
| `--output <path>` | `-o` | - | Write output to specified file path (e.g. `report.sarif`, `summary.md`) |
| `--fail-below <score>` | - | - | Exit with code `1` if the calculated score is below threshold (`0`–`100`) |
| `--skip-tls` | - | `false` | Bypass TLS/SSL certificate handshake verification |
| `--verbose` | - | `false` | Display HTTP handshake details, redirect chains, server headers, and evidence |
| `--timeout <seconds>` | - | `10` | Request timeout limit in seconds |
| `--no-color` | - | `false` | Disable ANSI terminal color codes |
| `--max-redirects <num>` | - | `5` | Maximum number of redirect hops to trace |

### Examples

```bash
# Basic terminal scan
websec-check https://example.com

# Verbose scan with handshake and evidence details
websec-check https://example.com --verbose

# CI/CD Quality Gate: fail the pipeline if score is below 80
websec-check https://example.com --fail-below 80

# Export SARIF for GitHub Code Scanning
websec-check https://example.com --format sarif -o results.sarif

# Export Markdown summary for PR comment or CI step summary
websec-check https://example.com --format markdown -o report.md
```

---

## CI/CD & GitHub Actions Integration

### 1. Direct Step in GitHub Actions
Add `websec-check` directly to your CI/CD deployment workflow:

```yaml
name: Security Audit

on:
  deployment_status:
  push:
    branches: [ main ]

jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Repository
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: 20

      - name: Audit Staging Environment
        run: |
          npx websec-check https://staging.example.com \
            --format markdown \
            -o report.md \
            --fail-below 80

      - name: Publish Summary to Job
        if: always()
        run: cat report.md >> $GITHUB_STEP_SUMMARY
```

### 2. GitHub Code Scanning (SARIF Integration)
Ingest results directly into GitHub's **Security > Code scanning alerts** tab:

```yaml
      - name: Run WebSec Check SARIF Export
        run: |
          npx websec-check https://staging.example.com --format sarif -o results.sarif

      - name: Upload SARIF to GitHub Security
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

---

## Security Scoring Methodology

The audit calculates a baseline hardening score from **0 to 100** based on standard weights:

| Category | Security Control | Base Points |
| :--- | :--- | :---: |
| **Headers** | Content-Security-Policy (CSP) | 25 |
| **Headers** | Strict-Transport-Security (HSTS) | 20 |
| **Headers** | X-Frame-Options (or CSP `frame-ancestors`) | 15 |
| **Headers** | X-Content-Type-Options | 15 |
| **Headers** | Permissions-Policy | 15 |
| **Headers** | Referrer-Policy | 10 |

### Negative Deductions (Capped)

Defensive misconfigurations deduct from the base score:

| Category | Defect | Max Deduction |
| :--- | :--- | :---: |
| **TLS / SSL** | Expired certificate, untrusted CA, or deprecated protocol (TLS 1.0/1.1) | -15 |
| **Cookies** | Missing `Secure`, `HttpOnly`, or `SameSite` on sensitive cookies | -20 |
| **Redirects** | HTTPS-to-HTTP downgrade or excessive redirection hops | -15 |
| **CORS** | Permissive wildcard origin paired with credential forwarding | -10 |
| **Disclosure** | Explicit server version leakage (`Server`, `X-Powered-By`) | -10 |
| **Cache** | Insecure caching policy on potentially sensitive responses | -5 |
| **Methods** | Dangerous debugging methods exposed (`TRACE`) | -5 |

### Risk Classification

- 🟢 **LOW RISK**: 80–100 points (Strong defensive hardening)
- 🟡 **MEDIUM RISK**: 60–79 points (Acceptable baseline, remediations recommended)
- 🔴 **HIGH RISK**: 0–59 points (Critical security headers or TLS issues detected)

---

## Project Structure

```text
websec-check/
├── .github/
│   └── workflows/
│       └── ci.yml             # Automated multi-OS Node.js matrix test workflow
├── action.yml                 # Composite GitHub Action manifest
├── bin/
│   └── websec-check.js        # Executable CLI entrypoint
├── src/
│   ├── cache.js               # Cache-Control sensitive data leakage checks
│   ├── cookies.js             # Cookie attribute & prefix audits
│   ├── cors.js                # CORS policy analyzer
│   ├── disclosure.js          # Technology stack footprint checks
│   ├── formatter.js           # Multi-format report engine (Terminal, JSON, SARIF, MD)
│   ├── headers.js             # OWASP security headers auditor
│   ├── methods.js             # HTTP methods analyzer
│   ├── redirects.js           # Redirection sequence & downgrade tracer
│   ├── scanner.js             # Orchestrator & async scanner pipeline
│   ├── scoring.js             # Hardening scoring & deduction calculator
│   ├── securitytxt.js         # RFC 9116 security.txt verification
│   ├── tls.js                 # Zero-dependency TLS certificate & cipher auditor
│   └── utils.js               # URL validator, SSRF protection, option parser
└── tests/                     # Comprehensive native unit test suite (28 passing tests)
```

---

## Development & Testing

Run unit tests natively with Node's built-in test runner:

```bash
# Run unit test suite
npm test

# Run syntax and lint check
npm run lint
```

---

## Responsible Use

> [!IMPORTANT]
> **Defensive and Authorized Testing Only**  
> `websec-check` performs purely passive HTTP/HTTPS requests. Never use this tool to scan targets without proper authorization or to conduct unauthorized reconnaissance.

---

## License

This project is open-source under the [MIT License](LICENSE).
