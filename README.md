# WebSec Check

A lightweight, zero-dependency command line interface (CLI) tool for performing passive HTTP/HTTPS security configuration checks on target websites. Written for Node.js 18+, it verifies the security properties of headers, cookie attributes, CORS configurations, redirects, caches, and HTTP methods.

## Overview

`websec-check` helps developers and security engineers audit their website configurations against general defensive industry guidelines. It strictly uses passive requests under standard HTTP protocols, ensuring no active exploitation or mutating sweeps are conducted.

## Features

- **Security Headers Auditing**: Validates HSTS/STS, CSP directives, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Cookie Security Checks**: Examines `Set-Cookie` headers for `Secure`, `HttpOnly`, `SameSite`, and other relevant attributes.
- **CORS Configuration Scan**: Detects permissive policies (such as wildcard allow origin coupled with credential forwarding).
- **Redirection Chain Tracing**: Traces redirect sequences, verifying HTTP-to-HTTPS upgrades, flagging HTTPS-to-HTTP downgrades, cross-origin changes, and excessive redirect hops.
- **Information Disclosure Audit**: Flags technology footprints and server stack versions (e.g. `Server`, `X-Powered-By`, `X-AspNet-Version`).
- **Cache Security Control**: Audits cache attributes preventing sensitive session memory leaks.
- **HTTP Methods Exposure Check**: Assesses allowed server methods passively to warn on debug features like `TRACE`.
- **Security Contact policy check**: Audits the presence of verification contacts under `.well-known/security.txt`.
- **Custom controls**: Handles connection timeouts, custom max redirects limits, and disabled color modes.

## Installation

Install globally:

```bash
npm install -g websec-check
```

Or run via `npx` directly without installation:

```bash
npx websec-check https://example.com
```

## Usage

```bash
websec-check <URL> [options]
```

### Options

- `--help`                 Show usage and options
- `--version`              Show tool version
- `--json`                 Output machine-readable JSON only
- `--verbose`              Include HTTP handshake, redirect chains, server headers, and evidence details
- `--timeout <seconds>`    Set request connection timeout (default: 10 seconds)
- `--no-color`             Disable colored terminal styling output
- `--max-redirects <num>`  Set maximum redirection hops limit (default: 5 hops)

### Examples

```bash
# Basic scan
websec-check https://example.com

# Verbose scan
websec-check https://example.com --verbose

# JSON export
websec-check https://example.com --json

# Disable colors and override timeout/redirect limits
websec-check https://example.com --no-color --timeout 15 --max-redirects 3
```

## Security Scoring

The audit calculates a configuration-hardening score from 0 to 100 based on standard weights:

| Check | Weight (Points) |
| --- | --- |
| Strict-Transport-Security | 20 |
| Content-Security-Policy | 25 |
| X-Content-Type-Options | 15 |
| X-Frame-Options | 15 |
| Referrer-Policy | 10 |
| Permissions-Policy | 15 |

### Deductions

The following negative points can be deducted from the base score (each capped to prevent excessive penalties):
- **Cookie settings**: up to -20 points
- **CORS policies**: up to -10 points
- **Redirect failures**: up to -15 points (e.g. unencrypted transmission, downgrades)
- **Information disclosure**: up to -10 points (e.g. tech versions exposure)
- **Cache-Control missing**: up to -5 points
- **HTTP method exposures**: up to -5 points (e.g. TRACE enabled)

*Note: security.txt absence does not affect coordinates score.*

### Risk Levels

- **LOW**: 80–100 points
- **MEDIUM**: 60–79 points
- **HIGH**: 0–59 points

*Note: The score is a configuration-hardening validator. It is not an absolute vulnerability score.*

## Responsible Use

> [!IMPORTANT]
> Users should only scan systems they own or are authorized to assess.

This tool is designed for educational, defensive, and authorized configuration assessment purposes only. It must only be used on:
- Websites you personally own or administer.
- Environments where you have obtained express written authorization.

Do not use this tool to perform mass passive scanning or target systems without consent.

## Limitations

WebSec Check is a lightweight passive HTTP security configuration assessment tool. Its score reflects the presence and quality of selected security controls and does not represent overall application security, vulnerability severity, or exploitability.

## Project Structure

```text
websec-check/
├── bin/
│   └── websec-check.js      # CLI Binary entry point
├── src/
│   ├── cache.js             # Caching headers auditor
│   ├── cookies.js           # Set-Cookie attribute scanner
│   ├── cors.js              # CORS headers analyzer
│   ├── disclosure.js        # Info leak & tech stack auditor
│   ├── formatter.js         # Output formatter (terminal/JSON/error)
│   ├── headers.js           # Security headers checker
│   ├── methods.js           # Safe HTTP methods check
│   ├── redirects.js         # Redirection sequence analyzer
│   ├── scanner.js           # Scanner orchestrator (timing & redirect tracer)
│   ├── scoring.js           # Score & Risk calculator
│   ├── securitytxt.js       # security.txt endpoint presence check
│   └── utils.js             # URL validator & options parser
```

## Development and Testing

Support native unit testing using the Node.js runner:

```bash
# Run tests
npm test

# Run syntax check
npm run lint
```

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
