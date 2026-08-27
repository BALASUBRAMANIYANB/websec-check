# WebSec Check

A lightweight command line interface (CLI) tool for performing passive HTTP/HTTPS security configuration checks on target websites. Written for Node.js 18+, it verifies the security properties of headers, cookie attributes, and CORS configurations.

## Overview

`websec-check` helps developers and security engineers audit their website headers and cookie settings against general industry guidelines.

## Features

- **Security Headers Auditing**: Validates STS/HSTS, CSP directives, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and Permissions-Policy.
- **Cookie Security Checks**: Examines `Set-Cookie` headers for `Secure`, `HttpOnly`, `SameSite`, and other relevant attributes.
- **CORS Configuration Scan**: Detects permissive policies (such as wildcard allow origin coupled with credential forwarding).
- **Redirection Chain Tracing**: Traces HTTP-to-HTTPS redirects and reports security status.
- **Custom Timeout Controls**: User-specified network connection timeouts.
- **Machine-Readable output**: Support for standard JSON outputs for integration into security pipelines.

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

- `--help`              Show usage and options
- `--version`           Show tool version
- `--json`              Output machine-readable JSON only
- `--verbose`           Include HTTP handshake, redirect chains, server headers, and evidence details
- `--timeout <seconds>` Set request connection timeout (defaults to 10 seconds)

### Examples

```bash
# Basic scan
websec-check https://example.com

# Verbose scan
websec-check https://example.com --verbose

# JSON export
websec-check https://example.com --json

# Override timeout to 15 seconds
websec-check https://example.com --timeout 15
```

## Example Output

### Human-Readable (Console)

```text
╔══════════════════════════════════════════════════╗
║                  WEBSEC CHECK                    ║
╚══════════════════════════════════════════════════╝

Target:       https://example.com
Final URL:    https://example.com/
HTTP Status:  200

Security Headers
────────────────────────────────────────────────────
✓ Strict-Transport-Security
✓ Content-Security-Policy
✗ X-Content-Type-Options
✓ X-Frame-Options
✓ Referrer-Policy
✗ Permissions-Policy

Cookies
────────────────────────────────────────────────────
No cookies set by target response.

CORS
────────────────────────────────────────────────────
✓ CORS: Not Enabled - No CORS headers are enabled.

Security Score: 70/100
Risk Level:     MEDIUM

Recommendations
────────────────────────────────────────────────────
• Configure X-Content-Type-Options:
  Why:  Allows MIME-sniffing, which can convert user uploads into executable assets (XSS).
  Fix:  Set: X-Content-Type-Options: nosniff

• Configure Permissions-Policy:
  Why:  No Permissions-Policy defined to restrict feature access (microphone, camera, geolocation, etc.).
  Fix:  Restrict features the application does not need using a hardware Permissions-Policy. Treat this as a hardening recommendation.
```

### JSON Output

```json
{
  "tool": {
    "name": "websec-check",
    "version": "1.0.0"
  },
  "target": {
    "originalUrl": "https://example.com",
    "finalUrl": "https://example.com/"
  },
  "response": {
    "status": 200,
    "responseTimeMs": 142,
    "server": "ECS (ewr/11A2)"
  },
  "score": {
    "value": 70,
    "max": 100,
    "risk": "MEDIUM"
  },
  "findings": [
     ...
  ]
}
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
│   ├── cookies.js           # Set-Cookie attribute scanner
│   ├── cors.js              # CORS headers analyzer
│   ├── formatter.js         # Output formatter (terminal/JSON/error)
│   ├── headers.js           # Security headers checker
│   ├── scanner.js           # Scanner orchestrator (timing & redirect tracer)
│   ├── scoring.js           # Score & Risk calculator
│   └── utils.js             # URL validator & options parser
```

## Development and Testing


Support native unit testing using the Node.js runner:

```bash
# Run tests
npm test

# Run syntax lint checks
npm run lint
```

## License

This project is licensed under the MIT License - see the `LICENSE` file for details.
