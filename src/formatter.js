/**
 * Formatting and console logic separation.
 * Handles:
 *  1. Text output formatting (Pretty human-readable terminal charts)
 *  2. JSON formatting (Strict silent JSON logging)
 *  3. Verbose diagnostics reporting
 */

/**
 * Returns standard status symbol based on finding properties.
 * @param {string} status 
 * @returns {string}
 */
function getStatusSymbol(status) {
    switch (status) {
        case "PASS":
            return "✓";
        case "WEAK":
        case "INVALID":
            return "✗";
        case "MISSING":
            return "✗";
        case "REVIEW":
        case "INFO":
        default:
            return "!";
    }
}

/**
 * Formats findings for console logs.
 * @param {Object} scanResult 
 * @param {boolean} verbose 
 */
export function formatTerminal(scanResult, verbose = false) {
    const findings = [...scanResult.headersResult.findings, ...scanResult.cookiesResult.findings, ...scanResult.corsResult.findings];

    console.log("╔══════════════════════════════════════════════════╗");
    console.log("║                  WEBSEC CHECK                    ║");
    console.log("╚══════════════════════════════════════════════════╝");
    console.log("");
    console.log(`Target:       ${scanResult.url}`);
    console.log(`Final URL:    ${scanResult.finalUrl}`);
    console.log(`HTTP Status:  ${scanResult.status}`);

    if (verbose) {
        console.log(`Response Time: ${scanResult.responseTimeMs} ms`);
        if (scanResult.server) {
            console.log(`Server:       ${scanResult.server}`);
        }
        if (scanResult.redirectChain && scanResult.redirectChain.length > 0) {
            console.log("Redirects Traced:");
            for (const step of scanResult.redirectChain) {
                console.log(`  → ${step}`);
            }
        }
    }
    console.log("");

    console.log("Security Headers");
    console.log("────────────────────────────────────────────────────");
    for (const f of scanResult.headersResult.findings) {
        const symbol = getStatusSymbol(f.status);
        console.log(`${symbol} ${f.name}`);
    }
    console.log("");

    console.log("Cookies");
    console.log("────────────────────────────────────────────────────");
    if (scanResult.cookiesResult.cookiesChecked.length === 0) {
        console.log("No cookies set by target response.");
    } else {
        const cookieFindings = findings.filter(f => f.category === "Cookies");
        if (cookieFindings.length === 0) {
            console.log("✓ All cookies configured securely (Secure, HttpOnly, and SameSite set).");
        } else {
            console.log(`Checked ${scanResult.cookiesResult.cookiesChecked.length} cookie(s).`);
            for (const f of cookieFindings) {
                const symbol = getStatusSymbol(f.status);
                console.log(`${symbol} ${f.name} (${f.status}) - ${f.description}`);
            }
        }
    }
    console.log("");

    console.log("CORS");
    console.log("────────────────────────────────────────────────────");
    const corsFindings = findings.filter(f => f.category === "CORS");
    for (const f of corsFindings) {
        const symbol = getStatusSymbol(f.status);
        console.log(`${symbol} ${f.name || f.status} - ${f.description || f.issue}`);
    }
    console.log("");

    console.log(`Security Score: ${scanResult.score}/100`);
    console.log(`Risk Level:     ${scanResult.riskLevel}`);
    console.log("");

    const recommendations = findings.filter(f => f.status !== "PASS" && f.recommendation);
    if (recommendations.length > 0) {
        console.log("Recommendations");
        console.log("────────────────────────────────────────────────────");
        for (const f of recommendations) {
            console.log(`• Configure ${f.name}:`);
            console.log(`  Why:  ${f.description}`);
            console.log(`  Fix:  ${f.recommendation}`);
            if (verbose && f.evidence) {
                console.log(`  Evidence:\n${f.evidence.split("\n").map(l => "    " + l).join("\n")}`);
            }
            console.log("");
        }
    } else {
        console.log("Recommendations");
        console.log("────────────────────────────────────────────────────");
        console.log("✓ No remediation actions required.");
        console.log("");
    }
}

/**
 * Outputs valid JSON data only to stdout.
 * @param {Object} scanResult 
 * @param {string} version 
 */
export function formatJson(scanResult, version) {
    const allFindings = [
        ...scanResult.headersResult.findings,
        ...scanResult.cookiesResult.findings,
        ...scanResult.corsResult.findings
    ];

    const jsonReport = {
        tool: {
            name: "websec-check",
            version
        },
        target: {
            originalUrl: scanResult.url,
            finalUrl: scanResult.finalUrl
        },
        response: {
            status: scanResult.status,
            responseTimeMs: scanResult.responseTimeMs,
            server: scanResult.server || null
        },
        score: {
            value: scanResult.score,
            max: 100,
            risk: scanResult.riskLevel
        },
        findings: allFindings.map(f => ({
            id: f.id,
            category: f.category,
            name: f.name,
            status: f.status,
            severity: f.severity,
            points: f.points || 0,
            maxPoints: f.maxPoints || 0,
            description: f.description,
            recommendation: f.recommendation || null,
            evidence: f.evidence || null
        }))
    };

    console.log(JSON.stringify(jsonReport, null, 2));
}

/**
 * Report error either as plain text or structured JSON.
 * @param {string} message 
 * @param {boolean} jsonMode 
 */
export function formatError(message, jsonMode = false) {
    if (jsonMode) {
        console.log(JSON.stringify({ error: message }, null, 2));
    } else {
        console.error(message);
    }
}
