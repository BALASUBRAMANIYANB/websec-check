/**
 * Formatting and console logic separation.
 * Handles colored terminal output, strict pure JSON, and verbose logs.
 */

// ANSII terminal escape helper functions
const colors = {
    green: (str, noColor) => noColor ? str : `\x1b[32m${str}\x1b[0m`,
    red: (str, noColor) => noColor ? str : `\x1b[31m${str}\x1b[0m`,
    yellow: (str, noColor) => noColor ? str : `\x1b[33m${str}\x1b[0m`,
    cyan: (str, noColor) => noColor ? str : `\x1b[36m${str}\x1b[0m`,
    bold: (str, noColor) => noColor ? str : `\x1b[1m${str}\x1b[0m`,
    dim: (str, noColor) => noColor ? str : `\x1b[2m${str}\x1b[0m`
};

/**
 * Returns formatted status symbol with colors options.
 * @param {string} status 
 * @param {boolean} noColor 
 * @returns {string}
 */
function getStatusSymbol(status, noColor) {
    switch (status) {
        case "PASS":
            return colors.green("✓", noColor);
        case "WARN":
            return colors.yellow("⚠", noColor);
        case "FAIL":
            return colors.red("✗", noColor);
        case "MISSING":
            return colors.red("✗", noColor);
        case "INFO":
        default:
            return colors.cyan("ℹ", noColor);
    }
}

/**
 * Formats findings for console logs.
 * @param {Object} scanResult 
 * @param {boolean} verbose 
 * @param {boolean} noColor 
 */
export function formatTerminal(scanResult, verbose = false, noColor = false) {
    const findings = scanResult.findings || [];

    console.log(colors.cyan("╔══════════════════════════════════════════════════╗", noColor));
    console.log(colors.cyan("║                  WEBSEC CHECK                    ║", noColor));
    console.log(colors.cyan("╚══════════════════════════════════════════════════╝", noColor));
    console.log("");
    console.log(`${colors.bold("Target:", noColor)}       ${scanResult.url}`);
    console.log(`${colors.bold("Final URL:", noColor)}    ${scanResult.finalUrl}`);
    console.log(`${colors.bold("HTTP Status:", noColor)}  ${scanResult.status}`);

    if (verbose) {
        console.log(`${colors.bold("Response Time:", noColor)} ${scanResult.responseTimeMs} ms`);
        if (scanResult.server) {
            console.log(`${colors.bold("Server:", noColor)}       ${scanResult.server}`);
        }
        if (scanResult.redirectChain && scanResult.redirectChain.length > 0) {
            console.log(colors.bold("Redirects Traced:", noColor));
            scanResult.redirectChain.forEach((step, idx) => {
                console.log(`  ${idx + 1}. → ${step.url} (${step.status})`);
            });
        }
    }
    console.log("");

    const printSection = (title, categoryName) => {
        console.log(colors.bold(title, noColor));
        console.log(colors.dim("────────────────────────────────────────────────────", noColor));
        const sectionFindings = findings.filter(f => f.category.toLowerCase() === categoryName.toLowerCase());
        if (sectionFindings.length === 0) {
            console.log(`  ${colors.green("✓", noColor)} No issues detected.`);
        } else {
            sectionFindings.forEach(f => {
                const symbol = getStatusSymbol(f.status, noColor);
                console.log(`  ${symbol} ${f.name} (${f.status}) - ${f.description}`);
            });
        }
        console.log("");
    };

    // Print core sections
    printSection("Security Headers", "Headers");
    printSection("Cookies", "Cookies");
    printSection("CORS", "CORS");
    printSection("Redirects", "Redirects");
    printSection("Information Disclosure", "Disclosure");
    printSection("Cache Security", "Caching");
    printSection("HTTP Methods", "Methods");
    printSection("Security.txt Details", "Securitytxt");

    // Print final score panel
    let scoreColor = colors.red;
    if (scanResult.score >= 80) {
        scoreColor = colors.green;
    } else if (scanResult.score >= 60) {
        scoreColor = colors.yellow;
    }

    console.log(`${colors.bold("Security Score:", noColor)} ${scoreColor(scanResult.score + "/100", noColor)}`);
    console.log(`${colors.bold("Risk Level:", noColor)}     ${scoreColor(scanResult.riskLevel, noColor)}`);
    console.log("");

    const recommendations = findings.filter(f => f.status !== "PASS" && f.recommendation);
    if (recommendations.length > 0) {
        console.log(colors.bold("Recommendations", noColor));
        console.log(colors.dim("────────────────────────────────────────────────────", noColor));
        recommendations.forEach(f => {
            console.log(`• Configure ${colors.bold(f.name, noColor)}:`);
            console.log(`  Why:  ${f.description}`);
            console.log(`  Fix:  ${f.recommendation}`);
            if (verbose && f.evidence) {
                console.log(`  Evidence:\n${f.evidence.split("\n").map(l => "    " + l).join("\n")}`);
            }
            console.log("");
        });
    } else {
        console.log(colors.bold("Recommendations", noColor));
        console.log(colors.dim("────────────────────────────────────────────────────", noColor));
        console.log(`  ${colors.green("✓", noColor)} No remediation actions required.`);
        console.log("");
    }
}

/**
 * Outputs valid JSON data only to stdout.
 * @param {Object} scanResult 
 * @param {string} version 
 */
export function formatJson(scanResult, version) {
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
        findings: scanResult.findings.map(f => ({
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
