/**
 * Formatting and console logic separation.
 * Handles colored terminal output, strict pure JSON, SARIF v2.1.0, and Markdown reports.
 */

// ANSI terminal escape helper functions
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
 * @param {boolean} [verbose=false] 
 * @param {boolean} [noColor=false] 
 * @returns {string}
 */
export function formatTerminal(scanResult, verbose = false, noColor = false) {
    const findings = scanResult.findings || [];
    const lines = [];

    lines.push(colors.cyan("╔══════════════════════════════════════════════════╗", noColor));
    lines.push(colors.cyan("║                  WEBSEC CHECK                    ║", noColor));
    lines.push(colors.cyan("╚══════════════════════════════════════════════════╝", noColor));
    lines.push("");
    lines.push(`${colors.bold("Target:", noColor)}       ${scanResult.url}`);
    lines.push(`${colors.bold("Final URL:", noColor)}    ${scanResult.finalUrl}`);
    lines.push(`${colors.bold("HTTP Status:", noColor)}  ${scanResult.status}`);

    if (verbose) {
        lines.push(`${colors.bold("Response Time:", noColor)} ${scanResult.responseTimeMs} ms`);
        if (scanResult.server) {
            lines.push(`${colors.bold("Server:", noColor)}       ${scanResult.server}`);
        }
        if (scanResult.redirectChain && scanResult.redirectChain.length > 0) {
            lines.push(colors.bold("Redirects Traced:", noColor));
            scanResult.redirectChain.forEach((step, idx) => {
                lines.push(`  ${idx + 1}. → ${step.url} (${step.status})`);
            });
        }
    }
    lines.push("");

    const printSection = (title, categoryName) => {
        lines.push(colors.bold(title, noColor));
        lines.push(colors.dim("────────────────────────────────────────────────────", noColor));
        const sectionFindings = findings.filter(f => f.category.toLowerCase() === categoryName.toLowerCase());
        if (sectionFindings.length === 0) {
            lines.push(`  ${colors.green("✓", noColor)} No issues detected.`);
        } else {
            sectionFindings.forEach(f => {
                const symbol = getStatusSymbol(f.status, noColor);
                lines.push(`  ${symbol} ${f.name} (${f.status}) - ${f.description}`);
            });
        }
        lines.push("");
    };

    // Print core sections
    printSection("Security Headers", "Headers");
    printSection("TLS & SSL Certificate", "TLS");
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

    lines.push(`${colors.bold("Security Score:", noColor)} ${scoreColor(scanResult.score + "/100", noColor)}`);
    lines.push(`${colors.bold("Risk Level:", noColor)}     ${scoreColor(scanResult.riskLevel, noColor)}`);
    lines.push("");

    const recommendations = findings.filter(f => f.status !== "PASS" && f.recommendation);
    if (recommendations.length > 0) {
        lines.push(colors.bold("Recommendations", noColor));
        lines.push(colors.dim("────────────────────────────────────────────────────", noColor));
        recommendations.forEach(f => {
            lines.push(`• Configure ${colors.bold(f.name, noColor)}:`);
            lines.push(`  Why:  ${f.description}`);
            lines.push(`  Fix:  ${f.recommendation}`);
            if (verbose && f.evidence) {
                lines.push(`  Evidence:\n${f.evidence.split("\n").map(l => "    " + l).join("\n")}`);
            }
            lines.push("");
        });
    } else {
        lines.push(colors.bold("Recommendations", noColor));
        lines.push(colors.dim("────────────────────────────────────────────────────", noColor));
        lines.push(`  ${colors.green("✓", noColor)} No remediation actions required.`);
        lines.push("");
    }

    const output = lines.join("\n");
    console.log(output);
    return output;
}

/**
 * Generates structured JSON report.
 * @param {Object} scanResult 
 * @param {string} version 
 * @returns {string}
 */
export function formatJson(scanResult, version = "1.2.0") {
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
        tls: scanResult.tlsResult?.certificate || null,
        score: {
            value: scanResult.score,
            max: 100,
            risk: scanResult.riskLevel
        },
        findings: (scanResult.findings || []).map(f => ({
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

    const output = JSON.stringify(jsonReport, null, 2);
    console.log(output);
    return output;
}

/**
 * Generates OASIS SARIF v2.1.0 output for GitHub Advanced Security & Code Scanning.
 * @param {Object} scanResult 
 * @param {string} version 
 * @returns {string}
 */
export function formatSarif(scanResult, version = "1.2.0") {
    const findings = scanResult.findings || [];
    const issueFindings = findings.filter(f => f.status !== "PASS");

    // Map severity to SARIF level
    const mapSarifLevel = (severity, status) => {
        if (status === "FAIL") return "error";
        if (severity === "HIGH") return "error";
        if (severity === "MEDIUM" || status === "WARN") return "warning";
        return "note";
    };

    // Deduplicate rules
    const rulesMap = new Map();
    issueFindings.forEach(f => {
        if (!rulesMap.has(f.id)) {
            rulesMap.set(f.id, {
                id: f.id,
                name: f.name.replace(/[^a-zA-Z0-9]/g, ""),
                shortDescription: {
                    text: f.name
                },
                fullDescription: {
                    text: f.description
                },
                defaultConfiguration: {
                    level: mapSarifLevel(f.severity, f.status)
                },
                help: {
                    text: f.recommendation || f.description
                },
                properties: {
                    category: f.category,
                    precision: "high",
                    tags: ["security", "web-security", f.category.toLowerCase()]
                }
            });
        }
    });

    const sarifReport = {
        $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        version: "2.1.0",
        runs: [
            {
                tool: {
                    driver: {
                        name: "websec-check",
                        version,
                        informationUri: "https://github.com/balasubramaniyan/websec-check",
                        rules: Array.from(rulesMap.values())
                    }
                },
                results: issueFindings.map(f => ({
                    ruleId: f.id,
                    level: mapSarifLevel(f.severity, f.status),
                    message: {
                        text: `${f.description}${f.recommendation ? ` Remediation: ${f.recommendation}` : ""}`
                    },
                    locations: [
                        {
                            physicalLocation: {
                                artifactLocation: {
                                    uri: scanResult.finalUrl || scanResult.url
                                }
                            }
                        }
                    ],
                    properties: {
                        category: f.category,
                        severity: f.severity,
                        status: f.status
                    }
                }))
            }
        ]
    };

    const output = JSON.stringify(sarifReport, null, 2);
    console.log(output);
    return output;
}

/**
 * Generates GitHub Flavored Markdown summary report for PRs & CI step summaries.
 * @param {Object} scanResult 
 * @param {string} version 
 * @returns {string}
 */
export function formatMarkdown(scanResult, version = "1.2.0") {
    const findings = scanResult.findings || [];
    const lines = [];

    const badgeIcon = scanResult.score >= 80 ? "🟢" : (scanResult.score >= 60 ? "🟡" : "🔴");

    lines.push("# 🛡️ WebSec Check Security Audit Report");
    lines.push("");
    lines.push(`**Target:** \`${scanResult.url}\` | **Final URL:** \`${scanResult.finalUrl}\``);
    lines.push(`**Score:** ${badgeIcon} **${scanResult.score}/100** (Risk Level: **${scanResult.riskLevel}**)`);
    lines.push(`**Audit Time:** ${new Date().toISOString()} | **Duration:** ${scanResult.responseTimeMs} ms | **Version:** \`v${version}\``);
    lines.push("");

    if (scanResult.tlsResult?.certificate) {
        const cert = scanResult.tlsResult.certificate;
        lines.push("### 🔒 TLS / SSL Certificate");
        lines.push(`- **Subject:** \`${cert.subject}\``);
        lines.push(`- **Issuer:** \`${cert.issuer}\``);
        lines.push(`- **Protocol:** \`${cert.protocol}\` (${cert.cipher})`);
        lines.push(`- **Valid Until:** \`${cert.validTo}\``);
        lines.push("");
    }

    lines.push("### 📋 Audit Summary");
    lines.push("");
    lines.push("| Status | Category | Check | Severity | Details |");
    lines.push("| :---: | :--- | :--- | :---: | :--- |");

    findings.forEach(f => {
        let statusIcon = "ℹ️";
        if (f.status === "PASS") statusIcon = "✅";
        else if (f.status === "WARN") statusIcon = "⚠️";
        else if (f.status === "FAIL" || f.status === "MISSING") statusIcon = "❌";

        lines.push(`| ${statusIcon} | **${f.category}** | ${f.name} | \`${f.severity}\` | ${f.description} |`);
    });
    lines.push("");

    const actionItems = findings.filter(f => f.status !== "PASS" && f.recommendation);
    if (actionItems.length > 0) {
        lines.push("### 🛠️ Remediation Steps");
        lines.push("");
        actionItems.forEach(f => {
            lines.push(`- **${f.name}** (\`${f.category}\`):`);
            lines.push(`  - *Issue:* ${f.description}`);
            lines.push(`  - *Remediation:* ${f.recommendation}`);
        });
        lines.push("");
    } else {
        lines.push("### 🛠️ Remediation Steps");
        lines.push("");
        lines.push("✅ No remediation required. All evaluated controls satisfy defensive baselines.");
        lines.push("");
    }

    lines.push("---");
    lines.push("*Generated by [websec-check](https://github.com/balasubramaniyan/websec-check)*");

    const output = lines.join("\n");
    console.log(output);
    return output;
}

/**
 * Report error either as plain text or structured JSON.
 * @param {string} message 
 * @param {boolean} [jsonMode=false] 
 */
export function formatError(message, jsonMode = false) {
    if (jsonMode) {
        console.log(JSON.stringify({ error: message }, null, 2));
    } else {
        console.error(message);
    }
}
