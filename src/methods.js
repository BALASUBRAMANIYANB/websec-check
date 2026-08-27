/**
 * Passive HTTP Methods exposure analyzer.
 * Scans for 'Allow' headers in HTTP responses to verify allowed API endpoints.
 */

function getHeaderValue(headers, name) {
    if (headers && typeof headers.get === "function") {
        return headers.get(name);
    }
    if (headers && typeof headers === "object") {
        const lowerName = name.toLowerCase();
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === lowerName) {
                return headers[key];
            }
        }
    }
    return null;
}

/**
 * Checks for HTTP Method exposures passively.
 * @param {Headers|Object} headers 
 * @returns {Object} { findings, deduction }
 */
export function analyzeMethods(headers) {
    const findings = [];
    let deduction = 0;

    const allowHeader = getHeaderValue(headers, "allow");
    if (allowHeader) {
        const methods = allowHeader.split(",").map(m => m.trim().toUpperCase());
        const dangerous = methods.filter(m => ["TRACE", "CONNECT", "TRACK"].includes(m));

        if (dangerous.length > 0) {
            findings.push({
                id: "methods-exposed-dangerous",
                category: "Methods",
                name: "Sensitive HTTP Methods Enabled",
                status: "WARN",
                severity: "LOW",
                points: 0,
                maxPoints: 0,
                description: `Response indicates potentially sensitive HTTP methods are exposed: ${dangerous.join(", ")}.`,
                recommendation: "Disable unused and debugging-related HTTP methods (specifically TRACE) on the web server configuration.",
                evidence: `Allow: ${allowHeader}`
            });
            deduction += 2;
        } else {
            findings.push({
                id: "methods-exposed-passive",
                category: "Methods",
                name: "Exposed HTTP Methods",
                status: "INFO",
                severity: "INFO",
                points: 0,
                maxPoints: 0,
                description: `Allowed server methods identified passively: ${methods.join(", ")}.`,
                recommendation: "Ensure only the methods required for this resources stack (e.g. GET/HEAD/POST) are permitted.",
                evidence: `Allow: ${allowHeader}`
            });
        }
    }

    return {
        findings,
        deduction
    };
}
