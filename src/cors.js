/**
 * Scans response headers for CORS policies:
 * - Access-Control-Allow-Origin
 * - Access-Control-Allow-Credentials
 * 
 * Reports and scores findings according to the security context.
 */

/**
 * Normalizes headers format and retrieves value case-insensitively.
 * @param {Headers|Object} headers 
 * @param {string} name 
 * @returns {string|null}
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
 * Analyzes response CORS configuration.
 * @param {Headers|Object} headers 
 * @returns {Object} { findings, deduction }
 */
export function analyzeCors(headers) {
    const findings = [];
    let deduction = 0;

    const allowOrigin = getHeaderValue(headers, "access-control-allow-origin");
    const allowCredentials = getHeaderValue(headers, "access-control-allow-credentials");

    if (allowOrigin) {
        if (allowOrigin === "*") {
            if (allowCredentials && allowCredentials.toLowerCase() === "true") {
                findings.push({
                    id: "cors-wildcard-credentials",
                    category: "CORS",
                    name: "CORS: Wildcard with Credentials",
                    status: "INVALID",
                    severity: "MEDIUM",
                    points: 0,
                    maxPoints: 0,
                    description: "The wildcard Origin '*' combined with credentials 'true' is invalid according to standard CORS specifications and modern browsers will drop/block this connection.",
                    recommendation: "If credentials are required, configure an explicit, trusted allowed origin instead of '*'. Otherwise, disable Access-Control-Allow-Credentials.",
                    evidence: `Access-Control-Allow-Origin: *\nAccess-Control-Allow-Credentials: ${allowCredentials}`
                });
                deduction += 10;
            } else {
                findings.push({
                    id: "cors-wildcard",
                    category: "CORS",
                    name: "CORS: Wildcard Origin",
                    status: "INFO",
                    severity: "INFO",
                    points: 0,
                    maxPoints: 0,
                    description: "Access-Control-Allow-Origin is set to '*'. This allows any client domain to browse this resource.",
                    recommendation: "Ensure this endpoint is intended to be a public resource. For non-public endpoints, specify explicit trusted origins.",
                    evidence: "Access-Control-Allow-Origin: *"
                });
            }
        } else if (allowOrigin.toLowerCase() === "null") {
            findings.push({
                id: "cors-null-origin",
                category: "CORS",
                name: "CORS: Null Origin",
                status: "REVIEW",
                severity: "LOW",
                points: 0,
                maxPoints: 0,
                description: "Access-Control-Allow-Origin is set to 'null'. Since sandboxed documents and local files can send a null origin, this configuration should be checked.",
                recommendation: "Avoid using the 'null' origin value. Use specific trusted domains or design authorization-managed endpoints.",
                evidence: "Access-Control-Allow-Origin: null"
            });
            deduction += 5;
        } else {
            // Explicit origin configured
            findings.push({
                id: "cors-explicit-origin",
                category: "CORS",
                name: "CORS: Explicit Origin",
                status: "PASS",
                severity: "INFO",
                points: 0,
                maxPoints: 0,
                description: `Access-Control-Allow-Origin is configured for the explicit origin: ${allowOrigin}`,
                recommendation: `Confirm that ${allowOrigin} is a trusted origin.`,
                evidence: `Access-Control-Allow-Origin: ${allowOrigin}`
            });
        }
    } else {
        // Safe by default when CORS headers are NOT present.
        findings.push({
            id: "cors-not-enabled",
            category: "CORS",
            name: "CORS: Not Enabled",
            status: "PASS",
            severity: "INFO",
            points: 0,
            maxPoints: 0,
            description: "No CORS headers are enabled. The browser's Same-Origin Policy applies, which is secure by default.",
            recommendation: "No actions needed unless cross-domain requests are required by the application.",
            evidence: "Access-Control-Allow-Origin: (missing)"
        });
    }

    return {
        findings,
        deduction
    };
}
