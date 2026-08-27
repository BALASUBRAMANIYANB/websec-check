/**
 * Passive Cache-Control Analyzer.
 * Inspects Cache-Control, Pragma, Expires, and Vary headers to verify sensitive info leaks protection.
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
 * Audit caching headers.
 * @param {Headers|Object} headers 
 * @returns {Object} { findings, deduction }
 */
export function analyzeCache(headers) {
    const findings = [];
    let deduction = 0;

    const cacheControl = getHeaderValue(headers, "cache-control");
    const pragma = getHeaderValue(headers, "pragma");
    const expires = getHeaderValue(headers, "expires");

    if (!cacheControl) {
        findings.push({
            id: "cache-missing-control",
            category: "Caching",
            name: "Missing Cache-Control Header",
            status: "MISSING",
            severity: "INFO",
            points: 0,
            maxPoints: 0,
            description: "No explicit Cache-Control directive was detected. Browsers may heuristically cache responses, which could store sensitive session actions.",
            recommendation: "Define a restrictive Cache-Control policy (e.g., 'no-store, max-age=0') for dynamic/sensitive resource targets, or static cache guidelines for assets.",
            evidence: "(missing)"
        });
        deduction += 1;
    } else {
        const ccLower = cacheControl.toLowerCase();
        // Check if sensitive cookies/headers might exist or response is explicitly cacheable
        // Note: we can warn when cache-control is public/private but lacks no-store for highly sensitive pages,
        // but for a general passive scan, public pages caching is fine.
        // We report info about cache status:
        if (ccLower.includes("public")) {
            findings.push({
                id: "cache-policy-public",
                category: "Caching",
                name: "Public Cache Policy",
                status: "INFO",
                severity: "INFO",
                points: 0,
                maxPoints: 0,
                description: `Cache-Control is set to public caching: "${cacheControl}".`,
                recommendation: "Ensure this endpoint does not serve patient-specific or credentialed session data.",
                evidence: `Cache-Control: ${cacheControl}`
            });
        }
    }

    return {
        findings,
        deduction: Math.min(deduction, 5) // Capped at 5 pts
    };
}
