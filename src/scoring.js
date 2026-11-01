/**
 * Calculates security score and maps to risk levels.
 * Weights:
 *  - HSTS: 20
 *  - CSP: 25
 *  - XCTO (X-Content-Type-Options): 15
 *  - XFO (X-Frame-Options): 15
 *  - Referrer-Policy: 10
 *  - Permissions-Policy: 15
 * Total points: 100.
 * 
 * Supports negative deductions from cookies (max -20), CORS (max -10), redirects (max -15),
 * information disclosure (max -10), caching (max -5), methods (max -5), and TLS/SSL (max -15).
 * Final score is range-bound in [0, 100].
 */

/**
 * Computes the final security score and maps it category-wise.
 * @param {Object} scoresObj 
 * @param {number} scoresObj.headersScore 
 * @param {number} [scoresObj.cookieDeduction] 
 * @param {number} [scoresObj.corsDeduction] 
 * @param {number} [scoresObj.redirectDeduction]
 * @param {number} [scoresObj.disclosureDeduction]
 * @param {number} [scoresObj.cacheDeduction]
 * @param {number} [scoresObj.methodsDeduction]
 * @param {number} [scoresObj.tlsDeduction]
 * @returns {Object} { score, riskLevel }
 */
export function calculateScore({
    headersScore,
    cookieDeduction = 0,
    corsDeduction = 0,
    redirectDeduction = 0,
    disclosureDeduction = 0,
    cacheDeduction = 0,
    methodsDeduction = 0,
    tlsDeduction = 0
}) {
    const totalDeductions =
        Math.min(cookieDeduction, 20) +
        Math.min(corsDeduction, 10) +
        Math.min(redirectDeduction, 15) +
        Math.min(disclosureDeduction, 10) +
        Math.min(cacheDeduction, 5) +
        Math.min(methodsDeduction, 5) +
        Math.min(tlsDeduction, 15);

    const calculated = headersScore - totalDeductions;
    const score = Math.max(0, Math.min(100, calculated));

    let riskLevel = "HIGH";
    if (score >= 80) {
        riskLevel = "LOW";
    } else if (score >= 60) {
        riskLevel = "MEDIUM";
    }

    return {
        score,
        riskLevel
    };
}
