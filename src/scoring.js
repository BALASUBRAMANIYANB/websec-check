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
 * Supports negative deductions from cookies (max -20) and CORS (max -10).
 * Final score is range-bound in [0, 100].
 */

/**
 * Computes the final security score and maps it category-wise.
 * @param {Object} scoresObj 
 * @param {number} scoresObj.headersScore 
 * @param {number} scoresObj.cookieDeduction 
 * @param {number} scoresObj.corsDeduction 
 * @returns {Object} { score, riskLevel }
 */
export function calculateScore({ headersScore, cookieDeduction = 0, corsDeduction = 0 }) {
    const calculated = headersScore - cookieDeduction - corsDeduction;
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
