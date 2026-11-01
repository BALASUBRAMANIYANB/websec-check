/**
 * Audits presence of security.txt contact file.
 * Avoids breaking connections or performing deep HTTP sweeps.
 */

/**
 * Checks security.txt presence.
 * @param {string} targetBaseUrl - base domain URL (e.g. https://example.com)
 * @param {number} timeoutSeconds - HTTP response timeout limit
 * @param {Function} [fetchFn] - Mockable fetch function (defaults to globalThis.fetch)
 * @returns {Promise<Object>} { findings, deduction }
 */
export async function analyzeSecurityTxt(targetBaseUrl, timeoutSeconds = 10, fetchFn = globalThis.fetch) {
    const findings = [];

    if (!targetBaseUrl) {
        return { findings, deduction: 0 };
    }

    // Resolve /.well-known/security.txt
    let verifyUrl;
    try {
        const parsed = new URL(targetBaseUrl);
        verifyUrl = `${parsed.protocol}//${parsed.host}/.well-known/security.txt`;
    } catch {
        return { findings, deduction: 0 };
    }

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutSeconds * 1000);

    try {
        const response = await fetchFn(verifyUrl, {
            method: "GET", // Use standard GET to verify readability
            signal: controller.signal,
            headers: {
                "User-Agent": "websec-check/1.2.0"
            }
        });

        clearTimeout(timer);

        if (response.ok) {
            findings.push({
                id: "securitytxt-ok",
                category: "Securitytxt",
                name: "Security.txt Presence",
                status: "PASS",
                severity: "INFO",
                points: 0,
                maxPoints: 0,
                description: "Security contact policy file successfully fetched at /.well-known/security.txt.",
                recommendation: "Maintain security.txt with active contact entries and GPG signatures.",
                evidence: `Status: ${response.status}\nURL: ${verifyUrl}`
            });
        } else {
            findings.push({
                id: "securitytxt-missing",
                category: "Securitytxt",
                name: "Security.txt Missing",
                status: "MISSING",
                severity: "INFO",
                points: 0,
                maxPoints: 0,
                description: "No security contact resource found under /.well-known/security.txt.",
                recommendation: "Publish a security.txt file describing authorization/vulnerability reporting channels.",
                evidence: `Status: ${response.status}\nURL: ${verifyUrl}`
            });
        }
    } catch (err) {
        clearTimeout(timer);
        findings.push({
            id: "securitytxt-missing",
            category: "Securitytxt",
            name: "Security.txt Missing",
            status: "MISSING",
            severity: "INFO",
            points: 0,
            maxPoints: 0,
            description: "No security contact resource could be retrieved under /.well-known/security.txt.",
            recommendation: "Publish a security.txt file describing authorization/vulnerability reporting channels.",
            evidence: `Error: ${err.message || err}\nURL: ${verifyUrl}`
        });
    }

    return {
        findings,
        deduction: 0 // security.txt does not affect score
    };
}
