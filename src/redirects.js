/**
 * Analyzes final redirection chains after scan operations.
 * Checks for upgrades, downgrades, origin crossings, and chain lengths.
 */

/**
 * Executes analysis on the tracked redirect chain data.
 * @param {Array<Object>} redirectChain - Hops metadata [{ url, status, headers }]
 * @param {string} originalUrl - initial requested target
 * @param {string} finalUrl - final target URL after redirects
 * @returns {Object} { findings, deduction }
 */
export function analyzeRedirects(redirectChain, originalUrl, finalUrl) {
    const findings = [];
    let deduction = 0;

    if (!redirectChain || redirectChain.length === 0) {
        // Simple case: no redirects followed
        try {
            const parsedOrig = new URL(originalUrl);
            const hostname = parsedOrig.hostname.toLowerCase();
            const isLocal =
                hostname === "localhost" ||
                hostname === "127.0.0.1" ||
                hostname === "0.0.0.0" ||
                hostname === "[::1]" ||
                /^127\./.test(hostname) ||
                /^10\./.test(hostname) ||
                /^192\.168\./.test(hostname) ||
                /^172\.(1[6-9]|2[0-9]|3[01])\./.test(hostname);

            if (parsedOrig.protocol === "http:" && !isLocal) {
                findings.push({
                    id: "redirect-missing-http-upgrade",
                    category: "Redirects",
                    name: "HTTP to HTTPS Upgrade",
                    status: "WARN",
                    severity: "LOW",
                    points: 0,
                    maxPoints: 0,
                    description: "Target URL specifies HTTP but did not attempt to redirect traffic to secure HTTPS.",
                    recommendation: "Configure a 301 redirection rule upgrading all cleartext HTTP traffic to HTTPS.",
                    evidence: `Protocol: HTTP`
                });
                deduction += 5;
            }
        } catch (e) {
            // Ignore malformed URL
        }

        return { findings, deduction };
    }

    const firstHop = redirectChain[0];
    const lastHop = redirectChain[redirectChain.length - 1];

    // Check 1: HTTP-to-HTTPS upgrade
    try {
        const parsedOrig = new URL(originalUrl);
        const parsedFinal = new URL(finalUrl);
        const hostname = parsedOrig.hostname.toLowerCase();
        const isLocal =
            hostname === "localhost" ||
            hostname === "127.0.0.1" ||
            hostname === "0.0.0.0" ||
            hostname === "[::1]" ||
            /^127\./.test(hostname) ||
            /^10\./.test(hostname) ||
            /^192\.168\./.test(hostname) ||
            /^172\.(1[6-9]|2[0-9]|3[01])\./.test(hostname);

        if (parsedOrig.protocol === "http:" && !isLocal) {
            if (parsedFinal.protocol === "https:") {
                findings.push({
                    id: "redirect-http-to-https",
                    category: "Redirects",
                    name: "HTTP to HTTPS Upgrade",
                    status: "PASS",
                    severity: "INFO",
                    points: 0,
                    maxPoints: 0,
                    description: "Target successfully upgrades initial HTTP request to HTTPS securely.",
                    recommendation: "Ensure HSTS policy is active to prevent cleartext requests entirely.",
                    evidence: `HTTP (${originalUrl}) -> HTTPS (${finalUrl})`
                });
            } else {
                findings.push({
                    id: "redirect-missing-http-upgrade",
                    category: "Redirects",
                    name: "HTTP to HTTPS Upgrade",
                    status: "WARN",
                    severity: "LOW",
                    points: 0,
                    maxPoints: 0,
                    description: "Target URL specifies HTTP and redirected requests but final URL is still cleartext HTTP.",
                    recommendation: "Configure redirection upgrading all cleartext traffic to HTTPS.",
                    evidence: `Final protocol: HTTP (${finalUrl})`
                });
                deduction += 5;
            }
        }
    } catch (e) { }

    // Check 2: HTTPS-to-HTTP downgrade
    let hasDowngrade = false;
    let downgradeHop = null;
    let currentProtocol = null;

    try {
        currentProtocol = new URL(originalUrl).protocol;
    } catch (e) { }

    for (const hop of redirectChain) {
        try {
            const nextProtocol = new URL(hop.url).protocol;
            if (currentProtocol === "https:" && nextProtocol === "http:") {
                hasDowngrade = true;
                downgradeHop = hop.url;
            }
            currentProtocol = nextProtocol;
        } catch (e) { }
    }

    if (hasDowngrade) {
        findings.push({
            id: "redirect-https-to-http",
            category: "Redirects",
            name: "HTTPS to HTTP Downgrade",
            status: "FAIL",
            severity: "HIGH",
            points: 0,
            maxPoints: 0,
            description: "Redirection chain contains a downgrade from HTTPS to cleartext HTTP, exposing transport security.",
            recommendation: "Ensure all resources in redirect sequences remain exclusively HTTPS.",
            evidence: `Downgraded target address: ${downgradeHop}`
        });
        deduction += 10;
    }

    // Check 3: Cross-origin redirect
    let hasCrosssite = false;
    let crossOriginTarget = null;
    try {
        const origOrigin = new URL(originalUrl).origin;
        for (const hop of redirectChain) {
            const hopOrigin = new URL(hop.url).origin;
            if (origOrigin !== hopOrigin) {
                hasCrosssite = true;
                crossOriginTarget = hop.url;
                break;
            }
        }
    } catch (e) { }

    if (hasCrosssite) {
        findings.push({
            id: "redirect-cross-origin",
            category: "Redirects",
            name: "Cross-Origin Redirect",
            status: "INFO",
            severity: "INFO",
            points: 0,
            maxPoints: 0,
            description: "Target redirected traffic to a different host origin.",
            recommendation: "Confirm external target destinations are trusted domains.",
            evidence: `Cross-origin target: ${crossOriginTarget}`
        });
    }

    // Check 4: Chain length
    if (redirectChain.length >= 5) {
        findings.push({
            id: "redirect-chain-long",
            category: "Redirects",
            name: "Chain Length Warning",
            status: "WARN",
            severity: "LOW",
            points: 0,
            maxPoints: 0,
            description: "Redirection sequence length contains multiple hops (5 or more). This degrades performance.",
            recommendation: "Reduce redirection sequences by pointing targets directly to the destination alias.",
            evidence: `Total redirection count: ${redirectChain.length}`
        });
        deduction += 2;
    }

    return {
        findings,
        deduction
    };
}
