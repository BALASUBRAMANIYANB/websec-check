/**
 * Scans HTTP security headers.
 * Supported headers:
 *  1. Strict-Transport-Security (20 pts)
 *  2. Content-Security-Policy (25 pts)
 *  3. X-Content-Type-Options (15 pts)
 *  4. X-Frame-Options (15 pts)
 *  5. Referrer-Policy (10 pts)
 *  6. Permissions-Policy (15 pts)
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
 * Parses HSTS header value.
 * @param {string} value 
 * @returns {Object} { maxAge, includeSubDomains, preload, valid }
 */
function parseHsts(value) {
    const parts = value.split(";").map(p => p.trim());
    let maxAge = null;
    let includeSubDomains = false;
    let preload = false;
    let valid = false;

    for (const part of parts) {
        if (part.toLowerCase().startsWith("max-age=")) {
            const numPart = part.substring(8);
            if (/^\d+$/.test(numPart)) {
                maxAge = parseInt(numPart, 10);
                valid = true;
            }
        } else if (part.toLowerCase() === "includesubdomains") {
            includeSubDomains = true;
        } else if (part.toLowerCase() === "preload") {
            preload = true;
        }
    }

    return { maxAge, includeSubDomains, preload, valid };
}

/**
 * Parses CSP value and looks for directive details.
 * @param {string} value 
 * @returns {Object} { hasDefaultSrc, hasScriptSrc, hasFrameAncestors, hasUnsafeInline, hasUnsafeEval, hasWildcard }
 */
function parseCsp(value) {
    const directives = value.split(";").map(d => d.trim());
    let hasDefaultSrc = false;
    let hasScriptSrc = false;
    let hasFrameAncestors = false;
    let hasUnsafeInline = false;
    let hasUnsafeEval = false;
    let hasWildcard = false;

    for (const directive of directives) {
        const lowerDirective = directive.toLowerCase();
        if (lowerDirective.startsWith("default-src")) {
            hasDefaultSrc = true;
            if (directive.includes("*")) hasWildcard = true;
            if (directive.includes("'unsafe-inline'")) hasUnsafeInline = true;
            if (directive.includes("'unsafe-eval'")) hasUnsafeEval = true;
        } else if (lowerDirective.startsWith("script-src")) {
            hasScriptSrc = true;
            if (directive.includes("*")) hasWildcard = true;
            if (directive.includes("'unsafe-inline'")) hasUnsafeInline = true;
            if (directive.includes("'unsafe-eval'")) hasUnsafeEval = true;
        } else if (lowerDirective.startsWith("frame-ancestors")) {
            hasFrameAncestors = true;
        }
    }

    return {
        hasDefaultSrc,
        hasScriptSrc,
        hasFrameAncestors,
        hasUnsafeInline,
        hasUnsafeEval,
        hasWildcard
    };
}

const REFERRER_POLICIES = [
    "no-referrer",
    "no-referrer-when-downgrade",
    "origin",
    "origin-when-cross-origin",
    "same-origin",
    "strict-origin",
    "strict-origin-when-cross-origin",
    "unsafe-url"
];

/**
 * Analyzes response headers.
 * @param {Headers|Object} headers 
 * @returns {Object} { score, maxScore, findings }
 */
export function analyzeHeaders(headers) {
    const findings = [];
    let score = 0;

    // 1. Strict-Transport-Security (20 pts)
    const hstsValue = getHeaderValue(headers, "strict-transport-security");
    if (!hstsValue) {
        findings.push({
            id: "missing-hsts",
            category: "Headers",
            name: "Strict-Transport-Security",
            status: "MISSING",
            severity: "MEDIUM",
            points: 0,
            maxPoints: 20,
            description: "Allows connection fallback to cleartext HTTP, which increases exposure to transit interception or man-in-the-middle redirects.",
            recommendation: "Set: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        });
    } else {
        const parsed = parseHsts(hstsValue);
        if (!parsed.valid) {
            findings.push({
                id: "invalid-hsts",
                category: "Headers",
                name: "Strict-Transport-Security",
                status: "INVALID",
                severity: "HIGH",
                points: 0,
                maxPoints: 20,
                description: "HSTS header is malformed and could not be interpreted by browsers.",
                recommendation: "Ensure Strict-Transport-Security specifies max-age as an integer of seconds.",
                evidence: hstsValue
            });
        } else if (parsed.maxAge < 15768000) { // < 6 months
            findings.push({
                id: "weak-hsts-short-duration",
                category: "Headers",
                name: "Strict-Transport-Security",
                status: "WEAK",
                severity: "MEDIUM",
                points: 10,
                maxPoints: 20,
                description: "HSTS header max-age is set to a short duration, limiting its protective period.",
                recommendation: "Set HSTS max-age to 31536000 (1 year) or greater.",
                evidence: hstsValue
            });
            score += 10;
        } else {
            findings.push({
                id: "hsts-ok",
                category: "Headers",
                name: "Strict-Transport-Security",
                status: "PASS",
                severity: "INFO",
                points: 20,
                maxPoints: 20,
                description: "HSTS correctly configured to enforce secure browser connections.",
                evidence: hstsValue
            });
            score += 20;
        }
    }

    // Capture CSP values since CSP check acts as a prerequisite for downstream checks
    const cspValue = getHeaderValue(headers, "content-security-policy");
    const parsedCsp = cspValue ? parseCsp(cspValue) : null;

    // 2. Content-Security-Policy (25 pts)
    if (!cspValue) {
        findings.push({
            id: "missing-csp",
            category: "Headers",
            name: "Content-Security-Policy",
            status: "MISSING",
            severity: "MEDIUM",
            points: 0,
            maxPoints: 25,
            description: "Lacks a Content Security Policy to restrict resource loading, reducing defense-in-depth against data injection or cross-site scripting (XSS) execution if an input sanitization bypass occurs.",
            recommendation: "Define a secure Content-Security-Policy appropriate for the application."
        });
    } else {
        if (!parsedCsp.hasDefaultSrc && !parsedCsp.hasScriptSrc) {
            findings.push({
                id: "weak-csp-missing-src-directives",
                category: "Headers",
                name: "Content-Security-Policy",
                status: "WEAK",
                severity: "MEDIUM",
                points: 10,
                maxPoints: 25,
                description: "CSP header lacks fundamental 'default-src' or 'script-src' control directives.",
                recommendation: "Incorporate 'default-src' or 'script-src' into your CSP policy to restrict script loads.",
                evidence: cspValue
            });
            score += 10;
        } else if (parsedCsp.hasUnsafeInline || parsedCsp.hasUnsafeEval || parsedCsp.hasWildcard) {
            findings.push({
                id: "review-csp-permissive-policy",
                category: "Headers",
                name: "Content-Security-Policy",
                status: "REVIEW",
                severity: "LOW",
                points: 15,
                maxPoints: 25,
                description: "CSP includes permissive options (like 'unsafe-inline', 'unsafe-eval', or wildcard '*'). CSP effectiveness depends heavily on application details.",
                recommendation: "Audit CSP directives to replace inline/eval exclusions with secure hashes or nonces, and tighten host origins.",
                evidence: cspValue
            });
            score += 15;
        } else {
            findings.push({
                id: "csp-ok",
                category: "Headers",
                name: "Content-Security-Policy",
                status: "PASS",
                severity: "INFO",
                points: 25,
                maxPoints: 25,
                description: "CSP present and defines active base source constraints.",
                evidence: cspValue
            });
            score += 25;
        }
    }

    // 3. X-Content-Type-Options (15 pts)
    const xctoValue = getHeaderValue(headers, "x-content-type-options");
    if (!xctoValue) {
        findings.push({
            id: "missing-xcto",
            category: "Headers",
            name: "X-Content-Type-Options",
            status: "MISSING",
            severity: "LOW",
            points: 0,
            maxPoints: 15,
            description: "Without MIME-sniffing protection, browser behaviors might interpret response content types differently than declared, potentially leading to unauthorized script execution under context-mismatch.",
            recommendation: "Set: X-Content-Type-Options: nosniff"
        });
    } else {
        if (xctoValue.toLowerCase() === "nosniff") {
            findings.push({
                id: "xcto-ok",
                category: "Headers",
                name: "X-Content-Type-Options",
                status: "PASS",
                severity: "INFO",
                points: 15,
                maxPoints: 15,
                description: "Prevents browsers from executing non-script MIME files.",
                evidence: xctoValue
            });
            score += 15;
        } else {
            findings.push({
                id: "invalid-xcto",
                category: "Headers",
                name: "X-Content-Type-Options",
                status: "INVALID",
                severity: "HIGH",
                points: 0,
                maxPoints: 15,
                description: "X-Content-Type-Options key is configured but set to an invalid value (must be 'nosniff').",
                recommendation: "Change X-Content-Type-Options setting strictly to 'nosniff'.",
                evidence: xctoValue
            });
        }
    }

    // 4. X-Frame-Options (15 pts)
    const xfoValue = getHeaderValue(headers, "x-frame-options");
    const cspHasFrameAncestors = parsedCsp && parsedCsp.hasFrameAncestors;

    if (!xfoValue) {
        if (cspHasFrameAncestors) {
            findings.push({
                id: "xfo-missing-but-csp-frame-ancestors",
                category: "Headers",
                name: "X-Frame-Options",
                status: "PASS",
                severity: "INFO",
                points: 15,
                maxPoints: 15,
                description: "X-Frame-Options is missing, but CSP 'frame-ancestors' is defined, which supersedes X-Frame-Options in modern browsers.",
                evidence: `CSP: ${cspValue}`
            });
            score += 15;
        } else {
            findings.push({
                id: "missing-xfo",
                category: "Headers",
                name: "X-Frame-Options",
                status: "MISSING",
                severity: "MEDIUM",
                points: 0,
                maxPoints: 15,
                description: "Without framing restrictions, external sites may frame this page, which can facilitate clickjacking attempts.",
                recommendation: "Configure X-Frame-Options to DENY or SAMEORIGIN, or define 'frame-ancestors' in CSP."
            });
        }
    } else {
        const xfoLower = xfoValue.toLowerCase();
        if (xfoLower === "deny" || xfoLower === "sameorigin") {
            findings.push({
                id: "xfo-ok",
                category: "Headers",
                name: "X-Frame-Options",
                status: "PASS",
                severity: "INFO",
                points: 15,
                maxPoints: 15,
                description: "Protects site frames from unauthorized browser window wrapping.",
                evidence: xfoValue
            });
            score += 15;
        } else {
            findings.push({
                id: "invalid-xfo",
                category: "Headers",
                name: "X-Frame-Options",
                status: "INVALID",
                severity: "HIGH",
                points: 0,
                maxPoints: 15,
                description: "X-Frame-Options value is invalid (only 'DENY' and 'SAMEORIGIN' are widely modern).",
                recommendation: "Change X-Frame-Options setting strictly to DENY or SAMEORIGIN.",
                evidence: xfoValue
            });
        }
    }

    // 5. Referrer-Policy (10 pts)
    const refValue = getHeaderValue(headers, "referrer-policy");
    if (!refValue) {
        findings.push({
            id: "missing-ref-policy",
            category: "Headers",
            name: "Referrer-Policy",
            status: "MISSING",
            severity: "LOW",
            points: 0,
            maxPoints: 10,
            description: "Default referrer policy applies, which may share sensitive URL path values with third-party sites during cross-origin navigations.",
            recommendation: "Configure a restrictive Referrer-Policy, such as 'strict-origin-when-cross-origin' or 'no-referrer'."
        });
    } else {
        const refLower = refValue.toLowerCase();
        if (refLower === "unsafe-url") {
            findings.push({
                id: "weak-ref-policy-unsafe-url",
                category: "Headers",
                name: "Referrer-Policy",
                status: "WEAK",
                severity: "MEDIUM",
                points: 3,
                maxPoints: 10,
                description: "Referrer-Policy is set to 'unsafe-url', which discloses full URL paths to external domains.",
                recommendation: "Change Referrer-Policy to a safer value (e.g. 'strict-origin-when-cross-origin').",
                evidence: refValue
            });
            score += 3;
        } else if (!REFERRER_POLICIES.includes(refLower)) {
            findings.push({
                id: "invalid-ref-policy",
                category: "Headers",
                name: "Referrer-Policy",
                status: "INVALID",
                severity: "MEDIUM",
                points: 0,
                maxPoints: 10,
                description: "Referrer-Policy specifies an invalid value.",
                recommendation: "Set a valid policy of: no-referrer, same-origin, or strict-origin-when-cross-origin.",
                evidence: refValue
            });
        } else {
            findings.push({
                id: "referrer-policy-ok",
                category: "Headers",
                name: "Referrer-Policy",
                status: "PASS",
                severity: "INFO",
                points: 10,
                maxPoints: 10,
                description: "Limits referrer leaking based on cross-origin rules.",
                evidence: refValue
            });
            score += 10;
        }
    }

    // 6. Permissions-Policy (15 pts)
    const permValue = getHeaderValue(headers, "permissions-policy");
    if (!permValue) {
        findings.push({
            id: "missing-permissions-policy",
            category: "Headers",
            name: "Permissions-Policy",
            status: "MISSING",
            severity: "INFO",
            points: 0,
            maxPoints: 15,
            description: "No restrictive Permissions-Policy found. Restricting capabilities access is recommended as a hardening measure.",
            recommendation: "Restrict hardware capabilities the application does not need using a Permissions-Policy header."
        });
    } else {
        // Basic presence / syntax analysis
        findings.push({
            id: "permissions-policy-ok",
            category: "Headers",
            name: "Permissions-Policy",
            status: "PASS",
            severity: "INFO",
            points: 15,
            maxPoints: 15,
            description: "Features capabilities restrictions active.",
            evidence: permValue
        });
        score += 15;
    }

    return {
        score,
        maxScore: 100,
        findings
    };
}
