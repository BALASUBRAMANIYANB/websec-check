/**
 * Scans Cookie headers for security properties.
 * Identifies if cookies are sensitive (e.g. key, sessionid, token, etc.)
 * Checks attributes: Secure, HttpOnly, SameSite, Domain, Path, Expires, Max-Age.
 */

const SENSITIVE_KEYWORDS = [
    "session", "sid", "token", "auth", "jwt", "key", "login",
    "admin", "secret", "pwd", "password", "xsrf", "csrf"
];

/**
 * Determines whether a cookie name looks sensitive.
 * @param {string} name 
 * @returns {boolean}
 */
function isSensitiveCookie(name) {
    const lowerName = name.toLowerCase();
    return SENSITIVE_KEYWORDS.some(keyword => lowerName.includes(keyword));
}

/**
 * Parses Set-Cookie header strings and returns detailed properties.
 * Handles commas in Expires attributes safely.
 * @param {string} cookieStr 
 * @returns {Object|null}
 */
function parseCookie(cookieStr) {
    if (!cookieStr || typeof cookieStr !== "string") return null;

    const parts = cookieStr.split(";").map(p => p.trim());
    if (parts.length === 0 || !parts[0]) return null;

    const firstPart = parts[0];
    const eqIdx = firstPart.indexOf("=");
    const name = eqIdx > 0 ? firstPart.substring(0, eqIdx) : firstPart;
    const value = eqIdx > 0 ? firstPart.substring(eqIdx + 1) : "";

    const attributes = {
        name,
        value,
        secure: false,
        httpOnly: false,
        sameSite: null,
        domain: null,
        path: null,
        expires: null,
        maxAge: null,
        rawAttributes: {}
    };

    for (let i = 1; i < parts.length; i++) {
        const part = parts[i];
        if (!part) continue;

        const eqSign = part.indexOf("=");
        const attrName = eqSign > 0 ? part.substring(0, eqSign).trim().toLowerCase() : part.trim().toLowerCase();
        const attrVal = eqSign > 0 ? part.substring(eqSign + 1).trim() : null;

        attributes.rawAttributes[attrName] = attrVal || true;

        if (attrName === "secure") {
            attributes.secure = true;
        } else if (attrName === "httponly") {
            attributes.httpOnly = true;
        } else if (attrName === "samesite") {
            attributes.sameSite = attrVal; // e.g. Lax, Strict, None
        } else if (attrName === "domain") {
            attributes.domain = attrVal;
        } else if (attrName === "path") {
            attributes.path = attrVal;
        } else if (attrName === "expires") {
            attributes.expires = attrVal;
        } else if (attrName === "max-age") {
            attributes.maxAge = attrVal;
        }
    }

    return attributes;
}

/**
 * Analyzes response cookies and returns findings conforming to standard model.
 * @param {Headers|Object} headers 
 * @returns {Object} { findings, deduction }
 */
export function analyzeCookies(headers) {
    let cookieHeaders = [];

    if (headers && typeof headers.getSetCookie === "function") {
        cookieHeaders = headers.getSetCookie();
    } else if (headers && typeof headers.get === "function") {
        const val = headers.get("set-cookie");
        if (val) {
            // Node headers.get('set-cookie') might return a single string or raise issues if comma-separated.
            // Under fallback, split by comma ONLY if it's not followed by 'Expires=' style date format.
            // Simple split regex: comma followed by a lookahead of a Word= pair.
            // But if getSetCookie exists, we rely on it.
            // Let's do a basic lookahead parse to separate cookies.
            cookieHeaders = val.split(/,\s*(?=[a-zA-Z0-9_\-]+[=;])/);
        }
    } else if (headers && typeof headers === "object") {
        const lowerKey = "set-cookie";
        for (const key of Object.keys(headers)) {
            if (key.toLowerCase() === lowerKey) {
                const val = headers[key];
                cookieHeaders = Array.isArray(val) ? val : [val];
                break;
            }
        }
    }

    const findings = [];
    let totalDeduction = 0;
    const cookiesChecked = [];

    for (const cookieStr of cookieHeaders) {
        const parsed = parseCookie(cookieStr);
        if (!parsed) continue;

        cookiesChecked.push(parsed.name);
        const sensitive = isSensitiveCookie(parsed.name);
        let cookieDeduction = 0;

        // Check 1: Secure attribute
        if (!parsed.secure) {
            if (sensitive) {
                findings.push({
                    id: `cookie-no-secure-sensitive-${parsed.name}`,
                    category: "Cookies",
                    name: `Cookie: ${parsed.name}`,
                    status: "WEAK",
                    severity: "MEDIUM",
                    points: 0,
                    maxPoints: 0,
                    description: `Sensitive cookie "${parsed.name}" is missing the "Secure" attribute. It can be sent over cleartext connections, increasing transit disclosure risks.`,
                    recommendation: `Add the "Secure" flag to the "${parsed.name}" cookie so that browsers only transmit it over secure HTTPS connections.`,
                    evidence: cookieStr
                });
                cookieDeduction += 10;
            } else {
                findings.push({
                    id: `cookie-no-secure-${parsed.name}`,
                    category: "Cookies",
                    name: `Cookie: ${parsed.name}`,
                    status: "REVIEW",
                    severity: "LOW",
                    points: 0,
                    maxPoints: 0,
                    description: `Cookie "${parsed.name}" is missing the "Secure" attribute.`,
                    recommendation: `Add the "Secure" flag if this cookie is used for any stateful or sensitive tracking.`,
                    evidence: cookieStr
                });
                cookieDeduction += 2;
            }
        }

        // Check 2: HttpOnly attribute
        if (!parsed.httpOnly) {
            if (sensitive) {
                findings.push({
                    id: `cookie-no-httponly-sensitive-${parsed.name}`,
                    category: "Cookies",
                    name: `Cookie: ${parsed.name}`,
                    status: "WEAK",
                    severity: "MEDIUM",
                    points: 0,
                    maxPoints: 0,
                    description: `Sensitive cookie "${parsed.name}" lacks the "HttpOnly" flag. This allows access via client-side scripts, reducing protection against XSS-based theft.`,
                    recommendation: `Add the "HttpOnly" flag to lock down the cookie from document.cookie scripts.`,
                    evidence: cookieStr
                });
                cookieDeduction += 10;
            } else {
                findings.push({
                    id: `cookie-no-httponly-${parsed.name}`,
                    category: "Cookies",
                    name: `Cookie: ${parsed.name}`,
                    status: "REVIEW",
                    severity: "LOW",
                    points: 0,
                    maxPoints: 0,
                    description: `Cookie "${parsed.name}" does not have the "HttpOnly" attribute.`,
                    recommendation: `Identify if client-side script access is needed; if not, configure "HttpOnly".`,
                    evidence: cookieStr
                });
                cookieDeduction += 2;
            }
        }

        // Check 3: SameSite attribute
        if (!parsed.sameSite) {
            findings.push({
                id: `cookie-no-samesite-${parsed.name}`,
                category: "Cookies",
                name: `Cookie: ${parsed.name}`,
                status: "MISSING",
                severity: "LOW",
                points: 0,
                maxPoints: 0,
                description: `Cookie "${parsed.name}" lacks an explicit "SameSite" policy. Browsers may apply default behaviors, which could increase cross-site request forgery (CSRF) exposure.`,
                recommendation: `Set "SameSite=Lax" (default safe) or "SameSite=Strict" depending on navigation requirements.`,
                evidence: cookieStr
            });
            cookieDeduction += 5;
        } else {
            const ssLower = parsed.sameSite.toLowerCase();
            if (ssLower === "none" && !parsed.secure) {
                findings.push({
                    id: `cookie-samesite-none-insecure-${parsed.name}`,
                    category: "Cookies",
                    name: `Cookie: ${parsed.name}`,
                    status: "INVALID",
                    severity: "MEDIUM",
                    points: 0,
                    maxPoints: 0,
                    description: `Cookie "${parsed.name}" specifies "SameSite=None" but lacks the "Secure" flag. Modern browsers reject this configuration, potentially leading to cookie transmission failure.`,
                    recommendation: `Add the "Secure" flag to this cookie or change "SameSite" to "Lax"/"Strict".`,
                    evidence: cookieStr
                });
                cookieDeduction += 10;
            }
        }

        totalDeduction += cookieDeduction;
    }

    // Cap the maximum cookie deduction at 20 points
    const finalDeduction = Math.min(totalDeduction, 20);

    return {
        findings,
        deduction: finalDeduction,
        cookiesChecked
    };
}
