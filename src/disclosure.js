/**
 * Passive Information Disclosure Analyzer.
 * Checks for Server, X-Powered-By, X-AspNet-Version, X-AspNetMvc-Version, and Via headers.
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
 * Analyzes response headers for information disclosure.
 * @param {Headers|Object} headers 
 * @returns {Object} { findings, deduction }
 */
export function analyzeDisclosure(headers) {
    const findings = [];
    let deduction = 0;

    const serverVal = getHeaderValue(headers, "server");
    const poweredByVal = getHeaderValue(headers, "x-powered-by");
    const aspNetVal = getHeaderValue(headers, "x-aspnet-version");
    const aspNetMvcVal = getHeaderValue(headers, "x-aspnetmvc-version");
    const viaVal = getHeaderValue(headers, "via");

    // Helper to determine if version details exist in value
    const hasDetailedVersion = (val) => {
        if (!val || typeof val !== "string") return false;
        // Match numbers, slash slash syntax (e.g. Apache/2.4.41, nginx/1.18.0, ASP.NET 4.0)
        return /[0-9]+\.[0-9]+/.test(val);
    };

    // 1. Server Header Check
    if (serverVal) {
        const detailed = hasDetailedVersion(serverVal);
        findings.push({
            id: detailed ? "server-disclosure-detailed" : "server-disclosure-generic",
            category: "Disclosure",
            name: "Server Header Disclosure",
            status: "WARN",
            severity: detailed ? "LOW" : "INFO",
            points: 0,
            maxPoints: 0,
            description: detailed
                ? `Response header discloses detailed technology/version specifics: "${serverVal}".`
                : `Response header discloses technology type: "${serverVal}".`,
            recommendation: "Configure the server daemon to strip this header entirely or return generic values.",
            evidence: `Server: ${serverVal}`
        });
        deduction += detailed ? 4 : 1;
    }

    // 2. X-Powered-By Check
    if (poweredByVal) {
        const detailed = hasDetailedVersion(poweredByVal);
        findings.push({
            id: detailed ? "powered-by-detailed" : "powered-by-generic",
            category: "Disclosure",
            name: "X-Powered-By Exposure",
            status: "WARN",
            severity: "LOW",
            points: 0,
            maxPoints: 0,
            description: `Header discloses underlying runtime technology framework: "${poweredByVal}".`,
            recommendation: "Disable or block the X-Powered-By response header at reverse proxy or framework level.",
            evidence: `X-Powered-By: ${poweredByVal}`
        });
        deduction += detailed ? 3 : 2;
    }

    // 3. X-AspNet-Version / X-AspNetMvc-Version
    if (aspNetVal) {
        findings.push({
            id: "aspnet-version-disclosure",
            category: "Disclosure",
            name: "ASP.NET Version Disclosure",
            status: "WARN",
            severity: "LOW",
            points: 0,
            maxPoints: 0,
            description: `Detailed ASP.NET version disclosed: "${aspNetVal}".`,
            recommendation: "Set <httpRuntime enableVersionHeader=\"false\" /> in web.config.",
            evidence: `X-AspNet-Version: ${aspNetVal}`
        });
        deduction += 3;
    }

    if (aspNetMvcVal) {
        findings.push({
            id: "aspnetmvc-version-disclosure",
            category: "Disclosure",
            name: "ASP.NET MVC Version Disclosure",
            status: "WARN",
            severity: "LOW",
            points: 0,
            maxPoints: 0,
            description: `Detailed ASP.NET MVC model version disclosed: "${aspNetMvcVal}".`,
            recommendation: "Set MvcHandler.DisableVersionHeader = true; in Global.asax Application_Start.",
            evidence: `X-AspNetMvc-Version: ${aspNetMvcVal}`
        });
        deduction += 3;
    }

    // 4. Via Header Check
    if (viaVal) {
        findings.push({
            id: "via-disclosure",
            category: "Disclosure",
            name: "Via Gateway Disclosure",
            status: "WARN",
            severity: "INFO",
            points: 0,
            maxPoints: 0,
            description: `Intermediate proxy pipeline detailed: "${viaVal}".`,
            recommendation: "Consider disabling Via header injection on forward proxies or API gateway routers to reduce proxy mapping disclosure.",
            evidence: `Via: ${viaVal}`
        });
        deduction += 1;
    }

    return {
        findings,
        deduction: Math.min(deduction, 10) // Capped at 10 pts
    };
}
