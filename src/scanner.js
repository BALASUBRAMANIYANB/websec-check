/**
 * Fetch orchestrator coordinating headers, CORS, cookies, redirect chains,
 * information exposure, cache, HTTP methods, security.txt, and TLS/SSL checks.
 */

import { analyzeHeaders } from "./headers.js";
import { analyzeCookies } from "./cookies.js";
import { analyzeCors } from "./cors.js";
import { analyzeRedirects } from "./redirects.js";
import { analyzeDisclosure } from "./disclosure.js";
import { analyzeCache } from "./cache.js";
import { analyzeMethods } from "./methods.js";
import { analyzeSecurityTxt } from "./securitytxt.js";
import { analyzeTls } from "./tls.js";
import { calculateScore } from "./scoring.js";

/**
 * Scans the absolute URL and calculates security state.
 * Traces redirects manually up to maxRedirects limit.
 * @param {string} url 
 * @param {number} [timeoutSeconds=10] 
 * @param {string} [version="1.2.0"] 
 * @param {number} [maxRedirects=5] 
 * @param {Object} [options={}]
 * @param {boolean} [options.skipTls=false]
 * @param {Function} [options.fetchFn=globalThis.fetch]
 * @param {Function} [options.tlsConnectFn]
 * @returns {Promise<Object>}
 */
export async function scanWebsite(
    url,
    timeoutSeconds = 10,
    version = "1.2.0",
    maxRedirects = 5,
    { skipTls = false, fetchFn = globalThis.fetch, tlsConnectFn } = {}
) {
    const userAgent = `websec-check/${version}`;
    const redirectChain = [];
    let currentUrl = url;
    let redirectsCount = 0;
    let response = null;
    const startTime = Date.now();

    while (redirectsCount < maxRedirects) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutSeconds * 1000);

        try {
            response = await fetchFn(currentUrl, {
                method: "GET",
                redirect: "manual", // trace redirects manually
                headers: {
                    "User-Agent": userAgent
                },
                signal: controller.signal
            });
        } finally {
            clearTimeout(timeoutId);
        }

        if (response.status >= 300 && response.status < 400) {
            const location = response.headers.get("location");
            if (!location) {
                break;
            }

            const absoluteLocation = new URL(location, currentUrl).toString();
            redirectChain.push({
                url: absoluteLocation,
                status: response.status,
                headers: response.headers
            });
            currentUrl = absoluteLocation;
            redirectsCount++;
        } else {
            break;
        }
    }

    if (!response) {
        throw new Error("No response received from target.");
    }

    const responseTimeMs = Date.now() - startTime;

    // Execute passive analyzers
    const headersResult = analyzeHeaders(response.headers);
    const cookiesResult = analyzeCookies(response.headers);
    const corsResult = analyzeCors(response.headers);
    const redirectsResult = analyzeRedirects(redirectChain, url, currentUrl);
    const disclosureResult = analyzeDisclosure(response.headers);
    const cacheResult = analyzeCache(response.headers);
    const methodsResult = analyzeMethods(response.headers);

    // TLS / SSL certificate inspection
    const tlsResult = skipTls
        ? { findings: [], deduction: 0, certificate: null }
        : await analyzeTls(currentUrl, timeoutSeconds, tlsConnectFn);

    // security.txt check
    const securityTxtResult = await analyzeSecurityTxt(currentUrl, timeoutSeconds, fetchFn);

    // Score synthesis
    const { score, riskLevel } = calculateScore({
        headersScore: headersResult.score,
        cookieDeduction: cookiesResult.deduction,
        corsDeduction: corsResult.deduction,
        redirectDeduction: redirectsResult.deduction,
        disclosureDeduction: disclosureResult.deduction,
        cacheDeduction: cacheResult.deduction,
        methodsDeduction: methodsResult.deduction,
        tlsDeduction: tlsResult.deduction
    });

    const serverHeader = response.headers.get("server");

    // Unified list of all findings
    const findings = [
        ...headersResult.findings,
        ...cookiesResult.findings,
        ...corsResult.findings,
        ...redirectsResult.findings,
        ...disclosureResult.findings,
        ...cacheResult.findings,
        ...methodsResult.findings,
        ...tlsResult.findings,
        ...securityTxtResult.findings
    ];

    return {
        url,
        finalUrl: currentUrl,
        status: response.status,
        responseTimeMs,
        server: serverHeader,
        redirectChain,
        headersResult,
        cookiesResult,
        corsResult,
        redirectsResult,
        disclosureResult,
        cacheResult,
        methodsResult,
        tlsResult,
        securityTxtResult,
        findings,
        score,
        riskLevel
    };
}
