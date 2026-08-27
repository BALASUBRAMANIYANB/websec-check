/**
 * Core fetch caller and analyzer orchestration.
 * Monitors headers, CORS, cookies, redirection state, and response timings.
 */

import { analyzeHeaders } from "./headers.js";
import { analyzeCookies } from "./cookies.js";
import { analyzeCors } from "./cors.js";
import { calculateScore } from "./scoring.js";

/**
 * Scans the absolute URL and calculates security state.
 * Traces redirects manually or gathers redirection info.
 * @param {string} url 
 * @param {number} timeoutSeconds 
 * @param {string} version 
 * @returns {Promise<Object>}
 */
export async function scanWebsite(url, timeoutSeconds = 10, version = "1.0.0") {
    const userAgent = `websec-check/${version}`;
    const redirectChain = [];
    let currentUrl = url;

    // Follow redirects manually to construct the redirection chain and evaluate TLS/HTTP -> HTTPS steps
    const maxRedirects = 10;
    let redirectsCount = 0;
    let response = null;
    const startTime = Date.now();

    while (redirectsCount < maxRedirects) {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), timeoutSeconds * 1000);

        try {
            response = await fetch(currentUrl, {
                method: "GET",
                redirect: "manual", // follow redirects manually to trace them
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
                break; // No redirect Location header found
            }

            // Build absolute URL from relative path if necessary
            const absoluteLocation = new URL(location, currentUrl).toString();
            redirectChain.push(`${currentUrl} → ${absoluteLocation} (${response.status})`);
            currentUrl = absoluteLocation;
            redirectsCount++;
        } else {
            break; // Finished redirection chain
        }
    }

    const responseTimeMs = Date.now() - startTime;

    const headersResult = analyzeHeaders(response.headers);
    const cookiesResult = analyzeCookies(response.headers);
    const corsResult = analyzeCors(response.headers);

    // Score calculations
    const { score, riskLevel } = calculateScore({
        headersScore: headersResult.score,
        cookieDeduction: cookiesResult.deduction,
        corsDeduction: corsResult.deduction
    });

    const serverHeader = response.headers.get("server");

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
        score,
        riskLevel
    };
}
