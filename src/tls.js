/**
 * Audits TLS / SSL certificate properties and negotiated protocol security.
 * Uses native node:tls and node:https with zero external dependencies.
 */

import tls from "node:tls";

/**
 * Evaluates TLS/SSL configuration for a target URL.
 * @param {string} targetUrl 
 * @param {number} timeoutSeconds 
 * @param {Function} [connectFn] - Optional mockable TLS connect function
 * @returns {Promise<Object>} { findings, deduction, certificate }
 */
export async function analyzeTls(targetUrl, timeoutSeconds = 10, connectFn = tls.connect) {
    const findings = [];
    let deduction = 0;

    let parsed;
    try {
        parsed = new URL(targetUrl);
    } catch {
        return { findings, deduction: 0, certificate: null };
    }

    // 1. Check HTTP vs HTTPS
    if (parsed.protocol !== "https:") {
        findings.push({
            id: "tls-not-https",
            category: "TLS",
            name: "HTTPS Protocol",
            status: "FAIL",
            severity: "HIGH",
            points: -15,
            description: "Site is served over unencrypted HTTP. All data in transit is vulnerable to sniffing and tampering.",
            recommendation: "Obtain an SSL/TLS certificate and enforce HTTPS across the domain with HTTP-to-HTTPS redirects.",
            evidence: `Protocol: ${parsed.protocol}`
        });
        return { findings, deduction: 15, certificate: null };
    }

    const port = parsed.port ? parseInt(parsed.port, 10) : 443;
    const hostname = parsed.hostname;

    return new Promise((resolve) => {
        let settled = false;
        const finish = (res) => {
            if (!settled) {
                settled = true;
                resolve(res);
            }
        };

        const timer = setTimeout(() => {
            if (socket && !socket.destroyed) {
                socket.destroy();
            }
            finish({
                findings: [{
                    id: "tls-handshake-timeout",
                    category: "TLS",
                    name: "TLS Connection Timeout",
                    status: "WARN",
                    severity: "LOW",
                    points: 0,
                    description: `TLS handshake timed out after ${timeoutSeconds}s on ${hostname}:${port}.`,
                    recommendation: "Verify server network configuration and ensure port 443 responds promptly to TLS handshakes.",
                    evidence: `Target: ${hostname}:${port}`
                }],
                deduction: 0,
                certificate: null
            });
        }, timeoutSeconds * 1000);

        let socket;
        try {
            socket = connectFn({
                host: hostname,
                port,
                servername: hostname, // SNI support
                rejectUnauthorized: false // Inspect peer certificate without aborting prematurely
            }, () => {
                clearTimeout(timer);

                try {
                    const cert = socket.getPeerCertificate ? socket.getPeerCertificate(true) : null;
                    const authorized = socket.authorized;
                    const authorizationError = socket.authorizationError;
                    const protocol = socket.getProtocol ? socket.getProtocol() : "Unknown";
                    const cipher = socket.getCipher ? socket.getCipher() : null;

                    socket.end();

                    if (!cert || Object.keys(cert).length === 0) {
                        findings.push({
                            id: "tls-cert-unavailable",
                            category: "TLS",
                            name: "TLS Certificate Presentation",
                            status: "WARN",
                            severity: "MEDIUM",
                            points: 0,
                            description: "No peer certificate was provided by the TLS server.",
                            recommendation: "Configure a valid X.509 server certificate on the HTTPS listener.",
                            evidence: `Host: ${hostname}:${port}`
                        });
                        return finish({ findings, deduction: 0, certificate: null });
                    }

                    // A. Certificate Authorization & Trust
                    if (!authorized) {
                        const errReason = authorizationError ? String(authorizationError) : "Untrusted certificate chain";
                        findings.push({
                            id: "tls-untrusted-cert",
                            category: "TLS",
                            name: "Certificate Trust Chain",
                            status: "FAIL",
                            severity: "HIGH",
                            points: -15,
                            description: `Certificate verification failed: ${errReason}. Browsers will display security warnings.`,
                            recommendation: "Deploy a valid certificate issued by a globally recognized Certificate Authority (e.g. Let's Encrypt).",
                            evidence: `Authorization Error: ${errReason}`
                        });
                        deduction += 15;
                    } else {
                        const issuerName = cert.issuer ? (cert.issuer.O || cert.issuer.CN || "Trusted CA") : "Trusted CA";
                        findings.push({
                            id: "tls-trusted-cert",
                            category: "TLS",
                            name: "Certificate Trust Chain",
                            status: "PASS",
                            severity: "INFO",
                            points: 0,
                            description: `Certificate is valid and signed by a trusted authority (${issuerName}).`,
                            recommendation: "Maintain automated renewal via ACME / Let's Encrypt.",
                            evidence: `Issuer: ${issuerName}\nSubject: ${cert.subject?.CN || hostname}`
                        });
                    }

                    // B. Expiration & Remaining Days
                    if (cert.valid_to) {
                        const validToTime = new Date(cert.valid_to).getTime();
                        const now = Date.now();
                        const daysRemaining = Math.floor((validToTime - now) / (1000 * 60 * 60 * 24));

                        if (daysRemaining < 0) {
                            findings.push({
                                id: "tls-cert-expired",
                                category: "TLS",
                                name: "Certificate Expiration",
                                status: "FAIL",
                                severity: "HIGH",
                                points: -15,
                                description: `Certificate expired on ${cert.valid_to} (${Math.abs(daysRemaining)} days ago).`,
                                recommendation: "Renew the expired TLS certificate immediately to restore secure visitor access.",
                                evidence: `Expired: ${cert.valid_to}`
                            });
                            deduction += 15;
                        } else if (daysRemaining <= 30) {
                            findings.push({
                                id: "tls-cert-expiring-soon",
                                category: "TLS",
                                name: "Certificate Expiration",
                                status: "WARN",
                                severity: "MEDIUM",
                                points: -5,
                                description: `Certificate will expire soon in ${daysRemaining} day(s) on ${cert.valid_to}.`,
                                recommendation: "Renew the TLS certificate before expiration to prevent service downtime.",
                                evidence: `Valid Until: ${cert.valid_to} (${daysRemaining} days remaining)`
                            });
                            deduction += 5;
                        } else {
                            findings.push({
                                id: "tls-cert-validity",
                                category: "TLS",
                                name: "Certificate Expiration",
                                status: "PASS",
                                severity: "INFO",
                                points: 0,
                                description: `Certificate is active with ${daysRemaining} day(s) of remaining validity.`,
                                recommendation: "Monitor renewal automation as expiry nears.",
                                evidence: `Valid Until: ${cert.valid_to} (${daysRemaining} days)`
                            });
                        }
                    }

                    // C. TLS Protocol Version Check
                    const lowerProtocol = (protocol || "").toLowerCase();
                    if (lowerProtocol === "tlsv1" || lowerProtocol === "tlsv1.1" || lowerProtocol === "sslv3") {
                        findings.push({
                            id: "tls-deprecated-protocol",
                            category: "TLS",
                            name: "TLS Protocol Version",
                            status: "FAIL",
                            severity: "HIGH",
                            points: -10,
                            description: `Insecure, deprecated protocol negotiated (${protocol}). Deprecated by IETF RFC 8996.`,
                            recommendation: "Disable TLS 1.0, TLS 1.1, and SSLv3. Require TLS 1.2 or TLS 1.3 only.",
                            evidence: `Negotiated Protocol: ${protocol}`
                        });
                        deduction += 10;
                    } else if (lowerProtocol === "tlsv1.3") {
                        findings.push({
                            id: "tls-protocol-modern",
                            category: "TLS",
                            name: "TLS Protocol Version",
                            status: "PASS",
                            severity: "INFO",
                            points: 0,
                            description: `Modern TLS 1.3 protocol successfully negotiated (${cipher?.name || "AES-GCM"}).`,
                            recommendation: "Maintain TLS 1.3 preference in server cipher suites.",
                            evidence: `Protocol: TLSv1.3\nCipher: ${cipher?.name || "Unknown"}`
                        });
                    } else if (lowerProtocol === "tlsv1.2") {
                        findings.push({
                            id: "tls-protocol-secure",
                            category: "TLS",
                            name: "TLS Protocol Version",
                            status: "PASS",
                            severity: "INFO",
                            points: 0,
                            description: `Secure TLS 1.2 negotiated (${cipher?.name || "AES-GCM"}). Consider enabling TLS 1.3.`,
                            recommendation: "Upgrade server configuration to support TLS 1.3 for enhanced speed and forward secrecy.",
                            evidence: `Protocol: TLSv1.2\nCipher: ${cipher?.name || "Unknown"}`
                        });
                    }

                    const certificateDetails = {
                        subject: cert.subject?.CN || hostname,
                        issuer: cert.issuer?.O || cert.issuer?.CN || "Unknown",
                        validFrom: cert.valid_from,
                        validTo: cert.valid_to,
                        protocol,
                        cipher: cipher?.name || "Unknown",
                        authorized
                    };

                    finish({
                        findings,
                        deduction: Math.min(deduction, 15),
                        certificate: certificateDetails
                    });
                } catch (parseErr) {
                    finish({
                        findings: [{
                            id: "tls-parse-error",
                            category: "TLS",
                            name: "TLS Inspection Error",
                            status: "WARN",
                            severity: "LOW",
                            points: 0,
                            description: `Could not parse certificate details: ${parseErr.message}`,
                            recommendation: "Inspect TLS configuration manually using openssl s_client.",
                            evidence: String(parseErr)
                        }],
                        deduction: 0,
                        certificate: null
                    });
                }
            });

            socket.on("error", (err) => {
                clearTimeout(timer);
                finish({
                    findings: [{
                        id: "tls-connection-error",
                        category: "TLS",
                        name: "TLS Connection Handshake",
                        status: "WARN",
                        severity: "LOW",
                        points: 0,
                        description: `Could not establish TLS connection to ${hostname}:${port}: ${err.message}`,
                        recommendation: "Verify that port 443 is open and serving HTTPS traffic.",
                        evidence: `Error: ${err.message}`
                    }],
                    deduction: 0,
                    certificate: null
                });
            });
        } catch (callErr) {
            clearTimeout(timer);
            finish({
                findings: [{
                    id: "tls-init-error",
                    category: "TLS",
                    name: "TLS Handshake Initialization",
                    status: "WARN",
                    severity: "LOW",
                    points: 0,
                    description: `Failed to initiate TLS connection: ${callErr.message}`,
                    recommendation: "Verify URL format and network accessibility.",
                    evidence: String(callErr)
                }],
                deduction: 0,
                certificate: null
            });
        }
    });
}
