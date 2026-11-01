/**
 * Validates that the provided URL is a valid Http or Https URL.
 * Restricts private, loopback, and local IP addresses to prevent SSRF abuse.
 * @param {string} value 
 * @returns {boolean}
 */
export function validateUrl(value) {
    try {
        const url = new URL(value);
        if (url.protocol !== "http:" && url.protocol !== "https:") {
            return false;
        }

        const hostname = url.hostname.toLowerCase();
        const isPrivate =
            hostname === "localhost" ||
            hostname === "0.0.0.0" ||
            hostname === "[::1]" ||
            /^127\./.test(hostname) ||
            /^10\./.test(hostname) ||
            /^192\.168\./.test(hostname) ||
            /^169\.254\./.test(hostname) ||
            /^172\.(1[6-9]|2[0-9]|3[01])\./.test(hostname) ||
            hostname.startsWith("fc00:") ||
            hostname.startsWith("fd00:") ||
            hostname.startsWith("fe80:");

        return !isPrivate;
    } catch {
        return false;
    }
}

const VALID_FORMATS = ["terminal", "json", "sarif", "markdown"];

/**
 * Custom parser for command line arguments.
 * Supports flags: --help (-h), --version (-v), --json, --format, --output (-o),
 *                 --fail-below, --verbose, --timeout, --no-color, --max-redirects, --skip-tls
 * @param {string[]} args 
 * @returns {Object} { url, options, error }
 */
export function parseArgs(args) {
    const options = {
        help: false,
        version: false,
        json: false,
        format: "terminal",
        output: null,
        failBelow: null,
        verbose: false,
        timeout: 10, // default 10 seconds
        noColor: false,
        maxRedirects: 5, // default 5 redirects
        skipTls: false
    };
    let url = null;
    let error = null;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg === "--help" || arg === "-h") {
            options.help = true;
        } else if (arg === "--version" || arg === "-v") {
            options.version = true;
        } else if (arg === "--json") {
            options.json = true;
            options.format = "json";
        } else if (arg === "--format") {
            const nextArg = args[i + 1];
            if (!nextArg || !VALID_FORMATS.includes(nextArg.toLowerCase())) {
                error = `Invalid format: "${nextArg || ""}". Supported formats: ${VALID_FORMATS.join(", ")}`;
                break;
            }
            options.format = nextArg.toLowerCase();
            if (options.format === "json") {
                options.json = true;
            }
            i++;
        } else if (arg === "--output" || arg === "-o") {
            const nextArg = args[i + 1];
            if (!nextArg || nextArg.startsWith("-")) {
                error = `Missing output file path for ${arg} option.`;
                break;
            }
            options.output = nextArg;
            i++;
        } else if (arg === "--fail-below") {
            const nextArg = args[i + 1];
            if (!nextArg || isNaN(nextArg)) {
                error = `Invalid fail-below value: "${nextArg || ""}". Must be a number between 0 and 100.`;
                break;
            }
            const threshold = parseInt(nextArg, 10);
            if (threshold < 0 || threshold > 100) {
                error = `Invalid fail-below value: ${threshold}. Must be between 0 and 100.`;
                break;
            }
            options.failBelow = threshold;
            i++;
        } else if (arg === "--verbose") {
            options.verbose = true;
        } else if (arg === "--no-color") {
            options.noColor = true;
        } else if (arg === "--skip-tls") {
            options.skipTls = true;
        } else if (arg === "--max-redirects") {
            const nextArg = args[i + 1];
            if (!nextArg || isNaN(nextArg)) {
                error = `Invalid max-redirects value: ${nextArg || "missing"}. It must be a valid number.`;
                break;
            }
            const num = parseInt(nextArg, 10);
            if (num < 0) {
                error = `Invalid max-redirects value: ${num}. It must be a non-negative integer.`;
                break;
            }
            options.maxRedirects = num;
            i++;
        } else if (arg === "--timeout") {
            const nextArg = args[i + 1];
            if (!nextArg || isNaN(nextArg)) {
                error = `Invalid timeout value: ${nextArg || "missing"}. Timeout must be a valid number of seconds.`;
                break;
            }
            const seconds = parseInt(nextArg, 10);
            if (seconds <= 0) {
                error = `Invalid timeout value: ${seconds}. Timeout must be a positive integer greater than zero.`;
                break;
            }
            options.timeout = seconds;
            i++;
        } else if (arg.startsWith("-")) {
            error = `Unknown option: ${arg}`;
            break;
        } else {
            // Treat as target URL (the first non-option arg)
            if (!url) {
                url = arg;
            } else {
                error = `More than one target URL supplied: ${url} and ${arg}`;
                break;
            }
        }
    }

    return { url, options, error };
}
