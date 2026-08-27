/**
 * Validates that the provided URL is a valid Http or Https URL.
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

/**
 * Custom parser for command line arguments.
 * Supports before/after options and URL extraction.
 * Options: --help, --version, --json, --verbose, --timeout <seconds>, --no-color, --max-redirects <number>
 * @param {string[]} args 
 * @returns {Object} { url, options: { help, version, json, verbose, timeout, noColor, maxRedirects }, error }
 */
export function parseArgs(args) {
    const options = {
        help: false,
        version: false,
        json: false,
        verbose: false,
        timeout: 10, // default 10 seconds
        noColor: false,
        maxRedirects: 5 // default 5 redirects
    };
    let url = null;
    let error = null;

    for (let i = 0; i < args.length; i++) {
        const arg = args[i];

        if (arg === "--help") {
            options.help = true;
        } else if (arg === "--version") {
            options.version = true;
        } else if (arg === "--json") {
            options.json = true;
        } else if (arg === "--verbose") {
            options.verbose = true;
        } else if (arg === "--no-color") {
            options.noColor = true;
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
            i++; // skip next arg
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
            i++; // skip next arg
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
