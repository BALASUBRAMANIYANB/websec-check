/**
 * Validates that the provided URL is a valid Http or Https URL.
 * @param {string} value 
 * @returns {boolean}
 */
export function validateUrl(value) {
    try {
        const url = new URL(value);
        return url.protocol === "http:" || url.protocol === "https:";
    } catch {
        return false;
    }
}

/**
 * Custom parser for command line arguments.
 * Supports before/after options and URL extraction.
 * Options: --help, --version, --json, --verbose, --timeout <seconds>
 * @param {string[]} args 
 * @returns {Object} { url, options: { help, version, json, verbose, timeout }, error }
 */
export function parseArgs(args) {
    const options = {
        help: false,
        version: false,
        json: false,
        verbose: false,
        timeout: 10 // default 10 seconds
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
