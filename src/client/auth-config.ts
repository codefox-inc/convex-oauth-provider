/**
 * Auth Config Generator
 *
 * Generates auth.config.ts configuration for Convex Auth
 * to trust JWTs from the OAuth Provider.
 */

import { normalizePrefix } from "../lib/oauth.js";

/**
 * Auth provider configuration for Convex
 */
export interface AuthProvider {
    domain: string;
    applicationID: string;
}

/**
 * Auth config structure (matches Convex Auth config)
 */
export interface AuthConfig {
    providers: AuthProvider[];
}

/**
 * Options for generating auth config
 */
export interface GenerateAuthConfigOptions {
    /**
     * CONVEX_SITE_URL - the deployed Convex site URL
     * @example "https://your-app.convex.site"
     */
    convexSiteUrl?: string;

    /**
     * Local development port for OAuth provider
     * @default 5173
     */
    localPort?: number;

    /**
     * OAuth endpoint prefix
     * @default "/oauth"
     */
    prefix?: string;

    /**
     * Audience value for JWT validation
     * @default "convex"
     */
    applicationID?: string;

    /**
     * Additional provider domains to trust
     */
    additionalProviders?: AuthProvider[];

    /**
     * Include the CONVEX_SITE_URL as a provider (for Convex Auth)
     * @default true
     */
    includeConvexSiteUrl?: boolean;
}

/**
 * Generate auth.config.ts configuration for OAuth Provider
 *
 * @example
 * ```typescript
 * // convex/auth.config.ts
 * import { generateAuthConfig } from "@codefox-inc/oauth-provider";
 *
 * export default generateAuthConfig({
 *   convexSiteUrl: process.env.CONVEX_SITE_URL,
 *   localPort: 5173,
 * });
 * ```
 *
 * @example Output
 * ```javascript
 * {
 *   providers: [
 *     { domain: "https://your-app.convex.site", applicationID: "convex" },
 *     { domain: "http://localhost:5173/oauth", applicationID: "convex" },
 *     { domain: "https://your-app.convex.site/oauth", applicationID: "convex" },
 *   ]
 * }
 * ```
 */
export function generateAuthConfig(options: GenerateAuthConfigOptions = {}): AuthConfig {
    const {
        convexSiteUrl,
        localPort = 5173,
        prefix: rawPrefix = "/oauth",
        applicationID = "convex",
        additionalProviders = [],
        includeConvexSiteUrl = true,
    } = options;
    const prefix = normalizePrefix(rawPrefix);

    const providers: AuthProvider[] = [];

    // 1. CONVEX_SITE_URL for Convex Auth (session-based auth)
    if (includeConvexSiteUrl && convexSiteUrl) {
        providers.push({
            domain: convexSiteUrl,
            applicationID,
        });
    }

    // 2. Local development OAuth issuer
    providers.push({
        domain: `http://localhost:${localPort}${prefix}`,
        applicationID,
    });

    // 3. Production OAuth issuer (CONVEX_SITE_URL + prefix)
    if (convexSiteUrl) {
        providers.push({
            domain: `${convexSiteUrl}${prefix}`,
            applicationID,
        });
    }

    // 4. Additional providers
    providers.push(...additionalProviders);

    return { providers };
}

/**
 * Create auth config with validation
 * Throws if required environment variables are missing
 */
export function createAuthConfig(options: GenerateAuthConfigOptions = {}): AuthConfig {
    const config = generateAuthConfig(options);

    const prefix = normalizePrefix(options.prefix);
    const localPort = options.localPort ?? 5173;

    // Validate that we have at least one OAuth issuer (with the configured prefix/port)
    const hasOAuthIssuer = config.providers.some(p => {
        if (prefix) {
            return p.domain.includes(prefix) || p.domain.includes(`:${localPort}`);
        }
        return p.domain.includes(`:${localPort}`) || (!!options.convexSiteUrl && p.domain === options.convexSiteUrl);
    });

    if (!hasOAuthIssuer) {
        console.warn(
            "[oauth-provider] Warning: No OAuth issuer found in auth config. " +
            "MCP clients may not be able to authenticate."
        );
    }

    return config;
}
