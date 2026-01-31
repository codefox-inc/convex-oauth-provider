import {
    SignJWT,
    importPKCS8,
    exportJWK,
    jwtVerify,
    importSPKI,
    createLocalJWKSet
} from "jose";
import type { JWTPayload, KeyLike } from "jose";
import type { Auth } from "convex/server";
import type { RunActionCtx } from "./convex-types.js";

/**
 * OAuth 2.1 Provider Configuration
 */
export interface OAuthConfig {
    privateKey: string;      // JWT_PRIVATE_KEY or OAUTH_PRIVATE_KEY (PEM)
    jwks: string;            // JWKS or OAUTH_JWKS (JSON) - for JWKS endpoint & token verification (REQUIRED)
    keyId?: string;          // JWT kid to use for signing (overrides JWKS kid)
    siteUrl: string;         // SITE_URL
    convexSiteUrl?: string;  // CONVEX_SITE_URL (optional)
    allowedOrigins?: string; // ALLOWED_ORIGINS (comma-separated, optional)
    allowedScopes?: string[]; // Allowed scopes for dynamic client registration
    applicationID?: string;  // JWT audience (default: "convex", use "oauth-provider" with Better Auth)
    getUserId?: (ctx: RunActionCtx & { auth: Auth }, request: Request) => Promise<string | null> | string | null;
    checkAuthorization?: (ctx: RunActionCtx & { auth: Auth }, userId: string, clientId?: string) => Promise<boolean>;
    allowDynamicClientRegistration?: boolean;
    prefix?: string;         // OAuth endpoint prefix (default: "/oauth")
}

/**
 * User Profile for UserInfo endpoint
 */
export interface UserProfile {
    sub: string;
    name?: string;
    email?: string;
    picture?: string;
    email_verified?: boolean;
}

// Cache for keys to avoid re-parsing on every request
type JoseKey = Awaited<ReturnType<typeof importPKCS8>>;
type JoseJWK = Awaited<ReturnType<typeof exportJWK>>;

const keyCache = new Map<string, JoseKey>();
const jwkCache = new Map<string, JoseJWK>();
const jwksKeyCache = new Map<string, ReturnType<typeof createLocalJWKSet>>();
const DEFAULT_KEY_ID = "default-key";

/**
 * Reset key cache (for testing)
 */
export function resetKeysForTest() {
    keyCache.clear();
    jwkCache.clear();
    jwksKeyCache.clear();
}

/**
 * Get Private Key from PEM string
 */
async function getPrivateKey(privateKeyPEM: string): Promise<JoseKey> {
    const cacheKey = `private:${privateKeyPEM}`;
    const cached = keyCache.get(cacheKey);
    if (cached) return cached;

    const key = await importPKCS8(privateKeyPEM, "RS256");
    keyCache.set(cacheKey, key);
    return key;
}

/**
 * Get Public Key from PEM string
 */
async function getPublicKey(publicKeyPEM: string): Promise<JoseKey> {
    const cacheKey = `public:${publicKeyPEM}`;
    const cached = keyCache.get(cacheKey);
    if (cached) return cached;

    const key = await importSPKI(publicKeyPEM, "RS256", { extractable: true });
    keyCache.set(cacheKey, key);
    return key;
}

/**
 * Get Public JWK (for JWKS endpoint)
 * @deprecated Use getJWKS instead
 */
export async function getPublicJWK(publicKeyPEM: string): Promise<JoseJWK> {
    const cacheKey = `jwk:${publicKeyPEM}`;
    const cached = jwkCache.get(cacheKey);
    if (cached) return cached;

    const key = await getPublicKey(publicKeyPEM);
    const jwk = await exportJWK(key);

    // Remove private fields
    const { d: _d, p: _p, q: _q, dp: _dp, dq: _dq, qi: _qi, ...publicKey } = jwk;

    const result = { ...publicKey, use: "sig", alg: "RS256", kid: "default-key" };
    jwkCache.set(cacheKey, result);
    return result;
}

/**
 * Get JWKS for the JWKS endpoint
 * Adds kid: "default-key" to each key if not present (for compatibility with Convex Auth JWKS)
 */
export async function getJWKS(config: OAuthConfig): Promise<{ keys: JoseJWK[] }> {
    const jwks = JSON.parse(config.jwks) as { keys: JoseJWK[] };
    const keyId = getSigningKeyId(config);
    jwks.keys = jwks.keys.map((key) => {
        const {
            d: _d,
            p: _p,
            q: _q,
            dp: _dp,
            dq: _dq,
            qi: _qi,
            oth: _oth,
            k: _k,
            ...publicKey
        } = key as JoseJWK & {
            d?: string;
            p?: string;
            q?: string;
            dp?: string;
            dq?: string;
            qi?: string;
            oth?: unknown;
            k?: string;
        };

        return {
            ...publicKey,
            kid: publicKey.kid ?? keyId,
        };
    });

    return jwks;
}

function ensureKidOnJwksKeys(keys: JoseJWK[], keyId: string): JoseJWK[] {
    return keys.map((key) => ({
        ...key,
        kid: key.kid ?? keyId,
    }));
}

export function getSigningKeyId(config: OAuthConfig): string {
    if (config.keyId) return config.keyId;
    try {
        const jwks = JSON.parse(config.jwks) as { keys?: JoseJWK[] };
        const kid = jwks.keys?.[0]?.kid;
        if (typeof kid === "string" && kid.length > 0) {
            return kid;
        }
    } catch {
        // Fall through to default when jwks is invalid.
    }
    return DEFAULT_KEY_ID;
}

/**
 * Sign a JWT using the private key
 */
export async function sign(
    payload: Record<string, unknown>,
    subject: string,
    audience: string,
    expiresIn: string | number,
    privateKeyPEM: string,
    issuer?: string,
    keyId: string = DEFAULT_KEY_ID
): Promise<string> {
    const privateKey = await getPrivateKey(privateKeyPEM);

    const jwt = new SignJWT(payload)
        .setProtectedHeader({ alg: "RS256", kid: keyId })
        .setIssuedAt()
        .setSubject(subject)
        .setAudience(audience)
        .setExpirationTime(expiresIn);

    if (issuer) {
        jwt.setIssuer(issuer);
    }

    return jwt.sign(privateKey);
}

/**
 * Verify Access Token using JWKS from config
 */
export async function verifyAccessToken(
    token: string,
    config: Pick<OAuthConfig, 'jwks'> & { applicationID?: string },
    issuerUrl: string,
    expectedAudience?: string
): Promise<JWTPayload> {
    const publicKey = await getVerificationKey(config as OAuthConfig);
    const audience = expectedAudience ?? config.applicationID ?? "convex";

    const options = {
        issuer: issuerUrl,
        audience,
    };
    const { payload } = typeof publicKey === "function"
        ? await jwtVerify(token, publicKey, options)
        : await jwtVerify(token, publicKey, options);

    return payload;
}

/**
 * Get verification key from config (JWKS)
 */
async function getVerificationKey(
    config: OAuthConfig
): Promise<KeyLike | ReturnType<typeof createLocalJWKSet>> {
    const cached = jwksKeyCache.get(config.jwks);
    if (cached) return cached;

    const jwks = JSON.parse(config.jwks) as { keys: JoseJWK[] };
    if (!jwks.keys?.length) {
        throw new Error("jwks must include at least one key");
    }
    const normalized = { keys: ensureKidOnJwksKeys(jwks.keys, getSigningKeyId(config)) };
    const localJwks = createLocalJWKSet(normalized);
    jwksKeyCache.set(config.jwks, localJwks);
    return localJwks;
}

/**
 * Generate a random code (Authorization Code)
 */
export function generateCode(length = 32): string {
    const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
    let result = "";
    const randomValues = new Uint32Array(length);
    crypto.getRandomValues(randomValues);
    for (let i = 0; i < length; i++) {
        result += chars[randomValues[i] % chars.length];
    }
    return result;
}

/**
 * Generate a cryptographically strong Client Secret (hex string)
 */
export function generateClientSecret(length = 64): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Get Issuer URL helper
 */
export function getIssuerUrl(config: OAuthConfig): string {
    const issuerBaseUrl = config.convexSiteUrl ?? config.siteUrl;
    const prefix = normalizePrefix(config.prefix);
    return issuerBaseUrl + prefix;
}

/**
 * Normalize OAuth prefix for consistent URL building.
 * Ensures a leading slash, trims a trailing slash, and treats "/" as root ("").
 */
export function normalizePrefix(prefix?: string): string {
    const raw = (prefix ?? "/oauth").trim();
    if (!raw || raw === "/") return "";
    let normalized = raw.startsWith("/") ? raw : `/${raw}`;
    if (normalized.length > 1 && normalized.endsWith("/")) {
        normalized = normalized.slice(0, -1);
    }
    return normalized;
}

/**
 * CORS Helper - Get allowed origin
 */
export function getAllowedOrigin(origin: string | null, config: OAuthConfig): string | null {
    // 1. CLI / Non-browser clients (No Origin header)
    if (!origin) return null;

    // 2. Browser clients (Verified Origins)
    const toOrigin = (value: string | undefined): string | null => {
        if (!value) return null;
        try {
            return new URL(value).origin;
        } catch {
            return null;
        }
    };
    const allowedList = (config.allowedOrigins || "")
        .split(",")
        .map((u) => toOrigin(u.trim()))
        .filter((u): u is string => !!u);
    const siteOrigin = toOrigin(config.siteUrl);
    const convexOrigin = toOrigin(config.convexSiteUrl);

    if (allowedList.includes(origin)) return origin;
    if (siteOrigin && origin === siteOrigin) return origin;
    if (convexOrigin && origin === convexOrigin) return origin;

    // Allow Localhost (Development tools & Inspectors)
    if (/^http:\/\/localhost(:\d+)?$/.test(origin)) return origin;
    if (/^http:\/\/127\.0\.0\.1(:\d+)?$/.test(origin)) return origin;

    return null;
}

/**
 * Create CORS headers
 */
export function createCorsHeaders(
    origin: string | null,
    config: OAuthConfig,
    methods: string = "GET, POST, OPTIONS"
): Record<string, string> {
    const headers: Record<string, string> = {
        "Content-Type": "application/json",
        "Access-Control-Allow-Methods": methods,
        "Access-Control-Allow-Headers": "Content-Type, Authorization, mcp-protocol-version",
    };
    const allowedOrigin = getAllowedOrigin(origin, config);
    if (allowedOrigin) {
        headers["Access-Control-Allow-Origin"] = allowedOrigin;
    }
    return headers;
}

/**
 * Handle CORS preflight OPTIONS request
 */
export function handleCorsOptions(
    request: Request,
    config: OAuthConfig,
    methods: string = "GET, POST, OPTIONS"
): Response | null {
    if (request.method === "OPTIONS") {
        const origin = request.headers.get("Origin");
        return new Response(null, { headers: createCorsHeaders(origin, config, methods) });
    }
    return null;
}

/**
 * OAuth Error Class
 */
export class OAuthError extends Error {
    constructor(
        public code: string,
        message: string,
        public statusCode: number = 400
    ) {
        super(message);
        this.name = "OAuthError";
    }

    toResponse(headers: Record<string, string>): Response {
        return new Response(
            JSON.stringify({
                error: this.code,
                error_description: this.message,
            }),
            { status: this.statusCode, headers }
        );
    }
}

// ============================================================================
// OAuth Token Detection Helpers
// ============================================================================

/**
 * Default OAuth issuer pattern
 * Used to identify OAuth tokens by checking if issuer URL contains this pattern
 */
export const DEFAULT_OAUTH_ISSUER_PATTERN = "/oauth";

/**
 * Check if an identity is from an OAuth token
 * @param identity - User identity from ctx.auth.getUserIdentity()
 * @param issuerPattern - Pattern to match in issuer URL (default: "/oauth")
 * @returns true if the identity is from an OAuth token
 */
export function isOAuthToken(
    identity: { issuer?: string; subject?: string } | null | undefined,
    issuerPattern: string = DEFAULT_OAUTH_ISSUER_PATTERN
): boolean {
    return !!(identity?.issuer?.includes(issuerPattern) && identity?.subject);
}

/**
 * Extract client ID from an OAuth token identity
 * @param identity - User identity from ctx.auth.getUserIdentity()
 * @returns Client ID if present, undefined otherwise
 */
export function getOAuthClientId(
    identity: { cid?: string } | null | undefined
): string | undefined {
    return identity?.cid;
}
