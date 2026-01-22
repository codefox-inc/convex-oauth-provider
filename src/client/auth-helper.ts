/**
 * Auth Helper for handling both Convex Auth and OAuth tokens
 *
 * This helper provides a unified way to get the current user
 * regardless of whether they authenticated via Convex Auth (session)
 * or OAuth token (MCP clients).
 */

import {
    isOAuthToken as checkIsOAuthToken,
    getOAuthClientId,
    DEFAULT_OAUTH_ISSUER_PATTERN,
} from "../lib/oauth.js";

/**
 * Context types (simplified for compatibility)
 */
 
type QueryCtx = any;
 
type MutationCtx = any;

/**
 * Configuration for the auth helper
 */
export interface AuthHelperConfig {
    /**
     * Convex Auth provider names to check for subject ID lookup
     * @example ["anonymous", "password", "google"]
     */
    providers?: string[];

    /**
     * Custom function to get auth user ID from Convex Auth
     * If not provided, you must pass it when calling methods
     */
    getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>;

    /**
     * Function to check if OAuth authorization is still valid
     * Called for OAuth token requests to verify the authorization wasn't revoked
     * @param ctx - Query/Mutation context
     * @param userId - User ID from JWT
     * @param clientId - Client ID from JWT (may be undefined if not in JWT)
     * @returns true if authorization is valid, false if revoked
     */
    checkAuthorization?: (ctx: QueryCtx | MutationCtx, userId: string, clientId?: string) => Promise<boolean>;

    /**
     * OAuth issuer URL pattern to identify OAuth tokens
     * If the token's issuer contains this string, authorization check is enforced
     * @example "/oauth"
     */
    oauthIssuerPattern?: string;
}

/**
 * Auth Helper instance
 */
export interface AuthHelper {
    /**
     * Get the current user ID from either Convex Auth or OAuth token
     * Returns null if not authenticated
     */
    getCurrentUserId: (
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ) => Promise<string | null>;

    /**
     * Get the current user document from the database
     * Returns null if not authenticated or user not found
     */
    getCurrentUser: <T>(
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ) => Promise<T | null>;

    /**
     * Require authentication - throws if not authenticated
     */
    requireAuth: (
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ) => Promise<string>;
}

/**
 * Create an auth helper for handling both Convex Auth and OAuth tokens
 *
 * @example
 * ```typescript
 * import { createAuthHelper } from "@codefox-inc/oauth-provider";
 * import { getAuthUserId } from "./auth";
 *
 * const authHelper = createAuthHelper({
 *   providers: ["anonymous"],
 * });
 *
 * // In a query/mutation:
 * const userId = await authHelper.getCurrentUserId(ctx, getAuthUserId);
 * const user = await authHelper.getCurrentUser(ctx, getAuthUserId);
 * ```
 */
export function createAuthHelper(config: AuthHelperConfig = {}): AuthHelper {
    const {
        providers = ["anonymous"],
        getAuthUserId: defaultGetAuthUserId,
        checkAuthorization,
        oauthIssuerPattern = DEFAULT_OAUTH_ISSUER_PATTERN,
    } = config;

    async function getCurrentUserId(
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ): Promise<string | null> {
        const authFn = getAuthUserId ?? defaultGetAuthUserId;

        // First, check if this is an OAuth token by looking at identity issuer
        const identity = await ctx.auth.getUserIdentity();
        const isOAuth = checkIsOAuthToken(identity, oauthIssuerPattern);

        // If this is an OAuth token, skip Convex Auth and enforce authorization check
        if (isOAuth && identity?.subject) {
            const validId = ctx.db.normalizeId("users", identity.subject);
            if (validId) {
                // OAuth tokens MUST pass authorization check
                if (checkAuthorization) {
                    const clientId = getOAuthClientId(identity);
                    const isValid = await checkAuthorization(ctx, validId, clientId);
                    if (!isValid) {
                        // Authorization was revoked - reject access
                        return null;
                    }
                }
                return validId;
            }
            // OAuth token but invalid user ID
            return null;
        }

        // 1. Try Convex Auth (session-based, getAuthUserId)
        if (authFn) {
            const userIdOrSubject = await authFn(ctx);
            if (userIdOrSubject) {
                // Handle "userId|sessionId" format from some Convex Auth versions
                const idToLookup = userIdOrSubject.includes("|")
                    ? userIdOrSubject.split("|")[0]
                    : userIdOrSubject;

                // Try as Convex ID
                const validId = ctx.db.normalizeId("users", idToLookup);
                if (validId) {
                    return validId;
                }

                // Try as Subject ID via authAccounts
                for (const provider of providers) {
                     
                    const account = await (ctx.db as any)
                        .query("authAccounts")
                        .withIndex("providerAndAccountId", (q: { eq: (field: string, value: string) => { eq: (field: string, value: string) => unknown } }) =>
                            q.eq("provider", provider).eq("providerAccountId", idToLookup)
                        )
                        .unique();
                    if (account) {
                        return account.userId;
                    }
                }
            }
        }

        return null;
    }

    async function getCurrentUser<T>(
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ): Promise<T | null> {
        const userId = await getCurrentUserId(ctx, getAuthUserId);
        if (!userId) return null;
        return ctx.db.get(userId) as Promise<T | null>;
    }

    async function requireAuth(
        ctx: QueryCtx | MutationCtx,
        getAuthUserId?: (ctx: QueryCtx | MutationCtx) => Promise<string | null>
    ): Promise<string> {
        const userId = await getCurrentUserId(ctx, getAuthUserId);
        if (!userId) {
            throw new Error("Not authenticated");
        }
        return userId;
    }

    return {
        getCurrentUserId,
        getCurrentUser,
        requireAuth,
    };
}
