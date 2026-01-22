import { v } from "convex/values";
import { query } from "./_generated/server";
import { hashToken, isHashedToken } from "./token_security";

/**
 * Get OAuth Client by clientId
 */
export const getClient = query({
    args: { clientId: v.string() },
    handler: async (ctx, args) => {
        return await ctx.db
            .query("oauthClients")
            .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
            .unique();
    },
});

/**
 * Get Refresh Token
 *
 * Note: Tokens are stored as SHA-256 hashes. This query hashes the input
 * before lookup, with backward compatibility for plaintext tokens.
 */
export const getRefreshToken = query({
    args: { refreshToken: v.string() },
    handler: async (ctx, args) => {
        // Hash the token for lookup
        const refreshTokenHash = await hashToken(args.refreshToken);

        // Try hash lookup first
        let token = await ctx.db
            .query("oauthTokens")
            .withIndex("by_refresh_token", (q) => q.eq("refreshToken", refreshTokenHash))
            .unique();

        // Backward compatibility: try plaintext lookup if hash lookup fails
        if (!token && !isHashedToken(args.refreshToken)) {
            token = await ctx.db
                .query("oauthTokens")
                .withIndex("by_refresh_token", (q) => q.eq("refreshToken", args.refreshToken))
                .unique();
        }

        return token;
    },
});

/**
 * List OAuth Clients (for admin)
 */
export const listClients = query({
    args: {},
    handler: async (ctx) => {
        const clients = await ctx.db.query("oauthClients").collect();
        // Don't return secrets
        return clients.map(client => ({
            ...client,
            clientSecret: undefined,
        }));
    },
});

/**
 * Get tokens by user ID
 */
export const getTokensByUser = query({
    args: { userId: v.string() },
    handler: async (ctx, args) => {
        return await ctx.db
            .query("oauthTokens")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .collect();
    },
});

// --------------------------------------------------------------------------
// Authorization Queries
// --------------------------------------------------------------------------

/**
 * Get authorization for a specific user-client pair
 */
export const getAuthorization = query({
    args: {
        userId: v.string(),
        clientId: v.string(),
    },
    handler: async (ctx, args) => {
        return await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user_client", (q) =>
                q.eq("userId", args.userId).eq("clientId", args.clientId)
            )
            .unique();
    },
});

/**
 * Check if authorization exists (for revocation check)
 * Returns true if authorization is valid, false if revoked or not found
 */
export const hasAuthorization = query({
    args: {
        userId: v.string(),
        clientId: v.string(),
    },
    handler: async (ctx, args) => {
        const auth = await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user_client", (q) =>
                q.eq("userId", args.userId).eq("clientId", args.clientId)
            )
            .unique();
        return auth !== null;
    },
});

/**
 * Check if user has any valid authorization (for OAuth token validation)
 * If user has no authorizations, they shouldn't be able to access via OAuth
 */
export const hasAnyAuthorization = query({
    args: {
        userId: v.string(),
    },
    handler: async (ctx, args) => {
        const auth = await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .first();
        return auth !== null;
    },
});

/**
 * List all authorizations for a user (with client info)
 */
export const listUserAuthorizations = query({
    args: { userId: v.string() },
    handler: async (ctx, args) => {
        const authorizations = await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .collect();

        // Enrich with client info
        const result = await Promise.all(
            authorizations.map(async (auth) => {
                const client = await ctx.db
                    .query("oauthClients")
                    .withIndex("by_client_id", (q) => q.eq("clientId", auth.clientId))
                    .unique();

                return {
                    ...auth,
                    clientName: client?.name ?? "Unknown App",
                    clientLogoUrl: client?.logoUrl,
                    clientWebsite: client?.website,
                };
            })
        );

        return result;
    },
});
