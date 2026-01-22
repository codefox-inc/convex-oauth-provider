import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export default defineSchema({
    /**
     * OAuth Clients
     * Registered applications that can request authorization
     */
    oauthClients: defineTable({
        name: v.string(),
        description: v.optional(v.string()),
        logoUrl: v.optional(v.string()),
        website: v.optional(v.string()),
        tosUrl: v.optional(v.string()),
        policyUrl: v.optional(v.string()),

        // Client Credentials
        clientId: v.string(), // Public ID (UUID v4)
        clientSecret: v.optional(v.string()), // Hashed Secret (for confidential clients)
        type: v.union(v.literal("confidential"), v.literal("public")),

        redirectUris: v.array(v.string()), // Must be exact match
        allowedScopes: v.array(v.string()), // e.g. ["openid", "profile", "email"]

        isInternal: v.optional(v.boolean()), // Internal tool flag

        createdAt: v.number(),
    }).index("by_client_id", ["clientId"]),

    /**
     * OAuth Authorization Codes
     * Short-lived codes for authorization code flow
     */
    oauthCodes: defineTable({
        code: v.string(),
        clientId: v.string(),
        userId: v.string(), // Convex users table Id (string, not v.id since component doesn't know about users table)
        scopes: v.array(v.string()),
        redirectUri: v.string(),

        // PKCE
        codeChallenge: v.string(),
        codeChallengeMethod: v.string(), // "S256" or "plain"
        nonce: v.optional(v.string()), // OIDC Nonce

        expiresAt: v.number(), // Usually 10 minutes
        usedAt: v.optional(v.number()), // RFC Line 1136: Track code usage for replay detection
    }).index("by_code", ["code"]),

    /**
     * OAuth Tokens
     * Access and Refresh tokens
     */
    oauthTokens: defineTable({
        accessToken: v.string(),
        refreshToken: v.optional(v.string()),

        clientId: v.string(),
        userId: v.string(), // Convex users table Id (string)
        scopes: v.array(v.string()),

        expiresAt: v.number(), // Access Token Expiry
        refreshTokenExpiresAt: v.optional(v.number()), // Refresh Token Expiry

        // RFC Line 1136: Track which authorization code issued this token for replay detection
        authorizationCode: v.optional(v.string()), // Hashed authorization code
    })
        .index("by_access_token", ["accessToken"])
        .index("by_refresh_token", ["refreshToken"])
        .index("by_user", ["userId"])
        .index("by_authorization_code", ["authorizationCode"]),

    /**
     * OAuth Authorizations
     * User consent records - persists beyond token expiry
     */
    oauthAuthorizations: defineTable({
        userId: v.string(), // Convex users table Id (string)
        clientId: v.string(),

        // Authorized scopes
        scopes: v.array(v.string()),

        // When the user first authorized this client
        authorizedAt: v.number(),

        // Last time a token was issued for this authorization
        lastUsedAt: v.optional(v.number()),
    })
        .index("by_user", ["userId"])
        .index("by_user_client", ["userId", "clientId"]),
});
