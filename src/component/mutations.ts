import { v } from "convex/values";
import { mutation, internalMutation } from "./_generated/server.js";
import { generateCode } from "../lib/oauth.js";
import { OAUTH_CONSTANTS } from "./constants.js";
import { hashToken, isHashedToken } from "./token_security.js";

// --------------------------------------------------------------------------
// Helper Functions
// --------------------------------------------------------------------------

/**
 * Check if a URI is a loopback address (localhost, 127.0.0.1, ::1)
 * RFC 8252 Section 7.3: Loopback redirect URIs with variable ports
 */
export function isLoopbackRedirectUri(uri: string): boolean {
  try {
    const parsed = new URL(uri);
    return (
      parsed.hostname === "127.0.0.1" ||
      parsed.hostname === "::1" ||
      parsed.hostname === "localhost"
    );
  } catch {
    return false;
  }
}

/**
 * Match redirect URI with registered URIs
 * RFC 6749 Section 3.1.2.3: Exact string matching required
 * RFC 8252 Section 7.3: Exception for loopback URIs (variable ports allowed)
 */
export function matchRedirectUri(requested: string, registered: string[]): boolean {
  // 厳密一致チェック
  if (registered.includes(requested)) {
    return true;
  }

  // localhost/127.0.0.1の可変ポート例外（RFC 8252 Section 7.3）
  if (isLoopbackRedirectUri(requested)) {
    try {
      const reqUrl = new URL(requested);
      for (const regUri of registered) {
        if (isLoopbackRedirectUri(regUri)) {
          const regUrl = new URL(regUri);
          // ホストとパスが一致すればポート違いを許容
          if (
            reqUrl.hostname === regUrl.hostname &&
            reqUrl.pathname === regUrl.pathname
          ) {
            return true;
          }
        }
      }
    } catch {
      return false;
    }
  }

  return false;
}

// --------------------------------------------------------------------------
// Authorization Code Flow
// --------------------------------------------------------------------------

/**
 * Issue Authorization Code
 * RFC 7636: PKCE validation
 * RFC 6749 Section 3.1.2.3: Redirect URI validation
 */
export const issueAuthorizationCode = mutation({
    args: {
        clientId: v.string(),
        userId: v.string(), // Convex users table Id (string, passed from app)
        scopes: v.array(v.string()),
        redirectUri: v.string(),
        codeChallenge: v.string(),
        codeChallengeMethod: v.string(),
        nonce: v.optional(v.string()),
    },
    handler: async (ctx, args) => {
        // 1. PKCE検証（RFC 7636）
        if (!args.codeChallenge || args.codeChallenge.trim() === "") {
            throw new Error("code_challenge required");
        }
        if (args.codeChallengeMethod !== "S256") {
            throw new Error("plain code_challenge_method is not supported, use S256");
        }

        // 2. クライアント取得
        const client = await ctx.db
            .query("oauthClients")
            .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
            .unique();

        if (!client) {
            throw new Error("invalid_client");
        }

        // 3. リダイレクトURI検証（RFC 6749 + RFC 8252）
        if (!matchRedirectUri(args.redirectUri, client.redirectUris)) {
            throw new Error("redirect_uri_mismatch");
        }

        // 4. スコープ検証
        const invalidScopes = args.scopes.filter(
            (scope) => !client.allowedScopes.includes(scope)
        );
        if (invalidScopes.length > 0) {
            throw new Error(`invalid_scope: ${invalidScopes.join(", ")}`);
        }

        // 5. Generate Code
        const code = generateCode(OAUTH_CONSTANTS.AUTH_CODE_LENGTH);

        // 6. Save Code (hashed for security)
        await ctx.db.insert("oauthCodes", {
            code: await hashToken(code),
            clientId: args.clientId,
            userId: args.userId,
            scopes: args.scopes,
            redirectUri: args.redirectUri,
            codeChallenge: args.codeChallenge,
            codeChallengeMethod: args.codeChallengeMethod,
            nonce: args.nonce,
            expiresAt: Date.now() + OAUTH_CONSTANTS.CODE_EXPIRY_MS,
        });

        return code;
    },
});

/**
 * Validate and Consume Authorization Code
 * Returns code data if valid, throws otherwise.
 * Marks the code as used (not deleted) to detect replay attacks.
 * RFC Line 1136: SHOULD revoke all tokens if code is reused.
 * RFC Section 10.2: OAuth 2.1 - redirect_uri is OPTIONAL
 */
export const consumeAuthCode = mutation({
    args: {
        code: v.string(),
        clientId: v.string(),
        redirectUri: v.optional(v.string()), // OAuth 2.1: optional
        codeVerifier: v.string(),
    },
    handler: async (ctx, args) => {
        // 1. Find Code (by hash)
        const codeHash = await hashToken(args.code);
        let authCode = await ctx.db
            .query("oauthCodes")
            .withIndex("by_code", (q) => q.eq("code", codeHash))
            .unique();

        // Backward compatibility: try plaintext lookup if hash lookup fails
        if (!authCode && !isHashedToken(args.code)) {
            authCode = await ctx.db
                .query("oauthCodes")
                .withIndex("by_code", (q) => q.eq("code", args.code))
                .unique();
        }

        if (!authCode) {
            throw new Error("invalid_grant");
        }

        // RFC Line 1136: Detect authorization code reuse (replay attack)
        if (authCode.usedAt !== undefined) {
            // Code was already used - this is a replay attack
            // Revoke all tokens issued with this code
            const tokensToRevoke = await ctx.db
                .query("oauthTokens")
                .withIndex("by_authorization_code", (q) => q.eq("authorizationCode", codeHash))
                .collect();

            for (const token of tokensToRevoke) {
                await ctx.db.delete(token._id);
            }

            // Delete the code
            await ctx.db.delete(authCode._id);

            // Return error status (cannot throw because it would rollback token deletion)
            return {
                error: "authorization_code_reuse_detected",
                revokedTokens: tokensToRevoke.length,
            } as any;
        }

        // 2. Validation
        if (authCode.clientId !== args.clientId) {
            throw new Error("invalid_client");
        }

        if (authCode.expiresAt < Date.now()) {
            await ctx.db.delete(authCode._id);
            throw new Error("invalid_grant");
        }

        // redirect_uri validation: 発行時に設定されている場合は必須
        // RFC 6749 Section 4.1.3: redirect_uri REQUIRED if included in authorization request
        if (authCode.redirectUri) {
            if (!args.redirectUri) {
                throw new Error("redirect_uri_required");
            }
            if (authCode.redirectUri !== args.redirectUri) {
                throw new Error("redirect_uri_mismatch");
            }
        }

        // PKCE検証（エラーメッセージ改善）
        if (authCode.codeChallengeMethod === "S256") {
            const encoder = new TextEncoder();
            const data = encoder.encode(args.codeVerifier);
            const hashBuffer = await crypto.subtle.digest("SHA-256", data);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashBase64 = btoa(String.fromCharCode(...hashArray))
                .replace(/\+/g, "-")
                .replace(/\//g, "_")
                .replace(/=+$/, "");

            if (hashBase64 !== authCode.codeChallenge) {
                throw new Error("invalid_code_verifier");
            }
        } else if (authCode.codeChallengeMethod === "plain") {
            if (args.codeVerifier !== authCode.codeChallenge) {
                throw new Error("invalid_code_verifier");
            }
        } else {
            throw new Error("unsupported_code_challenge_method");
        }

        // 3. Mark Code as Used (RFC Line 1136: detect replay)
        await ctx.db.patch(authCode._id, { usedAt: Date.now() });

        return {
            userId: authCode.userId,
            scopes: authCode.scopes,
            codeChallenge: authCode.codeChallenge,
            codeChallengeMethod: authCode.codeChallengeMethod,
            redirectUri: authCode.redirectUri,
            nonce: authCode.nonce,
            codeHash, // Return code hash to link tokens
        };
    },
});

/**
 * Save Tokens
 *
 * Note: Tokens are stored as SHA-256 hashes for security.
 * The original token value should be returned to the client, not stored.
 */
export const saveTokens = mutation({
    args: {
        accessToken: v.string(),
        refreshToken: v.optional(v.string()),
        clientId: v.string(),
        userId: v.string(),
        scopes: v.array(v.string()),
        expiresAt: v.number(),
        refreshTokenExpiresAt: v.optional(v.number()),
        authorizationCode: v.optional(v.string()), // Hashed code for replay detection (RFC Line 1136)
    },
    handler: async (ctx, args) => {
        // Hash tokens before storing for security
        // The original tokens are returned to the client, hashes are stored
        await ctx.db.insert("oauthTokens", {
            ...args,
            accessToken: await hashToken(args.accessToken),
            refreshToken: args.refreshToken
                ? await hashToken(args.refreshToken)
                : undefined,
        });
    },
});

/**
 * Rotate Refresh Token (Delete old, Insert new)
 * RFC 4.3.3: New refresh token MUST have identical scope as the old one
 *
 * Note: Tokens are stored as SHA-256 hashes for security.
 */
export const rotateRefreshToken = mutation({
    args: {
        oldRefreshToken: v.string(),
        // New Token Data
        accessToken: v.string(),
        refreshToken: v.optional(v.string()),
        clientId: v.string(),
        userId: v.string(),
        scopes: v.array(v.string()),
        expiresAt: v.number(),
        refreshTokenExpiresAt: v.optional(v.number()),
    },
    handler: async (ctx, args) => {
        // Hash the old refresh token for lookup
        const oldRefreshTokenHash = await hashToken(args.oldRefreshToken);

        // 1. Verify Old Token Exists (lookup by hash)
        let oldToken = await ctx.db
            .query("oauthTokens")
            .withIndex("by_refresh_token", (q) => q.eq("refreshToken", oldRefreshTokenHash))
            .unique();

        // Backward compatibility: try plaintext lookup if hash lookup fails
        if (!oldToken && !isHashedToken(args.oldRefreshToken)) {
            oldToken = await ctx.db
                .query("oauthTokens")
                .withIndex("by_refresh_token", (q) => q.eq("refreshToken", args.oldRefreshToken))
                .unique();
        }

        if (!oldToken) {
            throw new Error("invalid_grant");
        }

        // 2. Validate Client/User consistency
        if (oldToken.clientId !== args.clientId || oldToken.userId !== args.userId) {
            throw new Error("invalid_grant");
        }

        // 3. RFC 4.3.3: 新RTのスコープは元RTと完全一致が必須
        // スコープの完全一致を検証（エスカレーションも縮小も不可）
        const scopesMatch =
            args.scopes.length === oldToken.scopes.length &&
            args.scopes.every((scope) => oldToken.scopes.includes(scope)) &&
            oldToken.scopes.every((scope) => args.scopes.includes(scope));

        if (!scopesMatch) {
            throw new Error(
                "scope_change_not_allowed: Refresh token scope must remain identical"
            );
        }

        // 4. クライアントの許可スコープ検証
        const client = await ctx.db
            .query("oauthClients")
            .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
            .unique();

        if (!client) {
            throw new Error("invalid_client");
        }

        const invalidScopes = args.scopes.filter(
            (scope) => !client.allowedScopes.includes(scope)
        );
        if (invalidScopes.length > 0) {
            throw new Error(`invalid_scope: ${invalidScopes.join(", ")}`);
        }

        // 5. Delete Old Token
        await ctx.db.delete(oldToken._id);

        // 6. Insert New Token (with hashed values)
        await ctx.db.insert("oauthTokens", {
            accessToken: await hashToken(args.accessToken),
            refreshToken: args.refreshToken ? await hashToken(args.refreshToken) : undefined,
            clientId: args.clientId,
            userId: args.userId,
            scopes: args.scopes,
            expiresAt: args.expiresAt,
            refreshTokenExpiresAt: args.refreshTokenExpiresAt,
        });
    },
});

/**
 * Delete Client
 */
export const deleteClient = mutation({
    args: {
        clientId: v.string(),
    },
    handler: async (ctx, args) => {
        const client = await ctx.db
            .query("oauthClients")
            .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
            .unique();

        if (!client) {
            throw new Error("Client not found");
        }

        await ctx.db.delete(client._id);
    },
});

/**
 * Clean up expired codes/tokens (utility)
 * RFC Line 1136: Also cleanup used codes after retention period
 */
export const cleanupExpired = internalMutation({
    args: {},
    handler: async (ctx) => {
        const now = Date.now();

        // Cleanup expired codes (both unused and used codes past retention period)
        const expiredCodes = await ctx.db
            .query("oauthCodes")
            .filter(q => q.lt(q.field("expiresAt"), now))
            .take(100);

        for (const code of expiredCodes) {
            await ctx.db.delete(code._id);
        }

        // Cleanup expired tokens
        const expiredTokens = await ctx.db
            .query("oauthTokens")
            .filter(q => q.lt(q.field("expiresAt"), now))
            .take(100);

        for (const token of expiredTokens) {
            await ctx.db.delete(token._id);
        }

        return {
            deletedCodes: expiredCodes.length,
            deletedTokens: expiredTokens.length,
        };
    }
});

// --------------------------------------------------------------------------
// Authorization Management
// --------------------------------------------------------------------------

/**
 * Create or update authorization (upsert)
 * Called when user grants consent
 */
export const upsertAuthorization = mutation({
    args: {
        userId: v.string(),
        clientId: v.string(),
        scopes: v.array(v.string()),
    },
    handler: async (ctx, args) => {
        const existing = await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user_client", (q) =>
                q.eq("userId", args.userId).eq("clientId", args.clientId)
            )
            .unique();

        const now = Date.now();

        if (existing) {
            // Update: merge scopes, update lastUsedAt
            const mergedScopes = [...new Set([...existing.scopes, ...args.scopes])];
            await ctx.db.patch(existing._id, {
                scopes: mergedScopes,
                lastUsedAt: now,
            });
            return existing._id;
        } else {
            // Create new authorization
            return await ctx.db.insert("oauthAuthorizations", {
                userId: args.userId,
                clientId: args.clientId,
                scopes: args.scopes,
                authorizedAt: now,
                lastUsedAt: now,
            });
        }
    },
});

/**
 * Update lastUsedAt when tokens are issued
 */
export const updateAuthorizationLastUsed = mutation({
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

        if (auth) {
            await ctx.db.patch(auth._id, { lastUsedAt: Date.now() });
        }
    },
});

/**
 * Revoke authorization and delete all associated tokens
 */
export const revokeAuthorization = mutation({
    args: {
        userId: v.string(),
        clientId: v.string(),
    },
    handler: async (ctx, args) => {
        // 1. Delete authorization record
        const auth = await ctx.db
            .query("oauthAuthorizations")
            .withIndex("by_user_client", (q) =>
                q.eq("userId", args.userId).eq("clientId", args.clientId)
            )
            .unique();

        if (auth) {
            await ctx.db.delete(auth._id);
        }

        // 2. Delete all tokens for this user-client pair
        const tokens = await ctx.db
            .query("oauthTokens")
            .withIndex("by_user", (q) => q.eq("userId", args.userId))
            .collect();

        const toDelete = tokens.filter(t => t.clientId === args.clientId);
        for (const token of toDelete) {
            await ctx.db.delete(token._id);
        }

        return {
            authorizationDeleted: !!auth,
            tokensDeleted: toDelete.length,
        };
    },
});
