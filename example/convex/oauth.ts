import { mutation, query } from "./_generated/server";
import { v } from "convex/values";
import { components } from "./_generated/api";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { getAuthUserId } from "./auth";

/**
 * OAuth Provider proxy functions
 *
 * These wrap the OAuth provider component SDK for use from the frontend.
 */

function getOAuthProvider() {
  const prefix = process.env.OAUTH_PREFIX ?? "/oauth";

  return new OAuthProvider(components.oauthProvider, {
    // Use Convex Auth keys by default, fallback to OAuth-specific keys
    privateKey: process.env.JWT_PRIVATE_KEY ?? process.env.OAUTH_PRIVATE_KEY!,
    jwks: (process.env.JWKS ?? process.env.OAUTH_JWKS)!,
    siteUrl: process.env.SITE_URL!,
    convexSiteUrl: process.env.CONVEX_SITE_URL,
    prefix,
    allowedOrigins: process.env.ALLOWED_ORIGINS,
    allowedScopes: ["openid", "profile", "email", "offline_access"],
  });
}

/**
 * Issue authorization code for the current user
 * Called after user authenticates and authorizes the OAuth client
 */
export const issueAuthorizationCode = mutation({
  args: {
    clientId: v.string(),
    redirectUri: v.string(),
    scopes: v.array(v.string()),
    codeChallenge: v.optional(v.string()),
    codeChallengeMethod: v.optional(v.string()),
    nonce: v.optional(v.string()),
    state: v.optional(v.string()),
  },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) {
      throw new Error("Not authenticated");
    }

    const oauth = getOAuthProvider();
    const client = await oauth.getClient(ctx, args.clientId);
    if (!client) {
      throw new Error("Invalid client");
    }
    if (!client.redirectUris.includes(args.redirectUri)) {
      throw new Error("Invalid redirect URI");
    }
    const invalidScopes = args.scopes.filter((scope) => !client.allowedScopes.includes(scope));
    if (invalidScopes.length > 0) {
      throw new Error("Invalid scope");
    }
    if (client.type === "public" && !args.codeChallenge) {
      throw new Error("code_challenge required for public clients");
    }
    if (args.codeChallengeMethod && args.codeChallengeMethod !== "S256" && args.codeChallengeMethod !== "plain") {
      throw new Error("Unsupported code_challenge_method");
    }

    return await oauth.issueAuthorizationCode(ctx, {
      clientId: args.clientId,
      userId: userId,
      scopes: args.scopes,
      redirectUri: args.redirectUri,
      codeChallenge: args.codeChallenge ?? undefined,
      codeChallengeMethod: args.codeChallengeMethod ?? undefined,
      nonce: args.nonce,
    });
  },
});

/**
 * Get OAuth client details (for authorization screen)
 */
export const getClient = query({
  args: { clientId: v.string() },
  handler: async (ctx, args) => {
    const oauth = getOAuthProvider();
    return await oauth.getClient(ctx, args.clientId);
  },
});

/**
 * List tokens issued to the current user
 */
export const listMyTokens = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) {
      return [];
    }

    const oauth = getOAuthProvider();
    return await oauth.getTokensByUser(ctx, userId);
  },
});

/**
 * List authorized apps for the current user
 */
export const listMyAuthorizations = query({
  args: {},
  handler: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) {
      return [];
    }

    const oauth = getOAuthProvider();
    return await oauth.listUserAuthorizations(ctx, userId);
  },
});

/**
 * List all registered OAuth clients (for admin)
 */
export const listClients = query({
  args: {},
  handler: async (ctx) => {
    return await ctx.runQuery(components.oauthProvider.queries.listClients, {});
  },
});

/**
 * Revoke authorization for a specific client
 */
export const revokeAuthorization = mutation({
  args: { clientId: v.string() },
  handler: async (ctx, args) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) {
      throw new Error("Not authenticated");
    }

    const oauth = getOAuthProvider();
    return await oauth.revokeAuthorization(ctx, userId, args.clientId);
  },
});
