import { v } from "convex/values";
import { mutation } from "./_generated/server.js";
import * as bcrypt from "bcryptjs";
import { generateClientSecret } from "../lib/oauth.js";
import { OAUTH_CONSTANTS } from "./constants.js";

/**
 * OAuth Client Management Mutations
 *
 * Handles client registration, verification, and deletion.
 * Uses bcryptjs (pure JavaScript implementation) for secure client secret hashing.
 */

function isValidRedirectUri(uri: string): boolean {
    let parsed: URL;
    try {
        parsed = new URL(uri);
    } catch {
        return false;
    }

    if (parsed.hash) return false;

    const host = parsed.hostname.toLowerCase();
    const isLoopback =
        host === "localhost" ||
        host === "127.0.0.1" ||
        host === "::1";

    if (parsed.protocol === "https:") return true;
    if (parsed.protocol === "http:" && isLoopback) return true;

    return false;
}

/**
 * Register OAuth Client
 */
export const registerClient = mutation({
    args: {
        name: v.string(),
        redirectUris: v.array(v.string()),
        scopes: v.array(v.string()),
        type: v.union(v.literal("confidential"), v.literal("public")),
        // metadata
        description: v.optional(v.string()),
        website: v.optional(v.string()),
        logoUrl: v.optional(v.string()),
        tosUrl: v.optional(v.string()),
        policyUrl: v.optional(v.string()),
        isInternal: v.optional(v.boolean()),
    },
    handler: async (ctx, args) => {
        if (args.redirectUris.length === 0) {
            throw new Error("redirect_uris required");
        }
        const invalidRedirect = args.redirectUris.find((uri) => !isValidRedirectUri(uri));
        if (invalidRedirect) {
            throw new Error(`Invalid redirect_uri: ${invalidRedirect}`);
        }

        const clientId = crypto.randomUUID();

        // Generate secret only if confidential
        if (args.type === "confidential") {
            // Generate plain secret using CSPrng
            const clientSecret = generateClientSecret(OAUTH_CONSTANTS.CLIENT_SECRET_LENGTH);

            // Hash the secret
            const clientSecretHash = await bcrypt.hash(clientSecret, 10);

            // Store the HASH, return the PLAIN secret once
            await ctx.db.insert("oauthClients", {
                name: args.name,
                clientId,
                clientSecret: clientSecretHash, // Store Hash!
                type: args.type,
                redirectUris: args.redirectUris,
                allowedScopes: args.scopes,
                createdAt: Date.now(),
                description: args.description,
                website: args.website,
                logoUrl: args.logoUrl,
                tosUrl: args.tosUrl,
                policyUrl: args.policyUrl,
                isInternal: args.isInternal,
            });

            return {
                clientId,
                clientSecret, // Return Plain!
                clientIdIssuedAt: Math.floor(Date.now() / 1000),
            };
        }

        // Public client (no secret)
        await ctx.db.insert("oauthClients", {
            name: args.name,
            clientId,
            clientSecret: undefined,
            type: args.type,
            redirectUris: args.redirectUris,
            allowedScopes: args.scopes,
            createdAt: Date.now(),
            description: args.description,
            website: args.website,
            logoUrl: args.logoUrl,
            tosUrl: args.tosUrl,
            policyUrl: args.policyUrl,
            isInternal: args.isInternal,
        });

        return {
            clientId,
            clientIdIssuedAt: Math.floor(Date.now() / 1000),
        };
    },
});

/**
 * Verify Client Secret
 */
export const verifyClientSecret = mutation({
    args: {
        clientId: v.string(),
        clientSecret: v.string(),
    },
    handler: async (ctx, args) => {
        const client = await ctx.db
            .query("oauthClients")
            .withIndex("by_client_id", (q) => q.eq("clientId", args.clientId))
            .unique();

        if (!client || !client.clientSecret) {
            return false;
        }

        try {
            return await bcrypt.compare(args.clientSecret, client.clientSecret);
        } catch (e) {
            console.error("Client Secret Verification Failed:", e);
            return false;
        }
    },
});

/**
 * Delete OAuth Client
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

        // Delete all tokens for this client
        const tokens = await ctx.db
            .query("oauthTokens")
            .filter(q => q.eq(q.field("clientId"), args.clientId))
            .collect();

        for (const token of tokens) {
            await ctx.db.delete(token._id);
        }

        // Delete all codes for this client
        const codes = await ctx.db
            .query("oauthCodes")
            .filter(q => q.eq(q.field("clientId"), args.clientId))
            .collect();

        for (const code of codes) {
            await ctx.db.delete(code._id);
        }

        // Delete the client
        await ctx.db.delete(client._id);

        return { success: true };
    },
});
