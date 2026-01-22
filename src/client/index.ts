import {
    openIdConfigurationHandler,
    jwksHandler,
    tokenHandler,
    userInfoHandler,
    registerHandler,
    authorizeHandler,
    oauthProtectedResourceHandler,
} from "../component/handlers.js";
import type { OAuthComponentAPI } from "../component/handlers.js";
import type { OAuthConfig, UserProfile } from "../lib/oauth.js";
import type { RunQueryCtx, RunMutationCtx, RunActionCtx } from "../lib/convex-types.js";

// Re-export types and utilities
export type { OAuthConfig, UserProfile } from "../lib/oauth.js";
export {
    OAuthError,
    verifyAccessToken,
    isOAuthToken,
    getOAuthClientId,
    DEFAULT_OAUTH_ISSUER_PATTERN,
} from "../lib/oauth.js";
export { OAUTH_CONSTANTS, OAUTH_ERROR_CODES } from "../component/constants.js";

// Auth helper for getCurrentUser pattern
export { createAuthHelper } from "./auth-helper.js";
export type { AuthHelper, AuthHelperConfig } from "./auth-helper.js";

// Route registration helper
export { registerOAuthRoutes } from "./routes.js";
export type { RegisterOAuthRoutesOptions } from "./routes.js";

// Auth config generator
export { generateAuthConfig, createAuthConfig } from "./auth-config.js";
export type { AuthConfig, AuthProvider, GenerateAuthConfigOptions } from "./auth-config.js";

/**
 * OAuth Provider Client Configuration
 */
export type OAuthProviderConfig = OAuthConfig;

/**
 * OAuth Provider SDK
 *
 * Usage:
 * ```typescript
 * import { OAuthProvider } from "@codefox-inc/oauth-provider";
 * import { components } from "./_generated/api";
 *
 * const oauthProvider = new OAuthProvider(components.oauthProvider, {
 *   privateKey: process.env.OAUTH_PRIVATE_KEY!,
 *   publicKey: process.env.OAUTH_PUBLIC_KEY!,
 *   siteUrl: process.env.SITE_URL!,
 * });
 *
 * // In http.ts
 * http.route({
 *   path: "/oauth/.well-known/openid-configuration",
 *   method: "GET",
 *   handler: httpAction((ctx, req) => oauthProvider.handlers.openIdConfiguration(ctx, req)),
 * });
 * ```
 */
export class OAuthProvider {
    private config: OAuthProviderConfig;
    private api: OAuthComponentAPI;
     
    private component: any;

    constructor(
         
        component: any,
        config: OAuthProviderConfig
    ) {
        this.config = config;
        this.component = component;
        this.api = this.createAPI(component);
    }

    getConfig(): OAuthProviderConfig {
        return this.config;
    }

     
    private createAPI(component: any): OAuthComponentAPI {
        return {
            queries: {
                getClient: (ctx, args) => ctx.runQuery(component.queries.getClient, args),
                getRefreshToken: (ctx, args) => ctx.runQuery(component.queries.getRefreshToken, args),
                getTokensByUser: (ctx, args) => ctx.runQuery(component.queries.getTokensByUser, args),
            },
            mutations: {
                issueAuthorizationCode: (ctx, args) =>
                    ctx.runMutation(component.mutations.issueAuthorizationCode, args),
                consumeAuthCode: (ctx, args) =>
                    ctx.runMutation(component.mutations.consumeAuthCode, args),
                saveTokens: (ctx, args) =>
                    ctx.runMutation(component.mutations.saveTokens, args),
                rotateRefreshToken: (ctx, args) =>
                    ctx.runMutation(component.mutations.rotateRefreshToken, args),
                upsertAuthorization: (ctx, args) =>
                    ctx.runMutation(component.mutations.upsertAuthorization, args),
                updateAuthorizationLastUsed: (ctx, args) =>
                    ctx.runMutation(component.mutations.updateAuthorizationLastUsed, args),
            },
            clientManagement: {
                registerClient: (ctx, args) =>
                    ctx.runMutation(component.clientManagement.registerClient, args),
                verifyClientSecret: (ctx, args) =>
                    ctx.runMutation(component.clientManagement.verifyClientSecret, args),
            },
        };
    }

    /**
     * HTTP Handlers for mounting in http.ts
     *
     * Note: ctx expects Convex ActionCtx (HTTP Action context).
     * RunActionCtx is used as the base type for compatibility.
     */
    get handlers() {
        return {
            /**
             * OpenID Connect Discovery
             * Mount at: /oauth/.well-known/openid-configuration
             */
            openIdConfiguration: (ctx: RunActionCtx, request: Request) =>
                openIdConfigurationHandler(ctx as Parameters<typeof openIdConfigurationHandler>[0], request, this.config),

            /**
             * Authorization Endpoint
             * Mount at: /oauth/authorize
             */
            authorize: (ctx: RunActionCtx, request: Request) =>
                authorizeHandler(ctx as Parameters<typeof authorizeHandler>[0], request, this.config, this.api),

            /**
             * JWKS Endpoint
             * Mount at: /oauth/.well-known/jwks.json
             */
            jwks: (ctx: RunActionCtx, request: Request) =>
                jwksHandler(ctx as Parameters<typeof jwksHandler>[0], request, this.config),

            /**
             * Token Endpoint
             * Mount at: /oauth/token
             */
            token: (ctx: RunActionCtx, request: Request) =>
                tokenHandler(ctx as Parameters<typeof tokenHandler>[0], request, this.config, this.api),

            /**
             * UserInfo Endpoint
             * Mount at: /oauth/userinfo
             * Requires getUserProfile callback
             */
            userInfo: (ctx: RunActionCtx, request: Request, getUserProfile: (userId: string) => Promise<UserProfile | null>) =>
                userInfoHandler(ctx as Parameters<typeof userInfoHandler>[0], request, this.config, getUserProfile),

            /**
             * Dynamic Client Registration
             * Mount at: /oauth/register
             */
            register: (ctx: RunActionCtx, request: Request) =>
                registerHandler(ctx as Parameters<typeof registerHandler>[0], request, this.config, this.api),

            /**
             * Protected Resource Metadata
             * Mount at: /.well-known/oauth-protected-resource
             */
            protectedResource: (ctx: RunActionCtx, request: Request) =>
                oauthProtectedResourceHandler(ctx as Parameters<typeof oauthProtectedResourceHandler>[0], request, this.config),
        };
    }

    /**
     * Issue Authorization Code
     * Called from consent approval mutation
     * Also creates/updates authorization record automatically
     */
    async issueAuthorizationCode(ctx: RunMutationCtx, args: {
        userId: string;
        clientId: string;
        scopes: string[];
        redirectUri: string;
        codeChallenge?: string;
        codeChallengeMethod?: string;
        nonce?: string;
    }): Promise<string> {
        if (!args.codeChallenge) {
            throw new Error("codeChallenge required");
        }
        const codeChallengeMethod = args.codeChallengeMethod ?? "S256";
        if (codeChallengeMethod !== "S256") {
            throw new Error("codeChallengeMethod must be S256");
        }

        // 1. Create/update authorization record (user consented)
        await this.api.mutations.upsertAuthorization(ctx, {
            userId: args.userId,
            clientId: args.clientId,
            scopes: args.scopes,
        });

        // 2. Issue the authorization code
        return this.api.mutations.issueAuthorizationCode(ctx, {
            ...args,
            codeChallenge: args.codeChallenge,
            codeChallengeMethod,
        });
    }

    /**
     * Get OAuth Client
     */
    async getClient(ctx: RunQueryCtx, clientId: string) {
        return this.api.queries.getClient(ctx, { clientId });
    }

    /**
     * Register OAuth Client (for admin use)
     */
    async registerClient(ctx: RunMutationCtx, args: {
        name: string;
        redirectUris: string[];
        scopes: string[];
        type: "confidential" | "public";
        website?: string;
        logoUrl?: string;
        tosUrl?: string;
        policyUrl?: string;
    }) {
        return this.api.clientManagement.registerClient(ctx, args);
    }

    /**
     * Get user's active tokens
     */
    async getTokensByUser(ctx: RunQueryCtx, userId: string) {
        return this.api.queries.getTokensByUser(ctx, { userId });
    }

    // -------------------------------------------------------------------------
    // Authorization Management
    // -------------------------------------------------------------------------

    /**
     * Get authorization for a specific user-client pair
     * Returns null if user has not authorized this client
     */
    async getAuthorization(ctx: RunQueryCtx, userId: string, clientId: string) {
        return ctx.runQuery(this.component.queries.getAuthorization, { userId, clientId });
    }

    /**
     * List all authorized apps for a user
     * Returns client info along with authorization details
     */
    async listUserAuthorizations(ctx: RunQueryCtx, userId: string) {
        return ctx.runQuery(this.component.queries.listUserAuthorizations, { userId });
    }

    /**
     * Create or update authorization when user grants consent
     * Call this when user approves OAuth consent
     */
    async upsertAuthorization(ctx: RunMutationCtx, args: {
        userId: string;
        clientId: string;
        scopes: string[];
    }) {
        return ctx.runMutation(this.component.mutations.upsertAuthorization, args);
    }

    /**
     * Revoke authorization and delete all associated tokens
     * Call this when user wants to disconnect an app
     */
    async revokeAuthorization(ctx: RunMutationCtx, userId: string, clientId: string) {
        return ctx.runMutation(this.component.mutations.revokeAuthorization, { userId, clientId });
    }

    /**
     * Check if user has already authorized this client with sufficient scopes
     * Useful for "skip consent" flow
     */
    async hasAuthorization(ctx: RunQueryCtx, userId: string, clientId: string, requiredScopes: string[]): Promise<boolean> {
        const auth = await this.getAuthorization(ctx, userId, clientId);
        if (!auth) return false;

        // Check if all required scopes are authorized
        return requiredScopes.every(scope => auth.scopes.includes(scope));
    }

    /**
     * Check if authorization exists (for revocation check)
     * Use this with createAuthHelper's checkAuthorization option
     */
    async checkAuthorizationValid(ctx: RunQueryCtx, userId: string, clientId?: string): Promise<boolean> {
        if (clientId) {
            // Check specific client authorization
            return ctx.runQuery(this.component.queries.hasAuthorization, { userId, clientId });
        } else {
            // Check if user has any authorization
            return ctx.runQuery(this.component.queries.hasAnyAuthorization, { userId });
        }
    }

    /**
     * Create a checkAuthorization function for use with createAuthHelper
     * This ensures revoked authorizations are rejected
     *
     * @example
     * ```typescript
     * const oauthProvider = new OAuthProvider(components.oauthProvider, config);
     * const authHelper = createAuthHelper({
     *   providers: ["anonymous"],
     *   checkAuthorization: oauthProvider.createAuthorizationChecker(),
     * });
     * ```
     */
    createAuthorizationChecker() {
        return async (ctx: RunQueryCtx, userId: string, clientId?: string): Promise<boolean> => {
            return this.checkAuthorizationValid(ctx, userId, clientId);
        };
    }
}
