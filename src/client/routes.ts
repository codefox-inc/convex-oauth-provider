/**
 * OAuth Route Registration Helper
 *
 * Simplifies registering all OAuth endpoints in http.ts
 */

import type { OAuthProvider } from "./index.js";
import { normalizePrefix } from "../lib/oauth.js";
import type { UserProfile } from "../lib/oauth.js";
import type { RunActionCtx, RunQueryCtx } from "../lib/convex-types.js";
import type { Auth } from "convex/server";

/**
 * HTTP Router interface (compatible with Convex httpRouter)
 */
interface HttpRouter {
    route: (config: {
        path: string;
        method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS";
         
        handler: any;
    }) => void;
}

/**
 * HTTP Action creator function
 * Note: Actual Convex ActionCtx extends RunActionCtx with additional HTTP-specific properties
 */
type HttpActionCreator = (handler: (ctx: RunActionCtx & { auth: Auth }, request: Request) => Promise<Response>) => unknown;

/**
 * Options for registering OAuth routes
 */
export interface RegisterOAuthRoutesOptions {
    /**
     * URL prefix for OAuth endpoints
     * @default "/oauth"
     */
    prefix?: string;

    /**
     * Callback to get user profile for UserInfo endpoint
     * Receives ctx for DB access (e.g., ctx.runQuery)
     * If not provided, UserInfo endpoint returns only { sub: userId }
     */
    getUserProfile?: (ctx: RunQueryCtx, userId: string) => Promise<UserProfile | null>;

    /**
     * Custom authorize handler for authentication check before consent
     * If not provided, simply redirects to consent page
     *
     * @example
     * ```typescript
     * authorizeHandler: async (ctx, request, defaultRedirect) => {
     *   const identity = await ctx.auth.getUserIdentity();
     *   if (!identity) {
     *     const loginUrl = new URL(`${siteUrl}/login`);
     *     loginUrl.searchParams.set("returnTo", request.url);
     *     return Response.redirect(loginUrl.toString());
     *   }
     *   return defaultRedirect();
     * }
     * ```
     */
    authorizeHandler?: (
        ctx: RunActionCtx & { auth: Auth },
        request: Request,
        defaultAuthorize: () => Promise<Response>
    ) => Promise<Response>;

    /**
     * SITE_URL for authorize redirect
     */
    siteUrl?: string;

    /**
     * Also register routes without /oauth prefix for RFC 8414 compatibility
     * @default true
     */
    registerRootWellKnown?: boolean;
}

/**
 * Register all OAuth routes on an HTTP router
 *
 * @example
 * ```typescript
 * import { httpRouter } from "convex/server";
 * import { httpAction } from "./_generated/server";
 * import { OAuthProvider, registerOAuthRoutes } from "@codefox-inc/oauth-provider";
 *
 * const http = httpRouter();
 * const oauthProvider = new OAuthProvider(components.oauthProvider, config);
 *
 * registerOAuthRoutes(http, httpAction, oauthProvider, {
 *   siteUrl: process.env.SITE_URL,
 *   getUserProfile: async (userId) => ({ sub: userId, name: "User" }),
 * });
 *
 * export default http;
 * ```
 */
export function registerOAuthRoutes(
    http: HttpRouter,
    httpAction: HttpActionCreator,
    oauthProvider: OAuthProvider,
    options: RegisterOAuthRoutesOptions = {}
): void {
    const baseConfig = oauthProvider.getConfig?.();
    const prefix = normalizePrefix(options.prefix ?? baseConfig?.prefix);
    const {
        getUserProfile,
        authorizeHandler,
        siteUrl: _siteUrl = "http://localhost:5173",
        registerRootWellKnown = true,
    } = options;

    const handlers = oauthProvider.handlers;

    // Helper to register GET + OPTIONS for a path
    const registerGetEndpoint = (
        path: string,
        handler: (ctx: RunActionCtx, req: Request) => Promise<Response>
    ) => {
        http.route({
            path,
            method: "GET",
            handler: httpAction((ctx, req) => handler(ctx, req)),
        });
        http.route({
            path,
            method: "OPTIONS",
            handler: httpAction((ctx, req) => handler(ctx, req)),
        });
    };

    // Helper to register POST + OPTIONS for a path
    const registerPostEndpoint = (
        path: string,
        handler: (ctx: RunActionCtx, req: Request) => Promise<Response>
    ) => {
        http.route({
            path,
            method: "POST",
            handler: httpAction((ctx, req) => handler(ctx, req)),
        });
        http.route({
            path,
            method: "OPTIONS",
            handler: httpAction((ctx, req) => handler(ctx, req)),
        });
    };

    // 1. OpenID Configuration
    registerGetEndpoint(
        `${prefix}/.well-known/openid-configuration`,
        (ctx, req) => handlers.openIdConfiguration(ctx, req)
    );

    // 2. OAuth Authorization Server Metadata (RFC 8414)
    registerGetEndpoint(
        `${prefix}/.well-known/oauth-authorization-server`,
        (ctx, req) => handlers.openIdConfiguration(ctx, req)
    );

    // 3. JWKS
    registerGetEndpoint(
        `${prefix}/.well-known/jwks.json`,
        (ctx, req) => handlers.jwks(ctx, req)
    );

    // 4. Protected Resource Metadata (RFC 9728)
    registerGetEndpoint(
        `${prefix}/.well-known/oauth-protected-resource`,
        (ctx, req) => handlers.protectedResource(ctx, req)
    );

    // 5. Authorization Endpoint (redirect to frontend)
    const authorizeEndpoint = async (ctx: RunActionCtx, request: Request) => {
        const defaultAuthorize = () => handlers.authorize(ctx, request);

        if (authorizeHandler) {
            return authorizeHandler(ctx as RunActionCtx & { auth: Auth }, request, defaultAuthorize);
        }

        return defaultAuthorize();
    };
    registerGetEndpoint(
        `${prefix}/authorize`,
        (ctx, req) => authorizeEndpoint(ctx, req)
    );

    // 6. Token Endpoint
    registerPostEndpoint(
        `${prefix}/token`,
        (ctx, req) => handlers.token(ctx, req)
    );

    // 7. UserInfo Endpoint
    // Wrap getUserProfile to pass ctx for DB access
    const userInfoHandler = getUserProfile
        ? (ctx: RunActionCtx, req: Request) => handlers.userInfo(ctx, req, (userId) => getUserProfile(ctx, userId))
        : (ctx: RunActionCtx, req: Request) => handlers.userInfo(ctx, req, async (userId) => ({ sub: userId }));

    http.route({
        path: `${prefix}/userinfo`,
        method: "GET",
        handler: httpAction(userInfoHandler),
    });
    http.route({
        path: `${prefix}/userinfo`,
        method: "POST",
        handler: httpAction(userInfoHandler),
    });
    http.route({
        path: `${prefix}/userinfo`,
        method: "OPTIONS",
        handler: httpAction(userInfoHandler),
    });

    // 8. Dynamic Client Registration
    registerPostEndpoint(
        `${prefix}/register`,
        (ctx, req) => handlers.register(ctx, req)
    );

    // Root well-known paths (RFC 8414 compatibility)
    if (registerRootWellKnown) {
        // /.well-known/oauth-authorization-server
        registerGetEndpoint(
            "/.well-known/oauth-authorization-server",
            (ctx, req) => handlers.openIdConfiguration(ctx, req)
        );

        // /.well-known/oauth-authorization-server{prefix} (for issuer with custom prefix)
        // RFC 8414: If issuer is https://example.com/oauth, well-known is /.well-known/oauth-authorization-server/oauth
        // Only register if prefix is non-empty to avoid duplicate route registration
        if (prefix && prefix !== "/") {
            registerGetEndpoint(
                `/.well-known/oauth-authorization-server${prefix}`,
                (ctx, req) => handlers.openIdConfiguration(ctx, req)
            );
        }

        // /.well-known/oauth-protected-resource
        registerGetEndpoint(
            "/.well-known/oauth-protected-resource",
            (ctx, req) => handlers.protectedResource(ctx, req)
        );
    }
}
