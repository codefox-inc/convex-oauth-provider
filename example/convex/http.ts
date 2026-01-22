import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { components } from "./_generated/api";
import { OAuthProvider, registerOAuthRoutes } from "@codefox-inc/oauth-provider";
import { auth, getAuthUserId } from "./auth";

const http = httpRouter();
const oauthPrefix = process.env.OAUTH_PREFIX ?? "/oauth";

// Convex Auth routes (for session management)
auth.addHttpRoutes(http);

// ---------------------------------------------------------
// OAuth Provider Setup
// ---------------------------------------------------------

const oauthProvider = new OAuthProvider(components.oauthProvider, {
  // Use Convex Auth keys by default, fallback to OAuth-specific keys
  privateKey: process.env.JWT_PRIVATE_KEY ?? process.env.OAUTH_PRIVATE_KEY!,
  jwks: (process.env.JWKS ?? process.env.OAUTH_JWKS)!,
  siteUrl: process.env.SITE_URL ?? "http://localhost:5173",
  convexSiteUrl: process.env.CONVEX_SITE_URL,
  prefix: oauthPrefix,
  allowedOrigins: process.env.ALLOWED_ORIGINS,
  allowedScopes: ["openid", "profile", "email", "offline_access"],
  getUserId: async (ctx) => {
    const userId = await getAuthUserId(ctx);
    return userId ?? null;
  },
  allowDynamicClientRegistration: true,
});

// Register all OAuth routes with one call
registerOAuthRoutes(http, httpAction, oauthProvider, {
  siteUrl: process.env.SITE_URL ?? "http://localhost:5173",
  prefix: oauthPrefix,
  // ctx を受け取り、DB アクセスが可能
  getUserProfile: async (ctx, userId) => ({
    sub: userId,
    name: "Anonymous User",
  }),
  authorizeHandler: async (_ctx, request, defaultAuthorize) => {
    const url = new URL(request.url);
    if (url.searchParams.get("consent") === "approve") {
      return defaultAuthorize();
    }
    const consentUrl = new URL(
      `${process.env.SITE_URL ?? "http://localhost:5173"}${oauthPrefix}/authorize`
    );

    url.searchParams.forEach((value, key) => {
      if (value !== undefined && value !== null && value !== "") {
        consentUrl.searchParams.set(key, value);
      }
    });

    return Response.redirect(consentUrl.toString());
  },
});

export default http;
