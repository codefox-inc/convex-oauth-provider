import type { ActionCtx } from "./_generated/server.js";
import { SignJWT, importPKCS8 } from "jose";
import {
    getJWKS,
    sign,
    verifyAccessToken,
    getIssuerUrl,
    handleCorsOptions,
    createCorsHeaders,
    OAuthError,
    normalizePrefix,
    getSigningKeyId
} from "../lib/oauth.js";
import { matchRedirectUri } from "./mutations.js";
import type { Auth } from "convex/server";
import type { OAuthConfig, UserProfile } from "../lib/oauth.js";
import type { RunActionCtx, RunQueryCtx, RunMutationCtx } from "../lib/convex-types.js";

/**
 * OAuth Registration Request Body
 */
interface OAuthRegistrationBody {
    redirect_uris?: string[];
    client_name?: string;
    scope?: string;
    token_endpoint_auth_method?: string;
    logo_uri?: string;
    client_uri?: string;
    tos_uri?: string;
    policy_uri?: string;
    [key: string]: unknown;
}

function buildAuthorizeErrorRedirect(
    redirectUri: string,
    error: string,
    description?: string,
    state?: string | null
): Response {
    const url = new URL(redirectUri);
    url.searchParams.set("error", error);
    if (description) {
        url.searchParams.set("error_description", description);
    }
    if (state) {
        url.searchParams.set("state", state);
    }
    return Response.redirect(url.toString());
}

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

function isConsentFromProvider(request: Request, config: OAuthConfig): boolean {
    const allowedOrigins = [config.siteUrl, config.convexSiteUrl]
        .filter(Boolean)
        .map((url) => {
            try {
                return new URL(url as string).origin;
            } catch {
                return null;
            }
        })
        .filter((origin): origin is string => origin !== null);

    if (allowedOrigins.length === 0) return false;

    const origin = request.headers.get("Origin");
    if (origin) {
        return allowedOrigins.includes(origin);
    }

    const referer = request.headers.get("Referer");
    if (referer) {
        try {
            const refererOrigin = new URL(referer).origin;
            return allowedOrigins.includes(refererOrigin);
        } catch {
            return false;
        }
    }

    return false;
}

/**
 * Component API references (passed from SDK)
 *
 * Note: Uses RunQueryCtx/RunMutationCtx as the base context types.
 * ActionCtx extends these types, so handlers can pass ActionCtx to these functions.
 */
export interface OAuthComponentAPI {
    queries: {
        getClient: (ctx: RunQueryCtx, args: { clientId: string }) => Promise<{
            clientId: string;
            type: "confidential" | "public";
            redirectUris: string[];
            allowedScopes: string[];
        } | null>;
        getRefreshToken: (ctx: RunQueryCtx, args: { refreshToken: string }) => Promise<{
            refreshToken?: string;
            clientId: string;
            userId: string;
            scopes: string[];
            refreshTokenExpiresAt?: number;
        } | null>;
        getTokensByUser: (ctx: RunQueryCtx, args: { userId: string }) => Promise<Array<{
            _id: string;
            clientId: string;
            userId: string;
            scopes: string[];
            accessTokenExpiresAt: number;
            refreshTokenExpiresAt?: number;
        }>>;
    };
    mutations: {
        issueAuthorizationCode: (ctx: RunMutationCtx, args: {
            clientId: string;
            userId: string;
            scopes: string[];
            redirectUri: string;
            codeChallenge: string;
            codeChallengeMethod: string;
            nonce?: string;
        }) => Promise<string>;
        consumeAuthCode: (ctx: RunMutationCtx, args: {
            code: string;
            clientId: string;
            redirectUri?: string;
            codeVerifier: string;
        }) => Promise<{
            userId: string;
            scopes: string[];
            codeChallenge: string;
            codeChallengeMethod: string;
            redirectUri: string;
            nonce?: string;
            codeHash: string;
        }>;
        saveTokens: (ctx: RunMutationCtx, args: {
            accessToken: string;
            refreshToken?: string;
            clientId: string;
            userId: string;
            scopes: string[];
            expiresAt: number;
            refreshTokenExpiresAt?: number;
            authorizationCode?: string;
        }) => Promise<void>;
        rotateRefreshToken: (ctx: RunMutationCtx, args: {
            oldRefreshToken: string;
            accessToken: string;
            refreshToken: string;
            clientId: string;
            userId: string;
            scopes: string[];
            expiresAt: number;
            refreshTokenExpiresAt: number;
        }) => Promise<void>;
        upsertAuthorization: (ctx: RunMutationCtx, args: {
            userId: string;
            clientId: string;
            scopes: string[];
        }) => Promise<string>;
        updateAuthorizationLastUsed: (ctx: RunMutationCtx, args: {
            userId: string;
            clientId: string;
        }) => Promise<void>;
    };
    clientManagement: {
        registerClient: (ctx: RunMutationCtx, args: {
            name: string;
            redirectUris: string[];
            scopes: string[];
            type: "confidential" | "public";
            website?: string;
            logoUrl?: string;
            tosUrl?: string;
            policyUrl?: string;
        }) => Promise<{
            clientId: string;
            clientSecret?: string;
            clientIdIssuedAt: number;
        }>;
        verifyClientSecret: (ctx: RunMutationCtx, args: {
            clientId: string;
            clientSecret: string;
        }) => Promise<boolean>;
    };
}

// --------------------------------------------------------------------------
// Handler Functions
// --------------------------------------------------------------------------

/**
 * Authorization Endpoint
 */
export async function authorizeHandler(
    ctx: ActionCtx,
    request: Request,
    config: OAuthConfig,
    api: OAuthComponentAPI
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "GET, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "GET, OPTIONS");

    if (request.method !== "GET") {
        return new Response("Method Not Allowed", { status: 405, headers });
    }

    const url = new URL(request.url);
    const params = url.searchParams;

    const responseType = params.get("response_type");
    const clientId = params.get("client_id");
    const redirectUri = params.get("redirect_uri");
    const scope = params.get("scope") ?? "";
    const state = params.get("state");
    const consent = params.get("consent");
    const codeChallenge = params.get("code_challenge");
    const codeChallengeMethod = params.get("code_challenge_method");
    const nonce = params.get("nonce") ?? undefined;

    if (!clientId) {
        return new OAuthError("invalid_request", "client_id required").toResponse(headers);
    }
    if (!redirectUri) {
        return new OAuthError("invalid_request", "redirect_uri required").toResponse(headers);
    }

    const client = await api.queries.getClient(ctx, { clientId });
    if (!client) {
        return new OAuthError("invalid_client", "Unknown client").toResponse(headers);
    }
    if (!matchRedirectUri(redirectUri, client.redirectUris)) {
        return new OAuthError("invalid_request", "redirect_uri mismatch").toResponse(headers);
    }

    if (consent === "approve" && !isConsentFromProvider(request, config)) {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "access_denied",
            "User consent required",
            state
        );
    }

    if (responseType !== "code") {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "unsupported_response_type",
            "response_type must be code",
            state
        );
    }

    const requestedScopes = scope
        ? scope.split(" ").filter(Boolean)
        : [];
    if (requestedScopes.length === 0) {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "invalid_request",
            "scope required",
            state
        );
    }
    const invalidScopes = requestedScopes.filter((s) => !client.allowedScopes.includes(s));
    if (invalidScopes.length > 0) {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "invalid_scope",
            "Scope not allowed",
            state
        );
    }

    if (!codeChallenge) {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "invalid_request",
            "code_challenge required",
            state
        );
    }
    if (codeChallengeMethod !== "S256") {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "invalid_request",
            "code_challenge_method must be S256",
            state
        );
    }

    if (consent !== "approve") {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "access_denied",
            "User consent required",
            state
        );
    }

    if (!config.getUserId) {
        return new OAuthError("server_error", "getUserId is not configured", 500).toResponse(headers);
    }
    const userId = await config.getUserId(ctx as RunActionCtx & { auth: Auth }, request);
    if (!userId) {
        return buildAuthorizeErrorRedirect(
            redirectUri,
            "access_denied",
            "User not authenticated",
            state
        );
    }

    const code = await api.mutations.issueAuthorizationCode(ctx, {
        clientId,
        userId,
        scopes: requestedScopes,
        redirectUri,
        codeChallenge,
        codeChallengeMethod,
        nonce,
    });

    const redirect = new URL(redirectUri);
    redirect.searchParams.set("code", code);
    if (state) {
        redirect.searchParams.set("state", state);
    }

    return Response.redirect(redirect.toString());
}

/**
 * OpenID Configuration (Discovery Endpoint)
 */
export async function openIdConfigurationHandler(
    _ctx: ActionCtx,
    request: Request,
    config: OAuthConfig
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "GET, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "GET, OPTIONS");

    const backendUrl = config.convexSiteUrl ?? config.siteUrl;
    const prefix = normalizePrefix(config.prefix);

    const issuerUrl = getIssuerUrl(config);

    const supportedScopes =
        config.allowedScopes ?? ["openid", "profile", "email", "offline_access"];

    const responseBody: Record<string, unknown> = {
        issuer: issuerUrl,
        authorization_endpoint: `${backendUrl}${prefix}/authorize`,
        token_endpoint: `${backendUrl}${prefix}/token`,
        userinfo_endpoint: `${backendUrl}${prefix}/userinfo`,
        jwks_uri: `${backendUrl}${prefix}/.well-known/jwks.json`,
        response_types_supported: ["code"],
        subject_types_supported: ["public"],
        id_token_signing_alg_values_supported: ["RS256"],
        scopes_supported: supportedScopes,
        token_endpoint_auth_methods_supported: ["client_secret_post", "none"],
        grant_types_supported: ["authorization_code", "refresh_token"],
        code_challenge_methods_supported: ["S256"],
    };

    if (config.allowDynamicClientRegistration) {
        responseBody.registration_endpoint = `${backendUrl}${prefix}/register`;
    }

    return new Response(JSON.stringify(responseBody), { headers });
}

/**
 * JWKS Endpoint
 */
export async function jwksHandler(
    _ctx: ActionCtx,
    request: Request,
    config: OAuthConfig
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "GET, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "GET, OPTIONS");

    try {
        const jwks = await getJWKS(config);
        return new Response(JSON.stringify(jwks), { headers });
    } catch (e) {
        console.error(e);
        return new OAuthError("server_error", "Failed to get JWKS", 500).toResponse(headers);
    }
}

/**
 * Token Endpoint
 */
export async function tokenHandler(
    ctx: ActionCtx,
    request: Request,
    config: OAuthConfig,
    api: OAuthComponentAPI
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "POST, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "POST, OPTIONS");
    const tokenHeaders = {
        ...headers,
        "Cache-Control": "no-store",
        "Pragma": "no-cache",
    };

    if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405, headers: tokenHeaders });
    }

    try {
        const formData = await request.formData();
        const grantType = formData.get("grant_type");
        const code = formData.get("code");
        const redirectUri = formData.get("redirect_uri");
        const clientId = formData.get("client_id");
        const codeVerifier = formData.get("code_verifier");
        const clientSecret = formData.get("client_secret");

        if (!clientId) throw new OAuthError("invalid_request", "client_id required");

        // Client existence + confidential client check
        const client = await api.queries.getClient(ctx, { clientId: clientId as string });
        if (!client) {
            throw new OAuthError("invalid_client", "Unknown client", 401);
        }

        if (client.type === "confidential") {
            if (!clientSecret) throw new OAuthError("invalid_client", "client_secret required", 401);

            const isValid = await api.clientManagement.verifyClientSecret(ctx, {
                clientId: clientId as string,
                clientSecret: clientSecret as string,
            });

            if (!isValid) throw new OAuthError("invalid_client", "Invalid client secret", 401);
        }

        if (grantType === "authorization_code") {
            if (!code || !codeVerifier) {
                throw new OAuthError("invalid_request", "Missing code parameters");
            }

            // A. Consume Code
            const codeData = await api.mutations.consumeAuthCode(ctx, {
                code: code as string,
                clientId: clientId as string,
                redirectUri: redirectUri as string | undefined,
                codeVerifier: codeVerifier as string,
            });

            // Check for authorization code reuse (RFC Line 1136)
            if ("error" in codeData && codeData.error === "authorization_code_reuse_detected") {
                throw new OAuthError("invalid_grant", "Authorization code has already been used");
            }

            // D. Issue Tokens
            const userId = codeData.userId;
            const now = Math.floor(Date.now() / 1000);
            const accessTokenExpiresIn = 3600;
            const issuerUrl = getIssuerUrl(config);
            const keyId = getSigningKeyId(config);

            // Access Token
            const accessToken = await sign(
                {
                    uid: userId,
                    scp: codeData.scopes,
                    cid: clientId,
                },
                userId,
                config.applicationID ?? "convex",
                "1h",
                config.privateKey,
                issuerUrl,
                keyId
            );

            // ID Token (OIDC)
            let idToken: string | undefined;
            if (codeData.scopes.includes("openid")) {
                const privateKey = await importPKCS8(config.privateKey, "RS256");

                const idTokenClaims = {
                    sub: userId,
                    iss: issuerUrl,
                    aud: clientId as string,
                    nonce: codeData.nonce,
                };

                idToken = await new SignJWT(idTokenClaims)
                    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: keyId })
                    .setIssuedAt()
                    .setExpirationTime("1h")
                    .sign(privateKey);
            }

            // Refresh Token (only if offline_access scope is present)
            let refreshToken: string | undefined;
            if (codeData.scopes.includes("offline_access")) {
                refreshToken = crypto.randomUUID();
            }

            // E. Save Tokens (RFC Line 1136: link tokens to authorization code for replay detection)
            await api.mutations.saveTokens(ctx, {
                accessToken,
                refreshToken,
                clientId: clientId as string,
                userId: userId,
                scopes: codeData.scopes,
                expiresAt: (now + accessTokenExpiresIn) * 1000,
                refreshTokenExpiresAt: refreshToken ? (now + 3600 * 24 * 30) * 1000 : undefined,
                authorizationCode: codeData.codeHash, // Link to authorization code
            });

            // F. Create/Update Authorization Record
            await api.mutations.upsertAuthorization(ctx, {
                userId,
                clientId: clientId as string,
                scopes: codeData.scopes,
            });

            // Build response
            // RFC Line 509: Always include 'scope' for clarity (MUST include if different from requested)
            const tokenResponse: any = {
                access_token: accessToken,
                token_type: "Bearer",
                expires_in: accessTokenExpiresIn,
                scope: codeData.scopes.join(" "),
            };

            if (refreshToken) {
                tokenResponse.refresh_token = refreshToken;
            }

            if (idToken) {
                tokenResponse.id_token = idToken;
            }

            return new Response(
                JSON.stringify(tokenResponse),
                { status: 200, headers: tokenHeaders }
            );
        }

        if (grantType === "refresh_token") {
            const refreshToken = formData.get("refresh_token") as string;
            const requestedScope = formData.get("scope") as string | null; // RFC 6749 Section 6

            if (!refreshToken) throw new OAuthError("invalid_request", "refresh_token required");

            const oldToken = await api.queries.getRefreshToken(ctx, { refreshToken });

            if (!oldToken) throw new OAuthError("invalid_grant", "Invalid refresh token");

            if (!oldToken.refreshTokenExpiresAt || oldToken.refreshTokenExpiresAt < Date.now()) {
                throw new OAuthError("invalid_grant", "Refresh token expired");
            }

            if (oldToken.clientId !== clientId) throw new OAuthError("invalid_grant", "Client mismatch");

            const userId = oldToken.userId;

            // RFC 6749 Section 6: スコープパラメータ処理（アクセストークン用）
            let accessTokenScopes: string[];
            if (requestedScope) {
                // アクセストークンのスコープは元のスコープのサブセット可能
                const requestedScopes = requestedScope.split(" ").filter(Boolean);
                const invalidScopes = requestedScopes.filter(
                    (scope) => !oldToken.scopes.includes(scope)
                );
                if (invalidScopes.length > 0) {
                    throw new OAuthError(
                        "invalid_scope",
                        "Requested scope exceeds original authorization"
                    );
                }
                accessTokenScopes = requestedScopes;
            } else {
                accessTokenScopes = oldToken.scopes;
            }

            // クライアントの許可スコープ検証
            const invalidClientScopes = accessTokenScopes.filter(
                (scope) => !client.allowedScopes.includes(scope)
            );
            if (invalidClientScopes.length > 0) {
                throw new OAuthError(
                    "invalid_scope",
                    "Scope not allowed for this client"
                );
            }

            // RFC 4.3.3: 新RTのスコープは元RTと同一
            const refreshTokenScopes = oldToken.scopes; // 常に元のスコープ

            const now = Math.floor(Date.now() / 1000);
            const accessTokenExpiresIn = 3600;
            const issuerUrl = getIssuerUrl(config);
            const keyId = getSigningKeyId(config);

            // Access Token (JWT) - 縮小されたスコープ使用
            const accessToken = await sign(
                {
                    uid: userId,
                    scp: accessTokenScopes, // 縮小可能
                    cid: clientId as string,
                },
                userId,
                config.applicationID ?? "convex",
                "1h",
                config.privateKey,
                issuerUrl,
                keyId
            );

            // New Refresh Token (Rotation)
            const newRefreshToken = crypto.randomUUID();

            // ID Token
            let idToken: string | undefined;
            if (accessTokenScopes.includes("openid")) {
                const privateKey = await importPKCS8(config.privateKey, "RS256");
                idToken = await new SignJWT({
                    sub: userId,
                    iss: issuerUrl,
                    aud: clientId as string,
                })
                    .setProtectedHeader({ alg: "RS256", typ: "JWT", kid: keyId })
                    .setIssuedAt()
                    .setExpirationTime("1h")
                    .sign(privateKey);
            }

            // Rotate - 元のスコープ維持
            try {
                await api.mutations.rotateRefreshToken(ctx, {
                    oldRefreshToken: refreshToken,
                    accessToken,
                    refreshToken: newRefreshToken,
                    clientId: clientId as string,
                    userId,
                    scopes: refreshTokenScopes, // 元のスコープと同一
                    expiresAt: (now + accessTokenExpiresIn) * 1000,
                    refreshTokenExpiresAt: (now + 3600 * 24 * 30) * 1000,
                });

                // Update authorization lastUsedAt
                await api.mutations.updateAuthorizationLastUsed(ctx, {
                    userId,
                    clientId: clientId as string,
                });
            } catch (e) {
                if (e instanceof Error && e.message.includes("invalid_grant")) {
                    throw new OAuthError("invalid_grant", "Invalid refresh token (rotated?)");
                }
                throw e;
            }

            // Build response - アクセストークンのスコープを返す
            // RFC Line 509: Always include 'scope' (MUST include if different from requested)
            // Note: scope may be reduced if client requested a subset
            const refreshResponse: any = {
                access_token: accessToken,
                token_type: "Bearer",
                expires_in: accessTokenExpiresIn,
                scope: accessTokenScopes.join(" "),
            };

            refreshResponse.refresh_token = newRefreshToken;

            if (idToken) {
                refreshResponse.id_token = idToken;
            }

            return new Response(
                JSON.stringify(refreshResponse),
                { status: 200, headers: tokenHeaders }
            );
        }

        throw new OAuthError("unsupported_grant_type", "Grant type not supported");

    } catch (e) {
        console.error(e);
        if (e instanceof OAuthError) {
            return e.toResponse(tokenHeaders);
        }
        if (e instanceof Error) {
            // シンプルなエラーメッセージを先にチェック（完全一致）
            if (e.message === "invalid_grant") {
                return new OAuthError("invalid_grant", "Invalid grant").toResponse(tokenHeaders);
            }
            if (e.message === "invalid_client") {
                return new OAuthError("invalid_client", "Invalid client", 401).toResponse(tokenHeaders);
            }

            // 特定エラーメッセージをOAuthエラーコードにマッピング（部分一致）
            const errorMap: Record<string, [string, string, number?]> = {
                "redirect_uri_mismatch": ["invalid_grant", "Redirect URI mismatch", undefined],
                "invalid_code_verifier": ["invalid_grant", "Code verifier validation failed", undefined],
                "unsupported_code_challenge_method": ["invalid_request", "Unsupported code challenge method", undefined],
                "scope_change_not_allowed": ["invalid_scope", "Refresh token scope must remain identical", undefined],
                "authorization_code_reuse_detected": ["invalid_grant", "Authorization code has already been used", undefined],
            };

            for (const [pattern, [code, message, status]] of Object.entries(errorMap)) {
                if (e.message.includes(pattern)) {
                    return new OAuthError(code, message, status).toResponse(tokenHeaders);
                }
            }

            if (e.message.startsWith("invalid_scope")) {
                return new OAuthError("invalid_scope", e.message).toResponse(tokenHeaders);
            }
        }
        const message = e instanceof Error ? e.message : String(e);
        return new OAuthError("invalid_request", message).toResponse(tokenHeaders);
    }
}

/**
 * UserInfo Endpoint
 */
export async function userInfoHandler(
    ctx: ActionCtx,
    request: Request,
    config: OAuthConfig,
    getUserProfile: (userId: string) => Promise<UserProfile | null>
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "GET, POST, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "GET, POST, OPTIONS");

    const authHeader = request.headers.get("Authorization");
    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return new Response(null, {
            status: 401,
            headers: {
                ...headers,
                "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Missing bearer token"',
            },
        });
    }

    const token = authHeader.split(" ")[1];

    try {
        const issuerUrl = getIssuerUrl(config);
        const payload = await verifyAccessToken(token, config, issuerUrl);
        const userId = payload.sub as string;
        const clientId = payload.cid as string | undefined;
        const scopeClaim = payload.scp;
        const scopes = Array.isArray(scopeClaim)
            ? scopeClaim
            : typeof scopeClaim === "string"
                ? scopeClaim.split(" ").filter(Boolean)
                : [];

        if (config.checkAuthorization) {
            const isAuthorized = await config.checkAuthorization(ctx as RunActionCtx & { auth: Auth }, userId, clientId);
            if (!isAuthorized) {
                return new Response(null, {
                    status: 401,
                    headers: {
                        ...headers,
                        "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Authorization revoked"',
                    },
                });
            }
        }

        if (!scopes.includes("openid")) {
            return new Response(null, {
                status: 403,
                headers: {
                    ...headers,
                    "WWW-Authenticate": 'Bearer error="insufficient_scope", scope="openid"',
                },
            });
        }

        const user = await getUserProfile(userId);

        if (!user) {
            return new Response(null, { status: 401, headers });
        }

        const responseBody: UserProfile = { sub: userId };
        if (scopes.includes("profile")) {
            responseBody.name = user.name;
            responseBody.picture = user.picture;
        }
        if (scopes.includes("email")) {
            responseBody.email = user.email;
            responseBody.email_verified = user.email_verified;
        }

        return new Response(JSON.stringify(responseBody), { headers });

    } catch {
        return new Response(null, {
            status: 401,
            headers: {
                ...headers,
                "WWW-Authenticate": 'Bearer error="invalid_token", error_description="Token verification failed"',
            },
        });
    }
}

/**
 * Register Endpoint (Dynamic Client Registration)
 */
export async function registerHandler(
    ctx: ActionCtx,
    request: Request,
    config: OAuthConfig,
    api: OAuthComponentAPI
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "POST, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "POST, OPTIONS");

    if (request.method !== "POST") {
        return new Response("Method Not Allowed", { status: 405, headers });
    }
    if (!config.allowDynamicClientRegistration) {
        return new OAuthError(
            "access_denied",
            "Dynamic client registration disabled",
            403
        ).toResponse(headers);
    }

    try {
        const body = (await request.json()) as OAuthRegistrationBody;

        const redirectUris = body.redirect_uris || [];
        const clientName = body.client_name || "Unknown Client";
        const allowedScopes =
            config.allowedScopes ?? ["openid", "profile", "email", "offline_access"];
        const requestedScopes = body.scope
            ? body.scope.split(" ").filter(Boolean)
            : allowedScopes;
        const invalidScopes = requestedScopes.filter((scope) => !allowedScopes.includes(scope));
        if (invalidScopes.length > 0) {
            throw new OAuthError("invalid_scope", `Unsupported scopes: ${invalidScopes.join(", ")}`);
        }
        const scopes = requestedScopes;
        const authMethod = body.token_endpoint_auth_method;
        if (authMethod && authMethod !== "client_secret_post" && authMethod !== "none") {
            throw new OAuthError(
                "invalid_client_metadata",
                "Unsupported token_endpoint_auth_method"
            );
        }
        const type = (authMethod === "none") ? "public" : "confidential";

        if (redirectUris.length === 0) {
            throw new OAuthError("invalid_request", "redirect_uris required");
        }
        const invalidRedirect = redirectUris.find((uri) => !isValidRedirectUri(uri));
        if (invalidRedirect) {
            throw new OAuthError("invalid_request", `Invalid redirect_uri: ${invalidRedirect}`);
        }

        const result = await api.clientManagement.registerClient(ctx, {
            name: clientName,
            redirectUris: redirectUris,
            scopes: scopes,
            type: type,
            logoUrl: body.logo_uri,
            website: body.client_uri,
            tosUrl: body.tos_uri,
            policyUrl: body.policy_uri,
        });

        const responseBody: Record<string, unknown> = {
            client_id: result.clientId,
            client_id_issued_at: result.clientIdIssuedAt,
            redirect_uris: redirectUris,
            grant_types: ["authorization_code", "refresh_token"],
            response_types: ["code"],
            scope: scopes.join(" "),
            token_endpoint_auth_method: authMethod || "client_secret_post",
            application_type: "web",
            client_name: clientName,
        };

        if (result.clientSecret) {
            responseBody.client_secret = result.clientSecret;
            responseBody.client_secret_expires_at = 0;
        }

        return new Response(JSON.stringify(responseBody), { status: 201, headers });

    } catch (e) {
        console.error("DCR Failed:", e);
        if (e instanceof OAuthError) {
            return e.toResponse(headers);
        }
        const message = e instanceof Error ? e.message : String(e);
        return new OAuthError("invalid_request", message).toResponse(headers);
    }
}

/**
 * Protected Resource Metadata (RFC 9728)
 */
export async function oauthProtectedResourceHandler(
    _ctx: ActionCtx,
    request: Request,
    config: OAuthConfig
): Promise<Response> {
    const corsResponse = handleCorsOptions(request, config, "GET, POST, OPTIONS");
    if (corsResponse) return corsResponse;
    const headers = createCorsHeaders(request.headers.get("Origin"), config, "GET, POST, OPTIONS");

    const issuerUrl = getIssuerUrl(config);

    const supportedScopes =
        config.allowedScopes ?? ["openid", "profile", "email", "offline_access"];

    return new Response(
        JSON.stringify({
            resource: config.siteUrl,
            authorization_servers: [issuerUrl],
            scopes_supported: supportedScopes,
        }),
        { headers }
    );
}
