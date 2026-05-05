import { describe, expect, test, vi } from "vitest";
import { decodeJwt, decodeProtectedHeader, exportJWK, exportPKCS8, generateKeyPair } from "jose";
import {
    authorizeHandler,
    openIdConfigurationHandler,
    registerHandler,
    tokenHandler,
    userInfoHandler,
    type OAuthComponentAPI,
} from "../handlers";
import type { OAuthConfig } from "../../lib/oauth";

const config: OAuthConfig = {
    privateKey: "dummy",
    jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
    siteUrl: "https://example.com",
    allowDynamicClientRegistration: true,
};

function makeApi(overrides: Partial<OAuthComponentAPI> = {}): OAuthComponentAPI {
    return {
        queries: {
            getClient: async (_ctx, { clientId }) => ({
                clientId,
                type: "confidential",
                redirectUris: ["https://cb"],
                allowedScopes: ["openid", "profile", "offline_access"],
            }),
            getRefreshToken: async () => null,
            getTokensByUser: async () => [],
            ...overrides.queries,
        },
        mutations: {
            issueAuthorizationCode: async () => "",
            consumeAuthCode: async () => {
                throw new Error("invalid_grant");
            },
            saveTokens: async () => undefined,
            rotateRefreshToken: async () => undefined,
            upsertAuthorization: async () => "",
            updateAuthorizationLastUsed: async () => undefined,
            ...overrides.mutations,
        },
        clientManagement: {
            registerClient: async () => ({
                clientId: "client",
                clientSecret: "secret",
                clientIdIssuedAt: 0,
            }),
            verifyClientSecret: async () => true,
            ...overrides.clientManagement,
        },
    };
}

describe("OAuth handler protocol checks", () => {
    test("authorization endpoint rejects duplicated singleton parameters", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toContain("Duplicate parameter");
        expect(issueAuthorizationCode).not.toHaveBeenCalled();
    });

    test("authorization endpoint rejects resource values that are not absolute URI references without fragments", async () => {
        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve&resource=https%3A%2F%2Fapi.example.com%2Fmcp%23frag", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi()
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_target");
    });

    test("authorization endpoint treats duplicate resource parameters as invalid_target", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve&resource=https%3A%2F%2Fapi.example.com%2Fone&resource=https%3A%2F%2Fapi.example.com%2Ftwo", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_target");
        expect(issueAuthorizationCode).not.toHaveBeenCalled();
    });

    test("authorization endpoint rejects code_challenge values outside PKCE ABNF", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=short&code_challenge_method=S256&consent=approve", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toContain("code_challenge");
        expect(issueAuthorizationCode).not.toHaveBeenCalled();
    });

    test("authorization endpoint keeps offline_access when prompt contains consent in a space-delimited list", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid%20offline_access&prompt=login%20consent&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        expect(issueAuthorizationCode).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({ scopes: ["openid", "offline_access"] })
        );
    });

    test("authorization endpoint returns login_required for max_age it cannot safely satisfy", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve&max_age=60", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("login_required");
        expect(issueAuthorizationCode).not.toHaveBeenCalled();
    });

    test("token endpoint rejects a resource request when the authorization code was not resource-bound", async () => {
        const consumeAuthCode = vi.fn(async () => ({
            userId: "user",
            scopes: ["openid"],
            codeChallenge: "challenge",
            codeChallengeMethod: "S256",
            redirectUri: "https://cb",
            codeHash: "hash",
        }));

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                    resource: "https://api.example.com/mcp",
                }),
            }),
            config,
            makeApi({ mutations: { consumeAuthCode } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({ error: "invalid_target" });
    });

    test("token endpoint rejects a resource request when the refresh token was not resource-bound", async () => {
        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: "client",
                    refresh_token: "rt",
                    client_secret: "secret",
                    resource: "https://api.example.com/mcp",
                }),
            }),
            config,
            makeApi({
                queries: {
                    getRefreshToken: async () => ({
                        clientId: "client",
                        userId: "user",
                        scopes: ["openid", "offline_access"],
                        refreshTokenExpiresAt: Date.now() + 3600000,
                    }),
                } as any,
            })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({ error: "invalid_target" });
    });

    test("token endpoint stores the default audience on refresh tokens when no resource is requested", async () => {
        const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const saveTokens = vi.fn(async () => undefined);

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            {
                ...config,
                privateKey: privateKeyPem,
                jwks: JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }),
                applicationID: "default-audience",
            },
            makeApi({
                mutations: {
                    consumeAuthCode: async () => ({
                        userId: "user",
                        scopes: ["openid", "offline_access"],
                        codeChallenge: "challenge",
                        codeChallengeMethod: "S256",
                        redirectUri: "https://cb",
                        codeHash: "hash",
                    }),
                    saveTokens,
                } as any,
            })
        );

        expect(response.status).toBe(200);
        expect(saveTokens).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({ audience: "default-audience", resource: undefined })
        );
    });

    test("ID token includes auth_time from the authorization code", async () => {
        const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            {
                ...config,
                privateKey: privateKeyPem,
                jwks: JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }),
            },
            makeApi({
                mutations: {
                    consumeAuthCode: async () => ({
                        userId: "user",
                        scopes: ["openid"],
                        codeChallenge: "challenge",
                        codeChallengeMethod: "S256",
                        redirectUri: "https://cb",
                        codeHash: "hash",
                        authTime: 1710000000,
                    }),
                } as any,
            })
        );

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(decodeJwt(body.id_token)).toMatchObject({ auth_time: 1710000000 });
    });

    test("authorization code resource becomes access token audience and token resource must match", async () => {
        const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const jwtConfig: OAuthConfig = {
            ...config,
            privateKey: privateKeyPem,
            jwks: JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }),
            getUserId: async () => "user",
        };
        const issueAuthorizationCode = vi.fn(async () => "code-with-resource");
        const consumeAuthCode = vi.fn(async (_ctx: unknown, args: { resource?: string }) => {
            if (args.resource && args.resource !== "https://api.example.com/mcp") {
                throw new Error("invalid_target");
            }
            return {
                userId: "user",
                scopes: ["openid"],
                codeChallenge: "challenge",
                codeChallengeMethod: "S256",
                redirectUri: "https://cb",
                codeHash: "hash",
                resource: "https://api.example.com/mcp",
            };
        });
        const api = makeApi({
            queries: {
                getClient: async (_ctx: unknown, { clientId }: { clientId: string }) => ({
                    clientId,
                    type: "public" as const,
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                    tokenEndpointAuthMethod: "none" as const,
                }),
            } as any,
            mutations: {
                issueAuthorizationCode,
                consumeAuthCode,
            } as any,
        });

        await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve&resource=https%3A%2F%2Fapi.example.com%2Fmcp", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            jwtConfig,
            api
        );
        expect(issueAuthorizationCode).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({ resource: "https://api.example.com/mcp" })
        );

        const mismatch = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code-with-resource",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    resource: "https://api.example.com/other",
                }),
            }),
            jwtConfig,
            api
        );
        expect(mismatch.status).toBe(400);
        await expect(mismatch.json()).resolves.toMatchObject({ error: "invalid_target" });

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code-with-resource",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    resource: "https://api.example.com/mcp",
                }),
            }),
            jwtConfig,
            api
        );

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(decodeProtectedHeader(body.access_token).typ).toBe("at+jwt");
        expect(decodeJwt(body.access_token)).toMatchObject({
            aud: "https://api.example.com/mcp",
            client_id: "client",
            scope: "openid",
            cid: "client",
        });
        expect(decodeJwt(body.access_token).jti).toEqual(expect.any(String));
    });

    test("token endpoint enforces the registered DCR token endpoint auth method", async () => {
        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                }),
                headers: { Authorization: `Basic ${btoa("client:secret")}` },
            }),
            config,
            makeApi({
                queries: {
                    getClient: async (_ctx: unknown, { clientId }: { clientId: string }) => ({
                        clientId,
                        type: "confidential" as const,
                        redirectUris: ["https://cb"],
                        allowedScopes: ["openid"],
                        tokenEndpointAuthMethod: "client_secret_post" as const,
                    }),
                } as any,
            })
        );

        expect(response.status).toBe(401);
        await expect(response.json()).resolves.toMatchObject({ error: "invalid_client" });
    });

    test("userinfo returns invalid_token challenge when a presented token maps to no user", async () => {
        const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const jwtConfig: OAuthConfig = {
            ...config,
            privateKey: privateKeyPem,
            jwks: JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256" }] }),
        };
        const tokenResponse = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            jwtConfig,
            makeApi({
                mutations: {
                    consumeAuthCode: async () => ({
                        userId: "missing-user",
                        scopes: ["openid"],
                        codeChallenge: "challenge",
                        codeChallengeMethod: "S256",
                        redirectUri: "https://cb",
                        codeHash: "hash",
                    }),
                } as any,
            })
        );
        const { access_token } = await tokenResponse.json();

        const response = await userInfoHandler(
            {} as any,
            new Request("https://example.com/oauth/userinfo", {
                headers: { Authorization: `Bearer ${access_token}` },
            }),
            jwtConfig,
            async () => null
        );

        expect(response.status).toBe(401);
        expect(response.headers.get("WWW-Authenticate")).toContain('error="invalid_token"');
    });

    test("token endpoint rejects duplicated OAuth parameters", async () => {
        const getClient = vi.fn();
        const body = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: "client",
            code: "code-1",
            redirect_uri: "https://cb",
            code_verifier: "verifier",
            client_secret: "secret",
        });
        body.append("code", "code-2");

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body,
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
            }),
            config,
            makeApi({ queries: { getClient } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_request",
        });
        expect(getClient).not.toHaveBeenCalled();
    });

    test("token endpoint treats duplicate resource parameters as invalid_target", async () => {
        const getClient = vi.fn();
        const body = new URLSearchParams({
            grant_type: "authorization_code",
            client_id: "client",
            code: "code-1",
            redirect_uri: "https://cb",
            code_verifier: "verifier",
            client_secret: "secret",
            resource: "https://api.example.com/one",
        });
        body.append("resource", "https://api.example.com/two");

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body,
                headers: { "Content-Type": "application/x-www-form-urlencoded" },
            }),
            config,
            makeApi({ queries: { getClient } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_target",
        });
        expect(getClient).not.toHaveBeenCalled();
    });

    test("token endpoint rejects Basic auth combined with client_secret_post", async () => {
        const verifyClientSecret = vi.fn(async () => true);
        const basic = btoa("client:basic-secret");

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    client_secret: "post-secret",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                }),
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": `Basic ${basic}`,
                },
            }),
            config,
            makeApi({ clientManagement: { verifyClientSecret } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_request",
        });
        expect(verifyClientSecret).not.toHaveBeenCalled();
    });

    test("token endpoint decodes Basic client credentials before validation", async () => {
        const getClient = vi.fn(async (_ctx, { clientId }) => ({
            clientId,
            type: "confidential" as const,
            redirectUris: ["https://cb"],
            allowedScopes: ["openid"],
        }));
        const verifyClientSecret = vi.fn(async () => true);
        const basic = btoa("client%3Aone:sec%3Aret%2F%2B");

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                }),
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": `Basic ${basic}`,
                },
            }),
            config,
            makeApi({
                queries: { getClient } as any,
                clientManagement: { verifyClientSecret } as any,
            })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_grant",
        });
        expect(getClient).toHaveBeenCalledWith(expect.anything(), { clientId: "client:one" });
        expect(verifyClientSecret).toHaveBeenCalledWith(expect.anything(), {
            clientId: "client:one",
            clientSecret: "sec:ret/+",
        });
    });

    test("token endpoint rejects client credentials for public clients", async () => {
        const getClient = vi.fn(async (_ctx, { clientId }) => ({
            clientId,
            type: "public" as const,
            redirectUris: ["https://cb"],
            allowedScopes: ["openid"],
        }));
        const basic = btoa("public-client:unexpected-secret");

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                }),
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Authorization": `Basic ${basic}`,
                },
            }),
            config,
            makeApi({ queries: { getClient } as any })
        );

        expect(response.status).toBe(401);
        expect(response.headers.get("WWW-Authenticate")).toBe('Basic realm="oauth"');
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_client",
        });
    });

    test("discovery advertises all supported token endpoint auth methods", async () => {
        const response = await openIdConfigurationHandler(
            {} as any,
            new Request("https://example.com/.well-known/openid-configuration"),
            config
        );

        await expect(response.json()).resolves.toMatchObject({
            token_endpoint_auth_methods_supported: [
                "client_secret_basic",
                "client_secret_post",
                "none",
            ],
        });
    });

    test("DCR defaults token_endpoint_auth_method to client_secret_basic", async () => {
        const registerClient = vi.fn(async () => ({
            clientId: "client",
            clientSecret: "secret",
            clientIdIssuedAt: 0,
        }));

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["https://client.example.com/cb"],
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(response.status).toBe(201);
        await expect(response.json()).resolves.toMatchObject({
            token_endpoint_auth_method: "client_secret_basic",
            client_secret: "secret",
        });
        expect(registerClient).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({ type: "confidential" })
        );
    });

    test("DCR preserves provider-supported offline_access for later authorization requests", async () => {
        const registerClient = vi.fn(async () => ({
            clientId: "client",
            clientSecret: "secret",
            clientIdIssuedAt: 0,
        }));

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["https://client.example.com/cb"],
                    scope: "openid profile email",
                    token_endpoint_auth_method: "none",
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(response.status).toBe(201);
        expect(registerClient).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({
                scopes: ["openid", "profile", "email", "offline_access"],
            })
        );
        await expect(response.json()).resolves.toMatchObject({
            scope: "openid profile email offline_access",
        });
    });

    test("DCR rejects unsafe metadata URLs before saving", async () => {
        const registerClient = vi.fn();

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["https://client.example.com/cb"],
                    logo_uri: "javascript:alert(1)",
                    policy_uri: "https://client.example.com/policy#fragment",
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_client_metadata",
        });
        expect(registerClient).not.toHaveBeenCalled();
    });

    test("DCR accepts https and loopback http metadata URLs", async () => {
        const registerClient = vi.fn(async () => ({
            clientId: "client",
            clientSecret: "secret",
            clientIdIssuedAt: 0,
        }));

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["https://client.example.com/cb"],
                    logo_uri: "https://client.example.com/logo.png",
                    client_uri: "http://localhost:3000",
                    tos_uri: "http://127.0.0.1/tos",
                    policy_uri: "http://[::1]/policy",
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(response.status).toBe(201);
        expect(registerClient).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({
                logoUrl: "https://client.example.com/logo.png",
                website: "http://localhost:3000",
                tosUrl: "http://127.0.0.1/tos",
                policyUrl: "http://[::1]/policy",
            })
        );
    });

    test("DCR rejects invalid redirect URIs with invalid_redirect_uri", async () => {
        const registerClient = vi.fn();

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["http://client.example.com/cb"],
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(response.status).toBe(400);
        await expect(response.json()).resolves.toMatchObject({
            error: "invalid_redirect_uri",
        });
        expect(registerClient).not.toHaveBeenCalled();
    });

    test("DCR accepts RFC8252 private-use redirect URIs and rejects unsafe variants", async () => {
        const registerClient = vi.fn(async () => ({
            clientId: "client",
            clientIdIssuedAt: 0,
        }));

        const accepted = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["com.example.app:/oauth2redirect"],
                    token_endpoint_auth_method: "none",
                }),
                headers: { "Content-Type": "application/json" },
            }),
            config,
            makeApi({ clientManagement: { registerClient } as any })
        );

        expect(accepted.status).toBe(201);
        expect(registerClient).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({
                redirectUris: ["com.example.app:/oauth2redirect"],
                type: "public",
            })
        );

        for (const redirectUri of [
            "myapp:/oauth2redirect",
            "com.example.app://oauth2redirect",
            "com.example.app:/oauth2redirect#fragment",
        ]) {
            const rejected = await registerHandler(
                {} as any,
                new Request("https://example.com/oauth/register", {
                    method: "POST",
                    body: JSON.stringify({
                        redirect_uris: [redirectUri],
                        token_endpoint_auth_method: "none",
                    }),
                    headers: { "Content-Type": "application/json" },
                }),
                config,
                makeApi({ clientManagement: { registerClient } as any })
            );

            expect(rejected.status).toBe(400);
            await expect(rejected.json()).resolves.toMatchObject({
                error: "invalid_redirect_uri",
            });
        }
    });

    test("userinfo missing or non-Bearer credentials challenge without OAuth error", async () => {
        const headerCases: HeadersInit[] = [new Headers(), { Authorization: "Basic abc" }];
        for (const headers of headerCases) {
            const response = await userInfoHandler(
                {} as any,
                new Request("https://example.com/oauth/userinfo", { headers }),
                config,
                async () => null
            );

            expect(response.status).toBe(401);
            const challenge = response.headers.get("WWW-Authenticate");
            expect(challenge).toBe('Bearer realm="userinfo"');
        }
    });
});
