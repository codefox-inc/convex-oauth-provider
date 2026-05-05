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

    test("authorization endpoint drops offline_access unless prompt consent is present", async () => {
        const issueAuthorizationCode = vi.fn(async () => "code");

        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid%20offline_access&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi({ mutations: { issueAuthorizationCode } as any })
        );

        expect(response.status).toBe(302);
        expect(issueAuthorizationCode).toHaveBeenCalledWith(
            expect.anything(),
            expect.objectContaining({ scopes: ["openid"] })
        );
    });

    test("authorization endpoint rejects max_age when auth_time is not supported", async () => {
        const response = await authorizeHandler(
            {} as any,
            new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&consent=approve&max_age=60", {
                method: "GET",
                headers: { Origin: "https://example.com" },
            }),
            { ...config, getUserId: async () => "user" },
            makeApi()
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toContain("max_age");
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
});
