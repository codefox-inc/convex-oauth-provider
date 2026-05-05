import { describe, expect, test, vi } from "vitest";
import {
    openIdConfigurationHandler,
    registerHandler,
    tokenHandler,
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
