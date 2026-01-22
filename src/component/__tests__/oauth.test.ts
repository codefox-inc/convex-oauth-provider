import { describe, test, expect, beforeEach, vi } from "vitest";
import { convexTest } from "convex-test";
import { api } from "../_generated/api";
import schema from "../schema";
import { hashToken } from "../token_security";
import { authorizeHandler, registerHandler, tokenHandler, userInfoHandler, oauthProtectedResourceHandler, jwksHandler, openIdConfigurationHandler } from "../handlers";
import { SignJWT, generateKeyPair, exportJWK, exportPKCS8 } from "jose";
import type { OAuthComponentAPI } from "../handlers";
import type { OAuthConfig } from "../../lib/oauth";

const modules = import.meta.glob("../**/*.ts");

describe("OAuth 2.1 Flow", () => {
    let t: ReturnType<typeof convexTest>;

    beforeEach(async () => {
        t = convexTest(schema, modules);
    });

    // ==========================================
    // Phase 1: Critical Security Tests
    // ==========================================

    test("Client Registration: Verify Secret Hashing", async () => {
        const redirectUri = "https://client.example.com/callback";
        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Confidential Client",
            redirectUris: [redirectUri],
            scopes: ["openid", "profile"],
            type: "confidential",
        });

        expect(result.clientId).toBeDefined();
        expect(result.clientSecret).toBeDefined();

        // Check DB for Hash
        const clientInDb = await t.query(api.queries.getClient, {
            clientId: result.clientId
        });
        expect(clientInDb).toBeDefined();
        // Secret in DB should NOT be the plain secret returned
        expect(clientInDb?.clientSecret).not.toBe(result.clientSecret);
        // Secret in DB should be defined
        expect(clientInDb?.clientSecret).toBeDefined();
        expect(clientInDb?.clientSecret!.length).toBeGreaterThan(50); // Bcrypt hash is long
    });

    test("Client Secret Verification", async () => {
        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "confidential",
        });

        // Correct Secret
        const isValid = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: result.clientId,
            clientSecret: result.clientSecret!,
        });
        expect(isValid).toBe(true);

        // Incorrect Secret
        const isInvalid = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: result.clientId,
            clientSecret: "wrong-secret",
        });
        expect(isInvalid).toBe(false);
    });

    test("Authorization Code: Replay Attack Prevention", async () => {
        // In component, userId is just a string (not Id<"users">)
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Flow Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public",
        });

        // Issue Code
        const code = await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: client.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: [],
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  // Changed to S256
            codeChallengeMethod: "S256",  // Changed from "plain" to "S256"
        });

        // 1. First Consumption (Success)
        await t.mutation(api.mutations.consumeAuthCode, {
            code,
            clientId: client.clientId,
            redirectUri: "https://cb",
            codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  // Changed to match S256
        });

        // 2. Second Consumption (Fail)
        const secondAttempt: any = await t.mutation(api.mutations.consumeAuthCode, {
            code,
            clientId: client.clientId,
            redirectUri: "https://cb",
            codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  // Changed to match S256
        });
        expect(secondAttempt.error).toBe("authorization_code_reuse_detected");
    });

    test("Authorization Code: Wrong client does not consume code", async () => {
        const userId = "test-user-id";
        const clientA = await t.mutation(api.clientManagement.registerClient, {
            name: "Client A",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public",
        });
        const clientB = await t.mutation(api.clientManagement.registerClient, {
            name: "Client B",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public",
        });

        const code = await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: clientA.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: [],
            codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",  // Changed to S256
            codeChallengeMethod: "S256",  // Changed from "plain" to "S256"
        });

        await expect(t.mutation(api.mutations.consumeAuthCode, {
            code,
            clientId: clientB.clientId,
            redirectUri: "https://cb",
            codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  // Changed to match S256
        })).rejects.toThrow();

        await t.mutation(api.mutations.consumeAuthCode, {
            code,
            clientId: clientA.clientId,
            redirectUri: "https://cb",
            codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",  // Changed to match S256
        });
    });

    test("PKCE: S256 Calculation Helper", async () => {
        // Verify our test helper usage for S256
        const codeVerifier = "abcdefghijklmnopqrstuvwxyz1234567890abcdef"; // > 43 chars
        const encoder = new TextEncoder();
        const data = encoder.encode(codeVerifier);
        const hashBuffer = await crypto.subtle.digest("SHA-256", data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const codeChallenge = btoa(String.fromCharCode(...hashArray))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=+$/, '');

        expect(codeChallenge).toBeDefined();
    });

    // ==========================================
    // Phase 1b: Handler Error Mapping
    // ==========================================

    test("Token Handler: invalid_grant is not mapped to invalid_request", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: [],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
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
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "client",
                code: "code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_grant");
    });

    test("Token Handler: invalid_client is not mapped to invalid_request", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: [],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => {
                    throw new Error("invalid_client");
                },
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "client",
                code: "code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("invalid_client");
    });

    test("Token Handler: sets no-store headers on error responses", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
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
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: "code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.headers.get("Cache-Control")).toBe("no-store");
        expect(response.headers.get("Pragma")).toBe("no-cache");
    });

    test("Token Handler: authorization_code grant issues tokens with ID token and refresh token", async () => {
        // Generate valid RSA key pair for JWT signing
        const { privateKey, publicKey } = await generateKeyPair("RS256");
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const jwks = JSON.stringify({ keys: [{ ...jwk, kid: "test-key", use: "sig", alg: "RS256" }] });

        const config: OAuthConfig = {
            privateKey: privateKeyPem,
            jwks,
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client-1",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "profile", "offline_access"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "user-123",
                    scopes: ["openid", "profile", "offline_access"],
                    codeChallenge: "challenge",
                    codeChallengeMethod: "S256",
                    redirectUri: "https://cb",
                    nonce: "test-nonce-123",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "auth-id",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client-1",
                    clientIdIssuedAt: Date.now(),
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: "test-code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
                client_id: "client-1",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.access_token).toBeDefined();
        expect(body.token_type).toBe("Bearer");
        expect(body.expires_in).toBe(3600);
        expect(body.scope).toBe("openid profile offline_access");
        expect(body.id_token).toBeDefined(); // OIDC ID token should be present
        expect(body.refresh_token).toBeDefined(); // Refresh token should be present
    });

    test("Token Handler: confidential client requires client_secret", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "confidential-client",
                    type: "confidential",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "user-123",
                    scopes: ["openid"],
                    codeChallenge: "challenge",
                    codeChallengeMethod: "S256",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "auth-id",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "confidential-client",
                    clientIdIssuedAt: Date.now(),
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: "test-code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
                client_id: "confidential-client",
                // No client_secret
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("invalid_client");
        expect(body.error_description).toBe("client_secret required");
    });

    test("Token Handler: confidential client rejects invalid client_secret", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "confidential-client",
                    type: "confidential",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "user-123",
                    scopes: ["openid"],
                    codeChallenge: "challenge",
                    codeChallengeMethod: "S256",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "auth-id",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "confidential-client",
                    clientIdIssuedAt: Date.now(),
                }),
                verifyClientSecret: async () => false, // Invalid secret
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                code: "test-code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
                client_id: "confidential-client",
                client_secret: "wrong-secret",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("invalid_client");
        expect(body.error_description).toBe("Invalid client secret");
    });

    test("Token Handler: authorization_code grant requires code, redirect_uri, and code_verifier", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "user-123",
                    scopes: ["openid"],
                    codeChallenge: "challenge",
                    codeChallengeMethod: "S256",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "auth-id",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: Date.now(),
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "client",
                // Missing code, redirect_uri, code_verifier
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toBe("Missing code parameters");
    });

    test("Authorize Handler: rejects unsupported response_type", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=token&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc", {
            method: "GET",
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("unsupported_response_type");
        expect(redirect.searchParams.get("error_description")).toBe("response_type must be code");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: rejects empty scope", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&state=abc", {
            method: "GET",
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toBe("scope required");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: rejects missing code_challenge", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc", {
            method: "GET",
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toBe("code_challenge required");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: rejects when consent is not approved", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("access_denied");
        expect(redirect.searchParams.get("error_description")).toBe("User consent required");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: rejects invalid scope", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "profile"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid%20admin&state=abc&consent=approve&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
            headers: {
                "Referer": "https://example.com/consent",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_scope");
        expect(redirect.searchParams.get("error_description")).toBe("Scope not allowed");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: succeeds with valid parameters", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "profile"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "auth-code-123",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid%20profile&state=state-123&consent=approve&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
            headers: {
                "Referer": "https://example.com/consent",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("code")).toBe("auth-code-123");
        expect(redirect.searchParams.get("state")).toBe("state-123");
        expect(redirect.searchParams.get("error")).toBeNull();
    });

    test("Authorize Handler: returns error when user not authenticated", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => null, // User not authenticated
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc&consent=approve&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
            headers: {
                "Referer": "https://example.com/consent",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("access_denied");
        expect(redirect.searchParams.get("error_description")).toBe("User not authenticated");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("OpenID Configuration Handler: includes registration_endpoint when allowDynamicClientRegistration is true", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };

        const request = new Request("https://example.com/.well-known/openid-configuration", {
            method: "GET",
        });

        const response = await openIdConfigurationHandler({} as any, request, config);
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.registration_endpoint).toBe("https://example.com/oauth/register");
    });

    test("OpenID Configuration Handler: uses convexSiteUrl when provided", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            convexSiteUrl: "https://backend.convex.site",
        };

        const request = new Request("https://example.com/.well-known/openid-configuration", {
            method: "GET",
        });

        const response = await openIdConfigurationHandler({} as any, request, config);
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.authorization_endpoint).toBe("https://backend.convex.site/oauth/authorize");
        expect(body.token_endpoint).toBe("https://backend.convex.site/oauth/token");
        expect(body.userinfo_endpoint).toBe("https://backend.convex.site/oauth/userinfo");
        expect(body.jwks_uri).toBe("https://backend.convex.site/oauth/.well-known/jwks.json");
    });

    test("JWKS Handler: returns valid JWKS", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"test-n\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"key-1\"}]}",
            siteUrl: "https://example.com",
        };

        const request = new Request("https://example.com/.well-known/jwks.json", {
            method: "GET",
        });

        const response = await jwksHandler({} as any, request, config);
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.keys).toBeDefined();
        expect(body.keys).toHaveLength(1);
        expect(body.keys[0].kty).toBe("RSA");
        expect(body.keys[0].n).toBe("test-n");
    });

    test("Token Handler: rejects non-POST method", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "GET",
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(405);
        expect(response.headers.get("Cache-Control")).toBe("no-store");
        expect(response.headers.get("Pragma")).toBe("no-cache");
    });

    test("Token Handler: rejects unknown client", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "authorization_code",
                client_id: "unknown-client",
                code: "code",
                redirect_uri: "https://cb",
                code_verifier: "verifier",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(401);
        const body = await response.json();
        expect(body.error).toBe("invalid_client");
        expect(body.error_description).toBe("Unknown client");
    });

    test("Authorize Handler: requires S256 code_challenge_method", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc&consent=approve&code_challenge=challenge&code_challenge_method=plain", {
            method: "GET",
            headers: {
                "Referer": "https://example.com/consent",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("invalid_request");
        expect(redirect.searchParams.get("error_description")).toBe("code_challenge_method must be S256");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Authorize Handler: denies consent from non-provider origin", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            getUserId: async () => "user-1",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&state=abc&consent=approve&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
            headers: {
                "Referer": "https://client.example.com/start",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(302);
        const location = response.headers.get("Location");
        expect(location).toBeTruthy();
        const redirect = new URL(location as string);
        expect(redirect.searchParams.get("error")).toBe("access_denied");
        expect(redirect.searchParams.get("error_description")).toBe("User consent required");
        expect(redirect.searchParams.get("state")).toBe("abc");
    });

    test("Register Handler: rejects non-POST requests", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "GET",
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(405);
        expect(await response.text()).toBe("Method Not Allowed");
    });

    test("Register Handler: rejects when DCR disabled", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: false,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://cb"],
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(403);
        const body = await response.json();
        expect(body.error).toBe("access_denied");
        expect(body.error_description).toContain("disabled");
    });

    test("Register Handler: rejects invalid scopes", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
            allowedScopes: ["openid", "profile"],
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://cb"],
                scope: "openid admin",
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_scope");
        expect(body.error_description).toContain("admin");
    });

    test("Register Handler: rejects unsupported token_endpoint_auth_method", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://cb"],
                token_endpoint_auth_method: "client_secret_basic",
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_client_metadata");
    });

    test("Register Handler: rejects empty redirect_uris", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: [],
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toContain("redirect_uris required");
    });

    test("Register Handler: rejects invalid redirect_uri", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["http://example.com/callback#fragment"],
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toContain("Invalid redirect_uri");
    });

    test("Register Handler: succeeds with public client", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "public-client",
                    clientIdIssuedAt: Date.now(),
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://example.com/callback"],
                client_name: "Public Client",
                token_endpoint_auth_method: "none",
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(201);
        const body = await response.json();
        expect(body.client_id).toBe("public-client");
        expect(body.client_secret).toBeUndefined();
        expect(body.token_endpoint_auth_method).toBe("none");
    });

    test("Register Handler: handles general errors", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => {
                    throw new Error("Database error");
                },
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://example.com/callback"],
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toContain("Database error");
    });

    test("Register Handler: succeeds with confidential client", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            allowDynamicClientRegistration: true,
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => null,
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "confidential-client",
                    clientIdIssuedAt: Date.now(),
                    clientSecret: "super-secret",
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/register", {
            method: "POST",
            body: JSON.stringify({
                redirect_uris: ["https://example.com/callback"],
                client_name: "Confidential Client",
                token_endpoint_auth_method: "client_secret_post",
            }),
            headers: { "Content-Type": "application/json" },
        });

        const response = await registerHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(201);
        const body = await response.json();
        expect(body.client_id).toBe("confidential-client");
        expect(body.client_secret).toBe("super-secret");
        expect(body.client_secret_expires_at).toBe(0);
        expect(body.token_endpoint_auth_method).toBe("client_secret_post");
    });

    test("Protected Resource Handler: returns metadata", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://api.example.com",
            convexSiteUrl: "https://example.convex.site",
        };

        const request = new Request("https://example.convex.site/.well-known/oauth-protected-resource", {
            method: "GET",
        });

        const response = await oauthProtectedResourceHandler({} as any, request, config);
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.resource).toBe("https://api.example.com");
        expect(body.authorization_servers).toEqual(["https://example.convex.site/oauth"]);
        expect(body.scopes_supported).toEqual(["openid", "profile", "email", "offline_access"]);
    });

    test("Protected Resource Handler: handles custom scopes", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://api.example.com",
            allowedScopes: ["read", "write", "admin"],
        };

        const request = new Request("https://api.example.com/.well-known/oauth-protected-resource", {
            method: "GET",
        });

        const response = await oauthProtectedResourceHandler({} as any, request, config);
        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.scopes_supported).toEqual(["read", "write", "admin"]);
    });

    test("Protected Resource Handler: handles OPTIONS request", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://api.example.com",
        };

        const request = new Request("https://api.example.com/.well-known/oauth-protected-resource", {
            method: "OPTIONS",
            headers: { "Origin": "https://example.com" },
        });

        const response = await oauthProtectedResourceHandler({} as any, request, config);
        expect(response.status).toBe(200);
        expect(response.headers.get("Access-Control-Allow-Methods")).toContain("GET");
    });

    test("JWKS Handler: returns server_error on invalid JWKS", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "invalid-json",
            siteUrl: "https://example.com",
        };

        const request = new Request("https://example.com/.well-known/jwks.json", {
            method: "GET",
        });

        const response = await jwksHandler({} as any, request, config);
        expect(response.status).toBe(500);
        const body = await response.json();
        expect(body.error).toBe("server_error");
        expect(body.error_description).toBe("Failed to get JWKS");
    });

    test("JWKS Handler: handles OPTIONS request", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };

        const request = new Request("https://example.com/.well-known/jwks.json", {
            method: "OPTIONS",
            headers: { "Origin": "https://example.com" },
        });

        const response = await jwksHandler({} as any, request, config);
        expect(response.status).toBe(200);
        expect(response.headers.get("Access-Control-Allow-Methods")).toContain("GET");
    });

    test("Token Handler: rejects unsupported_grant_type", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "password",
                client_id: "client",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("unsupported_grant_type");
        expect(body.error_description).toBe("Grant type not supported");
    });

    test("Token Handler: handles rotateRefreshToken error with invalid_grant", async () => {
        // Generate valid RSA key pair for JWT signing
        const { privateKey, publicKey } = await generateKeyPair("RS256");
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const jwks = JSON.stringify({ keys: [{ ...jwk, kid: "test-key", use: "sig", alg: "RS256" }] });

        const config: OAuthConfig = {
            privateKey: privateKeyPem,
            jwks,
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "offline_access"],
                }),
                getRefreshToken: async () => ({
                    refreshToken: "old-rt",
                    clientId: "client",
                    userId: "user-1",
                    scopes: ["openid", "offline_access"],
                    refreshTokenExpiresAt: Date.now() + 86400000,
                }),
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => {
                    throw new Error("invalid_grant");
                },
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "client",
                refresh_token: "old-rt",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_grant");
        expect(body.error_description).toBe("Invalid refresh token (rotated?)");
    });

    test("Token Handler: handles rotateRefreshToken error (non-invalid_grant)", async () => {
        // Generate valid RSA key pair for JWT signing
        const { privateKey, publicKey } = await generateKeyPair("RS256");
        const privateKeyPem = await exportPKCS8(privateKey);
        const jwk = await exportJWK(publicKey);
        const jwks = JSON.stringify({ keys: [{ ...jwk, kid: "test-key", use: "sig", alg: "RS256" }] });

        const config: OAuthConfig = {
            privateKey: privateKeyPem,
            jwks,
            siteUrl: "https://example.com",
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "offline_access"],
                }),
                getRefreshToken: async () => ({
                    refreshToken: "old-rt",
                    clientId: "client",
                    userId: "user-1",
                    scopes: ["openid", "offline_access"],
                    refreshTokenExpiresAt: Date.now() + 86400000,
                }),
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => {
                    throw new Error("Database error");
                },
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "client",
                refresh_token: "old-rt",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
        expect(body.error_description).toBe("Database error");
    });

    test("Authorize Handler: returns error when getUserId not configured", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
            // getUserId not configured
        };
        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid"],
                }),
                getRefreshToken: async () => null,
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "code",
                consumeAuthCode: async () => ({
                    userId: "u",
                    scopes: [],
                    codeChallenge: "",
                    codeChallengeMethod: "plain",
                    redirectUri: "https://cb",
                    codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({
                    clientId: "client",
                    clientIdIssuedAt: 0,
                }),
                verifyClientSecret: async () => true,
            },
        };

        const request = new Request("https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&consent=approve&code_challenge=challenge&code_challenge_method=S256", {
            method: "GET",
            headers: {
                "Referer": "https://example.com/consent",
            },
        });

        const response = await authorizeHandler({} as any, request, config, apiStub);
        expect(response.status).toBe(500);
        const body = await response.json();
        expect(body.error).toBe("server_error");
        expect(body.error_description).toBe("getUserId is not configured");
    });

    // ==========================================
    // Phase 2: Token Lifecycle
    // ==========================================

    test("Authorization Code: Expiry", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "C",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: client.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: [],
            codeChallenge: "c",
            codeChallengeMethod: "S256"  // Changed from "plain" to "S256"
        });

        const codeInDb = await t.run(async (ctx) => {
            return await ctx.db.query("oauthCodes").first();
        });
        expect(codeInDb?.expiresAt).toBeGreaterThan(Date.now());
    });

    test("Refresh Token: Rotation (Atomic Swap)", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "C",
            redirectUris: ["https://cb"],
            scopes: ["openid"],  // Added "openid" scope
            type: "public"
        });

        const oldRefreshToken = "old_rt";
        const newRefreshToken = "new_rt";
        const accessToken = "at";

        // 1. Initial State
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "old_at",
            refreshToken: oldRefreshToken,
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        // 2. Rotate
        await t.mutation(api.mutations.rotateRefreshToken, {
            oldRefreshToken: oldRefreshToken,
            accessToken,
            refreshToken: newRefreshToken,
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        // 3. Verify Old Token Gone (tokens are stored as hashes)
        const oldTokenHash = await hashToken(oldRefreshToken);
        const oldTokenRecord = await t.run(async (ctx) => {
            return await ctx.db.query("oauthTokens")
                .filter(q => q.eq(q.field("refreshToken"), oldTokenHash))
                .first();
        });
        expect(oldTokenRecord).toBeNull();

        // 4. Verify New Token Exists (stored as hash)
        const newTokenHash = await hashToken(newRefreshToken);
        const newTokenRecord = await t.run(async (ctx) => {
            return await ctx.db.query("oauthTokens")
                .filter(q => q.eq(q.field("refreshToken"), newTokenHash))
                .first();
        });
        expect(newTokenRecord).toBeDefined();
        // Verify accessToken is stored as hash, not plaintext
        expect(newTokenRecord?.accessToken).toBe(await hashToken(accessToken));

        // 5. Replay Attack (Try to rotate old token again)
        await expect(t.mutation(api.mutations.rotateRefreshToken, {
            oldRefreshToken: oldRefreshToken, // Already used/deleted
            accessToken: "at2",
            refreshToken: "rt2",
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        })).rejects.toThrow(); // Should fail "invalid_grant"
    });

    // ==========================================
    // Phase 3: Client Management
    // ==========================================

    test("Public Client Registration (No Secret)", async () => {
        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "Public App",
            redirectUris: ["https://app.example.com/callback"],
            scopes: ["openid"],
            type: "public",
        });

        expect(result.clientId).toBeDefined();
        expect(result.clientSecret).toBeUndefined();

        const clientInDb = await t.query(api.queries.getClient, {
            clientId: result.clientId
        });
        expect(clientInDb?.clientSecret).toBeUndefined();
    });

    test("Client Registration: rejects invalid redirect URIs", async () => {
        await expect(t.mutation(api.clientManagement.registerClient, {
            name: "Bad Redirect",
            redirectUris: ["http://example.com/callback"],
            scopes: ["openid"],
            type: "public",
        })).rejects.toThrow();
    });

    test("Client Deletion", async () => {
        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "To Delete",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public",
        });

        // Verify exists
        const beforeDelete = await t.query(api.queries.getClient, {
            clientId: result.clientId
        });
        expect(beforeDelete).toBeDefined();

        // Delete
        await t.mutation(api.mutations.deleteClient, {
            clientId: result.clientId
        });

        // Verify gone
        const afterDelete = await t.query(api.queries.getClient, {
            clientId: result.clientId
        });
        expect(afterDelete).toBeNull();
    });

    // ==========================================
    // Phase 4: Query Tests
    // ==========================================

    test("Query: getRefreshToken", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        const refreshToken = "refresh_token_123";
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "access_token",
            refreshToken,
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        const token = await t.query(api.queries.getRefreshToken, {
            refreshToken
        });
        expect(token).toBeDefined();
        expect(token?.userId).toBe(userId);
        expect(token?.clientId).toBe(client.clientId);
    });

    test("Query: listClients", async () => {
        await t.mutation(api.clientManagement.registerClient, {
            name: "Client 1",
            redirectUris: ["https://cb1"],
            scopes: [],
            type: "public"
        });
        await t.mutation(api.clientManagement.registerClient, {
            name: "Client 2",
            redirectUris: ["https://cb2"],
            scopes: [],
            type: "confidential"
        });

        const clients = await t.query(api.queries.listClients, {});
        expect(clients.length).toBeGreaterThanOrEqual(2);
    });

    test("Query: listTokensByUser", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        await t.mutation(api.mutations.saveTokens, {
            accessToken: "at1",
            refreshToken: "rt1",
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        const tokens = await t.query(api.queries.getTokensByUser, {
            userId
        });
        expect(tokens.length).toBeGreaterThan(0);
        expect(tokens[0].userId).toBe(userId);
    });

    test("Query: getAuthorization", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid", "profile"]
        });

        const auth = await t.query(api.queries.getAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(auth).toBeDefined();
        expect(auth?.scopes).toContain("openid");
        expect(auth?.scopes).toContain("profile");
    });

    test("Query: hasAuthorization", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        // Before authorization
        const hasBefore = await t.query(api.queries.hasAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(hasBefore).toBe(false);

        // Create authorization
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });

        // After authorization
        const hasAfter = await t.query(api.queries.hasAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(hasAfter).toBe(true);
    });

    test("Query: hasAnyAuthorization", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        // No authorizations yet
        const hasNone = await t.query(api.queries.hasAnyAuthorization, {
            userId
        });
        expect(hasNone).toBe(false);

        // Create authorization
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });

        // Has authorization now
        const hasAny = await t.query(api.queries.hasAnyAuthorization, {
            userId
        });
        expect(hasAny).toBe(true);
    });

    test("Query: listUserAuthorizations", async () => {
        const userId = "user-1";
        const client1 = await t.mutation(api.clientManagement.registerClient, {
            name: "Client 1",
            redirectUris: ["https://cb1"],
            scopes: [],
            type: "public"
        });
        const client2 = await t.mutation(api.clientManagement.registerClient, {
            name: "Client 2",
            redirectUris: ["https://cb2"],
            scopes: [],
            type: "public"
        });

        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client1.clientId,
            scopes: ["openid"]
        });
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client2.clientId,
            scopes: ["profile"]
        });

        const auths = await t.query(api.queries.listUserAuthorizations, {
            userId
        });
        expect(auths.length).toBe(2);
    });

    test("Query: listUserAuthorizations with client info", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public",
            description: "Test Description",
            website: "https://example.com"
        });

        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });

        const auths = await t.query(api.queries.listUserAuthorizations, {
            userId
        });
        expect(auths.length).toBe(1);
        expect(auths[0].clientName).toBe("Test Client");
        expect(auths[0].clientWebsite).toBe("https://example.com");
    });

    test("Authorization: upsertAuthorization (merge scopes)", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        // First authorization
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });

        // Second authorization (should merge scopes)
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["profile"]
        });

        const auth = await t.query(api.queries.getAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(auth?.scopes).toContain("openid");
        expect(auth?.scopes).toContain("profile");
    });

    test("Authorization: updateAuthorizationLastUsed", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });

        const before = await t.query(api.queries.getAuthorization, {
            userId,
            clientId: client.clientId
        });
        const beforeTime = before?.lastUsedAt;

        // Wait a bit
        await new Promise(resolve => setTimeout(resolve, 10));

        await t.mutation(api.mutations.updateAuthorizationLastUsed, {
            userId,
            clientId: client.clientId
        });

        const after = await t.query(api.queries.getAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(after?.lastUsedAt).toBeGreaterThan(beforeTime!);
    });

    test("Authorization: revokeAuthorization", async () => {
        const userId = "user-1";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Client",
            redirectUris: ["https://cb"],
            scopes: [],
            type: "public"
        });

        // Create authorization and tokens
        await t.mutation(api.mutations.upsertAuthorization, {
            userId,
            clientId: client.clientId,
            scopes: ["openid"]
        });
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "at",
            refreshToken: "rt",
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        // Revoke
        const result = await t.mutation(api.mutations.revokeAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(result.authorizationDeleted).toBe(true);
        expect(result.tokensDeleted).toBeGreaterThan(0);

        // Verify authorization gone
        const auth = await t.query(api.queries.getAuthorization, {
            userId,
            clientId: client.clientId
        });
        expect(auth).toBeNull();

        // Verify tokens gone
        const tokens = await t.query(api.queries.getTokensByUser, {
            userId
        });
        expect(tokens.length).toBe(0);
    });

    async function createUserInfoFixture(
        scopes: string[],
        options: { clientId?: string } = {}
    ) {
        const { publicKey, privateKey } = await generateKeyPair("RS256");
        const jwk = await exportJWK(publicKey);
        const jwks = JSON.stringify({
            keys: [{
                ...jwk,
                kid: "default-key",
                use: "sig",
                alg: "RS256",
            }],
        });
        const privateKeyPem = await exportPKCS8(privateKey);
        const config: OAuthConfig = {
            privateKey: privateKeyPem,
            jwks,
            siteUrl: "https://example.com",
        };
        const payload: Record<string, unknown> = {
            scp: scopes.join(" "),
        };
        if (options.clientId) {
            payload.cid = options.clientId;
        }
        const token = await new SignJWT({
            ...payload,
        })
            .setProtectedHeader({ alg: "RS256", kid: "default-key" })
            .setIssuedAt()
            .setSubject("user-1")
            .setAudience("convex")
            .setIssuer("https://example.com/oauth")
            .setExpirationTime("1h")
            .sign(privateKey);

        return { config, token };
    }

    test("UserInfo: revoked authorization returns invalid_token", async () => {
        const { config, token } = await createUserInfoFixture(["openid"], { clientId: "client-1" });
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const checkAuthorization = vi.fn(async () => false);
        const response = await userInfoHandler(
            {} as any,
            request,
            { ...config, checkAuthorization },
            async (userId) => ({ sub: userId })
        );

        expect(response.status).toBe(401);
        const header = response.headers.get("WWW-Authenticate") ?? "";
        expect(header).toContain("invalid_token");
        expect(checkAuthorization).toHaveBeenCalledWith(expect.anything(), "user-1", "client-1");
    });

    test("UserInfo: openid scope required", async () => {
        const { config, token } = await createUserInfoFixture(["profile"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
            name: "Alice",
            email: "alice@example.com",
            picture: "https://example.com/avatar.png",
            email_verified: true,
        }));

        expect(response.status).toBe(403);
        const header = response.headers.get("WWW-Authenticate") ?? "";
        expect(header).toContain("insufficient_scope");
    });

    test("UserInfo: openid only returns sub", async () => {
        const { config, token } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
            name: "Alice",
            email: "alice@example.com",
            picture: "https://example.com/avatar.png",
            email_verified: true,
        }));

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body).toEqual({ sub: "user-1" });
    });

    test("UserInfo: profile adds name and picture", async () => {
        const { config, token } = await createUserInfoFixture(["openid", "profile"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
            name: "Alice",
            email: "alice@example.com",
            picture: "https://example.com/avatar.png",
            email_verified: true,
        }));

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body).toEqual({
            sub: "user-1",
            name: "Alice",
            picture: "https://example.com/avatar.png",
        });
    });

    test("UserInfo: email adds email and email_verified", async () => {
        const { config, token } = await createUserInfoFixture(["openid", "email"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
            name: "Alice",
            email: "alice@example.com",
            picture: "https://example.com/avatar.png",
            email_verified: true,
        }));

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body).toEqual({
            sub: "user-1",
            email: "alice@example.com",
            email_verified: true,
        });
    });

    test("UserInfo: profile + email returns combined claims", async () => {
        const { config, token } = await createUserInfoFixture(["openid", "profile", "email"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
            name: "Alice",
            email: "alice@example.com",
            picture: "https://example.com/avatar.png",
            email_verified: true,
        }));

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body).toEqual({
            sub: "user-1",
            name: "Alice",
            picture: "https://example.com/avatar.png",
            email: "alice@example.com",
            email_verified: true,
        });
    });

    test("UserInfo: returns 401 when getUserProfile returns null", async () => {
        const { config, token } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: `Bearer ${token}` },
        });
        const response = await userInfoHandler({} as any, request, config, async () => null);

        expect(response.status).toBe(401);
    });

    test("UserInfo: handles OPTIONS request", async () => {
        const { config } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "OPTIONS",
            headers: { "Origin": "https://example.com" },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
        }));

        expect(response.status).toBe(200);
        expect(response.headers.get("Access-Control-Allow-Methods")).toContain("GET");
    });

    test("UserInfo: returns 401 when Authorization header is missing", async () => {
        const { config } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            // No Authorization header
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
        }));

        expect(response.status).toBe(401);
        const wwwAuth = response.headers.get("WWW-Authenticate");
        expect(wwwAuth).toContain("invalid_token");
        expect(wwwAuth).toContain("Missing bearer token");
    });

    test("UserInfo: returns 401 when Authorization header is malformed", async () => {
        const { config } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: "Basic sometoken" }, // Not Bearer
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
        }));

        expect(response.status).toBe(401);
        const wwwAuth = response.headers.get("WWW-Authenticate");
        expect(wwwAuth).toContain("invalid_token");
        expect(wwwAuth).toContain("Missing bearer token");
    });

    test("UserInfo: returns 401 when token verification fails", async () => {
        const { config } = await createUserInfoFixture(["openid"]);
        const request = new Request("https://example.com/oauth/userinfo", {
            method: "GET",
            headers: { Authorization: "Bearer invalid-token" },
        });
        const response = await userInfoHandler({} as any, request, config, async (userId) => ({
            sub: userId,
        }));

        expect(response.status).toBe(401);
        const wwwAuth = response.headers.get("WWW-Authenticate");
        expect(wwwAuth).toContain("invalid_token");
        expect(wwwAuth).toContain("Token verification failed");
    });

    // ==========================================
    // Phase: Refresh Token Grant Tests
    // ==========================================

    // Removed: offline_access is no longer required for refresh_token grant (RFC non-compliant)

    test("Token Handler: refresh_token grant rejects expired refresh token", async () => {
        const config: OAuthConfig = {
            privateKey: "dummy",
            jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "offline_access"],
                }),
                getRefreshToken: async () => ({
                    userId: "user-1",
                    clientId: "client",
                    scopes: ["openid", "offline_access"],
                    expiresAt: Date.now() + 3600000,
                    refreshTokenExpiresAt: Date.now() - 1000, // Expired
                }),
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({ userId: "", scopes: [], codeChallenge: "", codeChallengeMethod: "", redirectUri: "", nonce: undefined,
codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({ clientId: "", clientIdIssuedAt: 0 }),
                verifyClientSecret: async () => false,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "client",
                refresh_token: "test-refresh-token",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_grant");
        expect(body.error_description).toBe("Refresh token expired");
    });

    test("Token Handler: refresh_token grant succeeds with offline_access scope", async () => {
        const { privateKey, publicKey } = await generateKeyPair("RS256");
        const privateKeyPEM = await exportPKCS8(privateKey);
        const publicJWK = await exportJWK(publicKey);

        const jwks = JSON.stringify({
            keys: [{ ...publicJWK, use: "sig", alg: "RS256", kid: "default-key" }],
        });

        const config: OAuthConfig = {
            privateKey: privateKeyPEM,
            jwks,
            siteUrl: "https://example.com",
        };

        const apiStub: OAuthComponentAPI = {
            queries: {
                getClient: async () => ({
                    clientId: "client",
                    type: "public",
                    redirectUris: ["https://cb"],
                    allowedScopes: ["openid", "profile", "offline_access"],
                }),
                getRefreshToken: async () => ({
                    userId: "user-1",
                    clientId: "client",
                    scopes: ["openid", "profile", "offline_access"], // Has offline_access
                    expiresAt: Date.now() + 3600000,
                    refreshTokenExpiresAt: Date.now() + 864000000,
                }),
                getTokensByUser: async () => [],
            },
            mutations: {
                issueAuthorizationCode: async () => "",
                consumeAuthCode: async () => ({ userId: "", scopes: [], codeChallenge: "", codeChallengeMethod: "", redirectUri: "", nonce: undefined,
codeHash: "test-code-hash",
}),
                saveTokens: async () => undefined,
                rotateRefreshToken: async () => undefined,
                upsertAuthorization: async () => "",
                updateAuthorizationLastUsed: async () => undefined,
            },
            clientManagement: {
                registerClient: async () => ({ clientId: "", clientIdIssuedAt: 0 }),
                verifyClientSecret: async () => false,
            },
        };

        const request = new Request("https://example.com/oauth/token", {
            method: "POST",
            body: new URLSearchParams({
                grant_type: "refresh_token",
                client_id: "client",
                refresh_token: "test-refresh-token",
            }),
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
        });

        const response = await tokenHandler({} as any, request, config, apiStub);

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.access_token).toBeDefined();
        expect(body.refresh_token).toBeDefined(); // Should receive new refresh token
        expect(body.token_type).toBe("Bearer");
    });

    // ==========================================
    // Phase: Mutations Coverage Tests
    // ==========================================

    test("consumeAuthCode: rejects redirectUri mismatch", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        const code = await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: client.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: ["openid"],
            codeChallenge: "challenge",
            codeChallengeMethod: "S256"
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code,
                clientId: client.clientId,
                redirectUri: "https://wrong-redirect",
                codeVerifier: "verifier",
            })
        ).rejects.toThrow("redirect_uri_mismatch");
    });

    test("consumeAuthCode: rejects S256 PKCE verification failure", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        const code = await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: client.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: ["openid"],
            codeChallenge: "correct-challenge",
            codeChallengeMethod: "S256"
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code,
                clientId: client.clientId,
                redirectUri: "https://cb",
                codeVerifier: "wrong-verifier",
            })
        ).rejects.toThrow("invalid_code_verifier");
    });

    test("consumeAuthCode: rejects plain PKCE verification failure", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        // Create code with plain PKCE method directly in DB (since issueAuthorizationCode rejects plain)
        const code = "plain-pkce-code-123";
        await t.run(async (ctx) => {
            await ctx.db.insert("oauthCodes", {
                code,
                clientId: client.clientId,
                userId,
                redirectUri: "https://cb",
                scopes: ["openid"],
                codeChallenge: "correct-challenge",
                codeChallengeMethod: "plain",
                expiresAt: Date.now() + 600000,
            });
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code,
                clientId: client.clientId,
                redirectUri: "https://cb",
                codeVerifier: "wrong-verifier",
            })
        ).rejects.toThrow("invalid_code_verifier");
    });

    test("consumeAuthCode: rejects expired code", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        // Create expired code directly in DB
        const code = "expired-code-123";
        await t.run(async (ctx) => {
            await ctx.db.insert("oauthCodes", {
                code,
                clientId: client.clientId,
                userId,
                redirectUri: "https://cb",
                scopes: ["openid"],
                codeChallenge: "challenge",
                codeChallengeMethod: "S256",
                expiresAt: Date.now() - 1000, // Expired
            });
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code,
                clientId: client.clientId,
                redirectUri: "https://cb",
                codeVerifier: "verifier",
            })
        ).rejects.toThrow("invalid_grant");
    });

    test("consumeAuthCode: rejects invalid PKCE method", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        // Create code with invalid PKCE method directly in DB
        const code = "invalid-method-code-123";
        await t.run(async (ctx) => {
            await ctx.db.insert("oauthCodes", {
                code,
                clientId: client.clientId,
                userId,
                redirectUri: "https://cb",
                scopes: ["openid"],
                codeChallenge: "challenge",
                codeChallengeMethod: "MD5", // Invalid method
                expiresAt: Date.now() + 600000,
            });
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code,
                clientId: client.clientId,
                redirectUri: "https://cb",
                codeVerifier: "verifier",
            })
        ).rejects.toThrow("unsupported_code_challenge_method");
    });

    test("rotateRefreshToken: rejects client mismatch", async () => {
        const userId = "test-user-id";
        const client1 = await t.mutation(api.clientManagement.registerClient, {
            name: "Client 1",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });
        const client2 = await t.mutation(api.clientManagement.registerClient, {
            name: "Client 2",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        const oldRefreshToken = "old_rt";
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "old_at",
            refreshToken: oldRefreshToken,
            clientId: client1.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        await expect(
            t.mutation(api.mutations.rotateRefreshToken, {
                oldRefreshToken,
                accessToken: "new_at",
                refreshToken: "new_rt",
                clientId: client2.clientId, // Wrong client
                userId,
                scopes: ["openid"],
                expiresAt: Date.now() + 3600000,
                refreshTokenExpiresAt: Date.now() + 864000000,
            })
        ).rejects.toThrow("invalid_grant");
    });

    test("rotateRefreshToken: rejects user mismatch", async () => {
        const userId1 = "user-1";
        const userId2 = "user-2";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        const oldRefreshToken = "old_rt";
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "old_at",
            refreshToken: oldRefreshToken,
            clientId: client.clientId,
            userId: userId1,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
            refreshTokenExpiresAt: Date.now() + 864000000,
        });

        await expect(
            t.mutation(api.mutations.rotateRefreshToken, {
                oldRefreshToken,
                accessToken: "new_at",
                refreshToken: "new_rt",
                clientId: client.clientId,
                userId: userId2, // Wrong user
                scopes: ["openid"],
                expiresAt: Date.now() + 3600000,
                refreshTokenExpiresAt: Date.now() + 864000000,
            })
        ).rejects.toThrow("invalid_grant");
    });

    test("deleteClient: rejects when client not found", async () => {
        await expect(
            t.mutation(api.mutations.deleteClient, {
                clientId: "non-existent-client",
            })
        ).rejects.toThrow("Client not found");
    });

    // ==========================================
    // Phase: Client Management Coverage Tests
    // ==========================================

    test("registerClient: rejects empty redirect_uris", async () => {
        await expect(
            t.mutation(api.clientManagement.registerClient, {
                name: "Test Client",
                redirectUris: [],
                scopes: ["openid"],
                type: "public"
            })
        ).rejects.toThrow("redirect_uris required");
    });

    test("registerClient: rejects invalid redirect_uri (unparseable)", async () => {
        await expect(
            t.mutation(api.clientManagement.registerClient, {
                name: "Test Client",
                redirectUris: ["not-a-valid-url"],
                scopes: ["openid"],
                type: "public"
            })
        ).rejects.toThrow("Invalid redirect_uri");
    });

    test("verifyClientSecret: returns false when client not found", async () => {
        const result = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: "non-existent-client",
            clientSecret: "secret"
        });
        expect(result).toBe(false);
    });

    test("verifyClientSecret: returns false when client has no secret", async () => {
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Public Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        const result = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: client.clientId,
            clientSecret: "any-secret"
        });
        expect(result).toBe(false);
    });

    test("verifyClientSecret: returns false on bcrypt error", async () => {
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Confidential Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "confidential"
        });

        // Corrupt the client secret in DB to trigger bcrypt error
        await t.run(async (ctx) => {
            const clientInDb = await ctx.db.query("oauthClients")
                .filter((q) => q.eq(q.field("clientId"), client.clientId))
                .unique();
            if (clientInDb) {
                await ctx.db.patch(clientInDb._id, {
                    clientSecret: "invalid-bcrypt-hash"
                });
            }
        });

        const result = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: client.clientId,
            clientSecret: client.clientSecret!
        });
        expect(result).toBe(false);
    });

    test("deleteClient: deletes client with all associated data", async () => {
        const userId = "test-user-id";
        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Test Client",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
            type: "public"
        });

        // Create associated data
        await t.mutation(api.mutations.issueAuthorizationCode, {
            clientId: client.clientId,
            userId,
            redirectUri: "https://cb",
            scopes: ["openid"],
            codeChallenge: "challenge",
            codeChallengeMethod: "S256"
        });

        await t.mutation(api.mutations.saveTokens, {
            accessToken: "test-token",
            clientId: client.clientId,
            userId,
            scopes: ["openid"],
            expiresAt: Date.now() + 3600000,
        });

        // Delete client
        const result = await t.mutation(api.clientManagement.deleteClient, {
            clientId: client.clientId,
        });
        expect(result.success).toBe(true);

        // Verify client deleted
        const clientInDb = await t.query(api.queries.getClient, {
            clientId: client.clientId,
        });
        expect(clientInDb).toBeNull();

        // Verify associated data deleted
        const tokens = await t.run(async (ctx) => {
            return await ctx.db.query("oauthTokens")
                .filter(q => q.eq(q.field("clientId"), client.clientId))
                .collect();
        });
        expect(tokens).toHaveLength(0);

        const codes = await t.run(async (ctx) => {
            return await ctx.db.query("oauthCodes")
                .filter(q => q.eq(q.field("clientId"), client.clientId))
                .collect();
        });
        expect(codes).toHaveLength(0);
    });
});
