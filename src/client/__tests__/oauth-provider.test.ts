import { describe, test, expect, vi } from "vitest";
import { OAuthProvider } from "../index";

const component = {
    queries: {
        getClient: "getClient",
        getRefreshToken: "getRefreshToken",
        getTokensByUser: "getTokensByUser",
        getAuthorization: "getAuthorization",
        hasAuthorization: "hasAuthorization",
        hasAnyAuthorization: "hasAnyAuthorization",
        listUserAuthorizations: "listUserAuthorizations",
    },
    mutations: {
        issueAuthorizationCode: "issueAuthorizationCode",
        upsertAuthorization: "upsertAuthorization",
        consumeAuthCode: "consumeAuthCode",
        saveTokens: "saveTokens",
        rotateRefreshToken: "rotateRefreshToken",
        updateAuthorizationLastUsed: "updateAuthorizationLastUsed",
        revokeAuthorization: "revokeAuthorization",
    },
    clientManagement: {
        registerClient: "registerClient",
        verifyClientSecret: "verifyClientSecret",
    },
};

const config = {
    privateKey: "key",
    jwks: "{\"keys\":[{\"kty\":\"RSA\",\"n\":\"n\",\"e\":\"AQAB\"}]}",
    siteUrl: "https://example.com",
};

describe("OAuthProvider", () => {
    describe("constructor", () => {
        test("should initialize with component and config", () => {
            const provider = new OAuthProvider(component as any, config);
            expect(provider).toBeDefined();
            expect(provider.getConfig()).toEqual(config);
        });
    });

    describe("getConfig", () => {
        test("should return the config", () => {
            const provider = new OAuthProvider(component as any, config);
            expect(provider.getConfig()).toEqual(config);
        });
    });

    describe("handlers", () => {
        test("should expose all handler methods", () => {
            const provider = new OAuthProvider(component as any, config);
            expect(provider.handlers.openIdConfiguration).toBeTypeOf("function");
            expect(provider.handlers.authorize).toBeTypeOf("function");
            expect(provider.handlers.jwks).toBeTypeOf("function");
            expect(provider.handlers.token).toBeTypeOf("function");
            expect(provider.handlers.userInfo).toBeTypeOf("function");
            expect(provider.handlers.register).toBeTypeOf("function");
            expect(provider.handlers.protectedResource).toBeTypeOf("function");
        });
    });

    describe("issueAuthorizationCode", () => {
        test("requires codeChallenge", async () => {
            const provider = new OAuthProvider(component as any, config);
            const ctx = { runMutation: vi.fn() };

            await expect(provider.issueAuthorizationCode(ctx as any, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
                redirectUri: "https://cb",
            })).rejects.toThrow("codeChallenge required");
        });

        test("requires S256 codeChallengeMethod", async () => {
            const provider = new OAuthProvider(component as any, config);
            const ctx = { runMutation: vi.fn() };

            await expect(provider.issueAuthorizationCode(ctx as any, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
                redirectUri: "https://cb",
                codeChallenge: "challenge",
                codeChallengeMethod: "plain",
            })).rejects.toThrow("codeChallengeMethod must be S256");
        });

        test("defaults codeChallengeMethod to S256", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async (mutationRef: string, _args: unknown) => {
                if (mutationRef === component.mutations.issueAuthorizationCode) {
                    return "code";
                }
                if (mutationRef === component.mutations.upsertAuthorization) {
                    return "auth";
                }
                return undefined;
            });
            const ctx = { runMutation };

            const code = await provider.issueAuthorizationCode(ctx as any, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
                redirectUri: "https://cb",
                codeChallenge: "challenge",
            });

            expect(code).toBe("code");
            expect(runMutation).toHaveBeenCalledWith(component.mutations.upsertAuthorization, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
            });
            expect(runMutation).toHaveBeenCalledWith(component.mutations.issueAuthorizationCode, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
                redirectUri: "https://cb",
                codeChallenge: "challenge",
                codeChallengeMethod: "S256",
            });
        });
    });

    describe("API methods", () => {
        test("getClient should call queries.getClient with clientId", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => ({ clientId: "client-1", name: "Test Client" }));
            const ctx = { runQuery };

            const result = await provider.getClient(ctx as any, "client-1");

            expect(result).toEqual({ clientId: "client-1", name: "Test Client" });
            expect(runQuery).toHaveBeenCalledWith(component.queries.getClient, { clientId: "client-1" });
        });

        test("API getRefreshToken should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => ({ refreshToken: "token" }));
            const ctx = { runQuery };

            // Access the internal API
            const api = (provider as any).api;
            await api.queries.getRefreshToken(ctx, { refreshToken: "token-hash" });

            expect(runQuery).toHaveBeenCalledWith(component.queries.getRefreshToken, { refreshToken: "token-hash" });
        });

        test("API getTokensByUser should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => [{ accessToken: "token" }]);
            const ctx = { runQuery };

            const api = (provider as any).api;
            await api.queries.getTokensByUser(ctx, { userId: "user-1" });

            expect(runQuery).toHaveBeenCalledWith(component.queries.getTokensByUser, { userId: "user-1" });
        });

        test("API consumeAuthCode should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => ({ userId: "user-1", scopes: ["openid"] }));
            const ctx = { runMutation };

            const api = (provider as any).api;
            await api.mutations.consumeAuthCode(ctx, {
                code: "code",
                clientId: "client-1",
                redirectUri: "https://cb",
                codeVerifier: "verifier"
            });

            expect(runMutation).toHaveBeenCalledWith(component.mutations.consumeAuthCode, {
                code: "code",
                clientId: "client-1",
                redirectUri: "https://cb",
                codeVerifier: "verifier"
            });
        });

        test("API saveTokens should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => undefined);
            const ctx = { runMutation };

            const api = (provider as any).api;
            await api.mutations.saveTokens(ctx, {
                accessToken: "token",
                clientId: "client-1",
                userId: "user-1",
                scopes: ["openid"],
                expiresAt: Date.now() + 3600000
            });

            expect(runMutation).toHaveBeenCalled();
        });

        test("API rotateRefreshToken should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => undefined);
            const ctx = { runMutation };

            const api = (provider as any).api;
            await api.mutations.rotateRefreshToken(ctx, {
                oldRefreshToken: "old",
                accessToken: "new-at",
                clientId: "client-1",
                userId: "user-1",
                scopes: ["openid"],
                expiresAt: Date.now() + 3600000
            });

            expect(runMutation).toHaveBeenCalled();
        });

        test("API updateAuthorizationLastUsed should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => undefined);
            const ctx = { runMutation };

            const api = (provider as any).api;
            await api.mutations.updateAuthorizationLastUsed(ctx, {
                userId: "user-1",
                clientId: "client-1"
            });

            expect(runMutation).toHaveBeenCalled();
        });

        test("API verifyClientSecret should be callable", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => true);
            const ctx = { runMutation };

            const api = (provider as any).api;
            const result = await api.clientManagement.verifyClientSecret(ctx, {
                clientId: "client-1",
                clientSecret: "secret"
            });

            expect(result).toBe(true);
            expect(runMutation).toHaveBeenCalled();
        });
    });

    describe("registerClient", () => {
        test("should call clientManagement.registerClient", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => ({ clientId: "new-client", clientSecret: "secret" }));
            const ctx = { runMutation };

            const result = await provider.registerClient(ctx as any, {
                name: "New Client",
                redirectUris: ["https://example.com/callback"],
                scopes: ["openid"],
                type: "confidential",
            });

            expect(result).toEqual({ clientId: "new-client", clientSecret: "secret" });
            expect(runMutation).toHaveBeenCalledWith(component.clientManagement.registerClient, {
                name: "New Client",
                redirectUris: ["https://example.com/callback"],
                scopes: ["openid"],
                type: "confidential",
            });
        });
    });

    describe("getTokensByUser", () => {
        test("should call queries.getTokensByUser with userId", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => [{ accessToken: "token1" }]);
            const ctx = { runQuery };

            const result = await provider.getTokensByUser(ctx as any, "user-1");

            expect(result).toEqual([{ accessToken: "token1" }]);
            expect(runQuery).toHaveBeenCalledWith(component.queries.getTokensByUser, { userId: "user-1" });
        });
    });

    describe("getAuthorization", () => {
        test("should call queries.getAuthorization", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => ({ userId: "user-1", clientId: "client-1", scopes: ["openid"] }));
            const ctx = { runQuery };

            const result = await provider.getAuthorization(ctx as any, "user-1", "client-1");

            expect(result).toEqual({ userId: "user-1", clientId: "client-1", scopes: ["openid"] });
            expect(runQuery).toHaveBeenCalledWith(component.queries.getAuthorization, { userId: "user-1", clientId: "client-1" });
        });
    });

    describe("listUserAuthorizations", () => {
        test("should call queries.listUserAuthorizations", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => [{ clientId: "client-1", scopes: ["openid"] }]);
            const ctx = { runQuery };

            const result = await provider.listUserAuthorizations(ctx as any, "user-1");

            expect(result).toEqual([{ clientId: "client-1", scopes: ["openid"] }]);
            expect(runQuery).toHaveBeenCalledWith(component.queries.listUserAuthorizations, { userId: "user-1" });
        });
    });

    describe("upsertAuthorization", () => {
        test("should call mutations.upsertAuthorization", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => "auth-id");
            const ctx = { runMutation };

            const result = await provider.upsertAuthorization(ctx as any, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
            });

            expect(result).toBe("auth-id");
            expect(runMutation).toHaveBeenCalledWith(component.mutations.upsertAuthorization, {
                userId: "user-1",
                clientId: "client-1",
                scopes: ["openid"],
            });
        });
    });

    describe("revokeAuthorization", () => {
        test("should call mutations.revokeAuthorization", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runMutation = vi.fn(async () => undefined);
            const ctx = { runMutation };

            await provider.revokeAuthorization(ctx as any, "user-1", "client-1");

            expect(runMutation).toHaveBeenCalledWith(component.mutations.revokeAuthorization, {
                userId: "user-1",
                clientId: "client-1",
            });
        });
    });

    describe("hasAuthorization", () => {
        test("should return false when authorization does not exist", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => null);
            const ctx = { runQuery };

            const result = await provider.hasAuthorization(ctx as any, "user-1", "client-1", ["openid"]);

            expect(result).toBe(false);
        });

        test("should return false when scopes are insufficient", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => ({ scopes: ["openid"] }));
            const ctx = { runQuery };

            const result = await provider.hasAuthorization(ctx as any, "user-1", "client-1", ["openid", "email"]);

            expect(result).toBe(false);
        });

        test("should return true when all scopes are authorized", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => ({ scopes: ["openid", "email", "profile"] }));
            const ctx = { runQuery };

            const result = await provider.hasAuthorization(ctx as any, "user-1", "client-1", ["openid", "email"]);

            expect(result).toBe(true);
        });
    });

    describe("checkAuthorizationValid", () => {
        test("should check specific client authorization when clientId provided", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => true);
            const ctx = { runQuery };

            const result = await provider.checkAuthorizationValid(ctx as any, "user-1", "client-1");

            expect(result).toBe(true);
            expect(runQuery).toHaveBeenCalledWith(component.queries.hasAuthorization, { userId: "user-1", clientId: "client-1" });
        });

        test("should check any authorization when clientId not provided", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => true);
            const ctx = { runQuery };

            const result = await provider.checkAuthorizationValid(ctx as any, "user-1");

            expect(result).toBe(true);
            expect(runQuery).toHaveBeenCalledWith(component.queries.hasAnyAuthorization, { userId: "user-1" });
        });
    });

    describe("createAuthorizationChecker", () => {
        test("should return a function that checks authorization", async () => {
            const provider = new OAuthProvider(component as any, config);
            const runQuery = vi.fn(async () => true);
            const ctx = { runQuery };

            const checker = provider.createAuthorizationChecker();
            const result = await checker(ctx as any, "user-1", "client-1");

            expect(result).toBe(true);
            expect(runQuery).toHaveBeenCalledWith(component.queries.hasAuthorization, { userId: "user-1", clientId: "client-1" });
        });
    });

});
