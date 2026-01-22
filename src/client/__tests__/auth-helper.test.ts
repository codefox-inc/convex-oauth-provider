import { describe, test, expect, vi } from "vitest";
import { createAuthHelper } from "../auth-helper";

describe("Auth Helper", () => {
    describe("OAuth tokens", () => {
        test("default issuer pattern rejects non-OAuth tokens", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com",
                        subject: "user-1",
                    }),
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBeNull();
        });

        test("issuer match enforces authorization check", async () => {
            const checkAuthorization = vi.fn(async () => false);
            const helper = createAuthHelper({ checkAuthorization });
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com/oauth",
                        subject: "user-1",
                        cid: "client-1",
                    }),
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBeNull();
            expect(checkAuthorization).toHaveBeenCalledWith(ctx, "user-1", "client-1");
        });

        test("issuer match returns user id when authorized", async () => {
            const checkAuthorization = vi.fn(async () => true);
            const helper = createAuthHelper({ checkAuthorization });
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com/oauth",
                        subject: "user-1",
                        cid: "client-1",
                    }),
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBe("user-1");
            expect(checkAuthorization).toHaveBeenCalledWith(ctx, "user-1", "client-1");
        });

        test("OAuth token with invalid user ID returns null", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com/oauth",
                        subject: "invalid-user",
                    }),
                },
                db: {
                    normalizeId: (_table: string, _id: string) => null,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBeNull();
        });

        test("OAuth token without checkAuthorization still validates", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com/oauth",
                        subject: "user-1",
                    }),
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBe("user-1");
        });

        test("custom oauthIssuerPattern", async () => {
            const helper = createAuthHelper({ oauthIssuerPattern: "/api/auth" });
            const ctx = {
                auth: {
                    getUserIdentity: async () => ({
                        issuer: "https://example.com/api/auth",
                        subject: "user-1",
                    }),
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBe("user-1");
        });
    });

    describe("Convex Auth", () => {
        test("getAuthUserId from config", async () => {
            const getAuthUserId = vi.fn(async () => "user-1");
            const helper = createAuthHelper({ getAuthUserId });
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBe("user-1");
            expect(getAuthUserId).toHaveBeenCalledWith(ctx);
        });

        test("getAuthUserId from parameter", async () => {
            const helper = createAuthHelper();
            const getAuthUserId = vi.fn(async () => "user-2");
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any, getAuthUserId);
            expect(userId).toBe("user-2");
            expect(getAuthUserId).toHaveBeenCalledWith(ctx);
        });

        test("handles userId|sessionId format", async () => {
            const getAuthUserId = vi.fn(async () => "user-1|session-123");
            const helper = createAuthHelper({ getAuthUserId });
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id === "user-1" ? id : null,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBe("user-1");
        });

        test("returns null when getAuthUserId returns null", async () => {
            const getAuthUserId = vi.fn(async () => null);
            const helper = createAuthHelper({ getAuthUserId });
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBeNull();
        });

        test("returns null when no getAuthUserId provided", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.getCurrentUserId(ctx as any);
            expect(userId).toBeNull();
        });
    });

    describe("getCurrentUser", () => {
        test("returns user document when authenticated", async () => {
            const getAuthUserId = vi.fn(async () => "user-1");
            const helper = createAuthHelper({ getAuthUserId });
            const mockUser = { _id: "user-1", name: "Test User" };
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                    get: vi.fn(async () => mockUser),
                },
            };

            const user = await helper.getCurrentUser(ctx as any);
            expect(user).toEqual(mockUser);
            expect(ctx.db.get).toHaveBeenCalledWith("user-1");
        });

        test("returns null when not authenticated", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                    get: vi.fn(),
                },
            };

            const user = await helper.getCurrentUser(ctx as any);
            expect(user).toBeNull();
            expect(ctx.db.get).not.toHaveBeenCalled();
        });
    });

    describe("requireAuth", () => {
        test("returns userId when authenticated", async () => {
            const getAuthUserId = vi.fn(async () => "user-1");
            const helper = createAuthHelper({ getAuthUserId });
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            const userId = await helper.requireAuth(ctx as any);
            expect(userId).toBe("user-1");
        });

        test("throws error when not authenticated", async () => {
            const helper = createAuthHelper();
            const ctx = {
                auth: {
                    getUserIdentity: async () => null,
                },
                db: {
                    normalizeId: (_table: string, id: string) => id,
                },
            };

            await expect(helper.requireAuth(ctx as any)).rejects.toThrow("Not authenticated");
        });
    });
});
