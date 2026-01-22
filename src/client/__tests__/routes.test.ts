import { describe, test, expect, vi } from "vitest";
import { registerOAuthRoutes } from "../routes";

describe("Route Registration", () => {
    // Mock HTTP router
    const createMockRouter = () => {
        const routes: Array<{ path: string; method: string; handler: any }> = [];
        return {
            router: {
                route: vi.fn((config: { path: string; method: string; handler: any }) => {
                    routes.push(config);
                }),
            },
            routes,
        };
    };

    // Mock httpAction creator
    const mockHttpAction = (handler: any) => handler;

    // Mock OAuth provider
    const createMockProvider = (config?: { prefix?: string }) => {
        const mockHandlers = {
            openIdConfiguration: vi.fn(async () => new Response("{}")),
            jwks: vi.fn(async () => new Response("{}")),
            protectedResource: vi.fn(async () => new Response("{}")),
            authorize: vi.fn(async () => new Response(null, { status: 302 })),
            token: vi.fn(async () => new Response("{}")),
            userInfo: vi.fn(async () => new Response("{}")),
            register: vi.fn(async () => new Response("{}")),
        };

        return {
            provider: {
                handlers: mockHandlers,
                getConfig: () => config,
            },
            mockHandlers,
        };
    };

    test("should register all OAuth endpoints with default prefix", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        // Expected routes (GET + OPTIONS for most, POST + OPTIONS for token/register/userinfo, GET + POST + OPTIONS for userinfo)
        const expectedPaths = [
            // Prefixed routes
            "/oauth/.well-known/openid-configuration",
            "/oauth/.well-known/oauth-authorization-server",
            "/oauth/.well-known/jwks.json",
            "/oauth/.well-known/oauth-protected-resource",
            "/oauth/authorize",
            "/oauth/token",
            "/oauth/userinfo",
            "/oauth/register",
            // Root well-known routes
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-authorization-server/oauth",
            "/.well-known/oauth-protected-resource",
        ];

        // Check all expected paths are registered
        const registeredPaths = routes.map(r => r.path);
        for (const path of expectedPaths) {
            expect(registeredPaths).toContain(path);
        }

        // Total routes: 11 paths × methods
        // - 7 GET endpoints (openid-config, oauth-auth-server, jwks, protected-resource, authorize, userinfo, root×3) × 2 (GET + OPTIONS) = 14
        // - 2 POST endpoints (token, register) × 2 (POST + OPTIONS) = 4
        // - 1 userinfo (GET + POST + OPTIONS) = 3
        expect(routes.length).toBeGreaterThan(20);
    });

    test("should register routes with custom prefix", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            prefix: "/api/auth",
        });

        const registeredPaths = routes.map(r => r.path);
        expect(registeredPaths).toContain("/api/auth/.well-known/openid-configuration");
        expect(registeredPaths).toContain("/api/auth/authorize");
        expect(registeredPaths).toContain("/api/auth/token");
        expect(registeredPaths).toContain("/api/auth/userinfo");
        expect(registeredPaths).toContain("/api/auth/register");
        expect(registeredPaths).toContain("/.well-known/oauth-authorization-server/api/auth");
    });

    test("should use prefix from provider config if not specified in options", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider({ prefix: "/custom" });

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        const registeredPaths = routes.map(r => r.path);
        expect(registeredPaths).toContain("/custom/.well-known/openid-configuration");
        expect(registeredPaths).toContain("/custom/authorize");
    });

    test("should handle root prefix", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            prefix: "/",
        });

        const registeredPaths = routes.map(r => r.path);
        expect(registeredPaths).toContain("/.well-known/openid-configuration");
        expect(registeredPaths).toContain("/authorize");
        expect(registeredPaths).toContain("/token");
        expect(registeredPaths).toContain("/.well-known/oauth-authorization-server");
    });

    test("should skip root well-known routes when disabled", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            registerRootWellKnown: false,
        });

        const registeredPaths = routes.map(r => r.path);
        expect(registeredPaths).toContain("/oauth/.well-known/openid-configuration");
        expect(registeredPaths).not.toContain("/.well-known/oauth-authorization-server");
        expect(registeredPaths).not.toContain("/.well-known/oauth-protected-resource");
    });

    test("should call custom authorizeHandler when provided", async () => {
        const { router } = createMockRouter();
        const { provider, mockHandlers } = createMockProvider();
        const customAuthorizeHandler = vi.fn(async (_ctx, _req, defaultFn) => {
            return defaultFn();
        });

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            authorizeHandler: customAuthorizeHandler,
        });

        // Find the authorize route handler
        const authorizeRoute = router.route.mock.calls.find(
            call => call[0].path === "/oauth/authorize" && call[0].method === "GET"
        );
        expect(authorizeRoute).toBeDefined();

        // Invoke the handler
        const handler = authorizeRoute![0].handler;
        const mockCtx = { auth: { getUserIdentity: async () => null } };
        const mockReq = new Request("http://localhost/oauth/authorize");
        await handler(mockCtx, mockReq);

        expect(customAuthorizeHandler).toHaveBeenCalled();
        expect(mockHandlers.authorize).toHaveBeenCalled();
    });

    test("should use default getUserProfile when not provided", async () => {
        const { router } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        // Find userinfo route
        const userInfoRoute = router.route.mock.calls.find(
            call => call[0].path === "/oauth/userinfo" && call[0].method === "GET"
        );
        expect(userInfoRoute).toBeDefined();

        // The handler should be registered
        expect(userInfoRoute![0].handler).toBeDefined();
    });

    test("should use custom getUserProfile when provided", async () => {
        const { router } = createMockRouter();
        const { provider } = createMockProvider();
        const customGetUserProfile = vi.fn(async (_ctx, userId) => ({
            sub: userId,
            name: "Test User",
            email: "test@example.com",
        }));

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            getUserProfile: customGetUserProfile,
        });

        // Find userinfo route
        const userInfoRoute = router.route.mock.calls.find(
            call => call[0].path === "/oauth/userinfo" && call[0].method === "GET"
        );
        expect(userInfoRoute).toBeDefined();

        // The handler should be registered
        expect(userInfoRoute![0].handler).toBeDefined();
    });

    test("should register GET and OPTIONS for discovery endpoints", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        const openidConfigRoutes = routes.filter(
            r => r.path === "/oauth/.well-known/openid-configuration"
        );
        expect(openidConfigRoutes).toHaveLength(2);
        expect(openidConfigRoutes.map(r => r.method)).toEqual(
            expect.arrayContaining(["GET", "OPTIONS"])
        );
    });

    test("should register POST and OPTIONS for token endpoint", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        const tokenRoutes = routes.filter(r => r.path === "/oauth/token");
        expect(tokenRoutes).toHaveLength(2);
        expect(tokenRoutes.map(r => r.method)).toEqual(
            expect.arrayContaining(["POST", "OPTIONS"])
        );
    });

    test("should register GET, POST, and OPTIONS for userinfo endpoint", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

        const userInfoRoutes = routes.filter(r => r.path === "/oauth/userinfo");
        expect(userInfoRoutes).toHaveLength(3);
        expect(userInfoRoutes.map(r => r.method)).toEqual(
            expect.arrayContaining(["GET", "POST", "OPTIONS"])
        );
    });

    test("should register routes with custom siteUrl", () => {
        const { router } = createMockRouter();
        const { provider } = createMockProvider();

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            siteUrl: "https://example.com",
        });

        // siteUrl is used internally but doesn't affect route registration
        expect(router.route).toHaveBeenCalled();
    });

    test("should handle all options combined", () => {
        const { router, routes } = createMockRouter();
        const { provider } = createMockProvider();
        const customAuthorizeHandler = vi.fn(async (_ctx, _req, defaultFn) => defaultFn());
        const customGetUserProfile = vi.fn(async (_ctx, userId) => ({ sub: userId }));

        registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
            prefix: "/api/oauth",
            getUserProfile: customGetUserProfile,
            authorizeHandler: customAuthorizeHandler,
            siteUrl: "https://example.com",
            registerRootWellKnown: false,
        });

        const registeredPaths = routes.map(r => r.path);
        expect(registeredPaths).toContain("/api/oauth/.well-known/openid-configuration");
        expect(registeredPaths).toContain("/api/oauth/authorize");
        expect(registeredPaths).toContain("/api/oauth/token");
        expect(registeredPaths).toContain("/api/oauth/userinfo");
        expect(registeredPaths).toContain("/api/oauth/register");
        expect(registeredPaths).not.toContain("/.well-known/oauth-authorization-server");
    });

    describe("Handler Execution", () => {
        test("should execute openIdConfiguration handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const openidRoute = routes.find(
                r => r.path === "/oauth/.well-known/openid-configuration" && r.method === "GET"
            );
            expect(openidRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/.well-known/openid-configuration");
            await openidRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.openIdConfiguration).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute jwks handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const jwksRoute = routes.find(
                r => r.path === "/oauth/.well-known/jwks.json" && r.method === "GET"
            );
            expect(jwksRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/.well-known/jwks.json");
            await jwksRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.jwks).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute protectedResource handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const protectedRoute = routes.find(
                r => r.path === "/oauth/.well-known/oauth-protected-resource" && r.method === "GET"
            );
            expect(protectedRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/.well-known/oauth-protected-resource");
            await protectedRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.protectedResource).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute authorize handler without custom handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const authorizeRoute = routes.find(
                r => r.path === "/oauth/authorize" && r.method === "GET"
            );
            expect(authorizeRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/authorize");
            await authorizeRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.authorize).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute token handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const tokenRoute = routes.find(
                r => r.path === "/oauth/token" && r.method === "POST"
            );
            expect(tokenRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/token", { method: "POST" });
            await tokenRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.token).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute register handler", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const registerRoute = routes.find(
                r => r.path === "/oauth/register" && r.method === "POST"
            );
            expect(registerRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/register", { method: "POST" });
            await registerRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.register).toHaveBeenCalledWith(mockCtx, mockReq);
        });

        test("should execute userInfo handler with default getUserProfile", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any);

            const userInfoRoute = routes.find(
                r => r.path === "/oauth/userinfo" && r.method === "GET"
            );
            expect(userInfoRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/userinfo");
            await userInfoRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.userInfo).toHaveBeenCalled();
        });

        test("should execute userInfo handler with custom getUserProfile", async () => {
            const { router, routes } = createMockRouter();
            const { provider, mockHandlers } = createMockProvider();
            const customGetUserProfile = vi.fn(async (_ctx, userId) => ({
                sub: userId,
                name: "Test User",
            }));

            registerOAuthRoutes(router as any, mockHttpAction as any, provider as any, {
                getUserProfile: customGetUserProfile,
            });

            const userInfoRoute = routes.find(
                r => r.path === "/oauth/userinfo" && r.method === "GET"
            );
            expect(userInfoRoute).toBeDefined();

            const mockCtx = {};
            const mockReq = new Request("http://localhost/oauth/userinfo");
            await userInfoRoute!.handler(mockCtx, mockReq);

            expect(mockHandlers.userInfo).toHaveBeenCalled();
        });
    });
});
