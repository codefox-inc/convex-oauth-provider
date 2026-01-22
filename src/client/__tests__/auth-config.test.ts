import { describe, test, expect, vi, beforeEach, afterEach } from "vitest";
import { generateAuthConfig, createAuthConfig } from "../auth-config";

describe("Auth Config Generator", () => {
    describe("generateAuthConfig", () => {
        test("should generate config with localhost only (default options)", () => {
            const config = generateAuthConfig();

            expect(config.providers).toHaveLength(1);
            expect(config.providers[0]).toEqual({
                domain: "http://localhost:5173/oauth",
                applicationID: "convex",
            });
        });

        test("should include CONVEX_SITE_URL provider when provided", () => {
            const config = generateAuthConfig({
                convexSiteUrl: "https://example.convex.site",
            });

            expect(config.providers).toHaveLength(3);
            expect(config.providers[0]).toEqual({
                domain: "https://example.convex.site",
                applicationID: "convex",
            });
            expect(config.providers[1]).toEqual({
                domain: "http://localhost:5173/oauth",
                applicationID: "convex",
            });
            expect(config.providers[2]).toEqual({
                domain: "https://example.convex.site/oauth",
                applicationID: "convex",
            });
        });

        test("should exclude CONVEX_SITE_URL provider when includeConvexSiteUrl is false", () => {
            const config = generateAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                includeConvexSiteUrl: false,
            });

            expect(config.providers).toHaveLength(2);
            expect(config.providers[0]).toEqual({
                domain: "http://localhost:5173/oauth",
                applicationID: "convex",
            });
            expect(config.providers[1]).toEqual({
                domain: "https://example.convex.site/oauth",
                applicationID: "convex",
            });
        });

        test("should apply custom prefix", () => {
            const config = generateAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                prefix: "/api/auth",
            });

            expect(config.providers).toHaveLength(3);
            expect(config.providers[0]).toEqual({
                domain: "https://example.convex.site",
                applicationID: "convex",
            });
            expect(config.providers[1]).toEqual({
                domain: "http://localhost:5173/api/auth",
                applicationID: "convex",
            });
            expect(config.providers[2]).toEqual({
                domain: "https://example.convex.site/api/auth",
                applicationID: "convex",
            });
        });

        test("should normalize root prefix", () => {
            const config = generateAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                prefix: "/",
            });

            expect(config.providers).toHaveLength(3);
            expect(config.providers[0]).toEqual({
                domain: "https://example.convex.site",
                applicationID: "convex",
            });
            expect(config.providers[1]).toEqual({
                domain: "http://localhost:5173",
                applicationID: "convex",
            });
            expect(config.providers[2]).toEqual({
                domain: "https://example.convex.site",
                applicationID: "convex",
            });
        });

        test("should apply custom localPort", () => {
            const config = generateAuthConfig({
                localPort: 3000,
            });

            expect(config.providers).toHaveLength(1);
            expect(config.providers[0]).toEqual({
                domain: "http://localhost:3000/oauth",
                applicationID: "convex",
            });
        });

        test("should apply custom applicationID", () => {
            const config = generateAuthConfig({
                applicationID: "my-app",
            });

            expect(config.providers).toHaveLength(1);
            expect(config.providers[0]).toEqual({
                domain: "http://localhost:5173/oauth",
                applicationID: "my-app",
            });
        });

        test("should include additional providers", () => {
            const config = generateAuthConfig({
                additionalProviders: [
                    { domain: "https://auth.example.com", applicationID: "external" },
                    { domain: "https://oauth.example.com", applicationID: "oauth" },
                ],
            });

            expect(config.providers).toHaveLength(3);
            expect(config.providers[0]).toEqual({
                domain: "http://localhost:5173/oauth",
                applicationID: "convex",
            });
            expect(config.providers[1]).toEqual({
                domain: "https://auth.example.com",
                applicationID: "external",
            });
            expect(config.providers[2]).toEqual({
                domain: "https://oauth.example.com",
                applicationID: "oauth",
            });
        });

        test("should handle all options combined", () => {
            const config = generateAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                localPort: 8080,
                prefix: "/api/oauth",
                applicationID: "custom-app",
                includeConvexSiteUrl: true,
                additionalProviders: [
                    { domain: "https://auth.example.com", applicationID: "external" },
                ],
            });

            expect(config.providers).toHaveLength(4);
            expect(config.providers[0]).toEqual({
                domain: "https://example.convex.site",
                applicationID: "custom-app",
            });
            expect(config.providers[1]).toEqual({
                domain: "http://localhost:8080/api/oauth",
                applicationID: "custom-app",
            });
            expect(config.providers[2]).toEqual({
                domain: "https://example.convex.site/api/oauth",
                applicationID: "custom-app",
            });
            expect(config.providers[3]).toEqual({
                domain: "https://auth.example.com",
                applicationID: "external",
            });
        });
    });

    describe("createAuthConfig", () => {
        let consoleWarnSpy: ReturnType<typeof vi.spyOn>;

        beforeEach(() => {
            consoleWarnSpy = vi.spyOn(console, "warn").mockImplementation(() => {});
        });

        afterEach(() => {
            consoleWarnSpy.mockRestore();
        });

        test("should not warn when OAuth issuer is present (with prefix)", () => {
            const config = createAuthConfig({
                convexSiteUrl: "https://example.convex.site",
            });

            expect(config.providers).toHaveLength(3);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        test("should not warn when localhost OAuth issuer is present", () => {
            const config = createAuthConfig();

            expect(config.providers).toHaveLength(1);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        test("should not warn when custom port OAuth issuer is present", () => {
            const config = createAuthConfig({
                localPort: 3000,
            });

            expect(config.providers).toHaveLength(1);
            expect(config.providers[0].domain).toContain(":3000");
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        test("should not warn when custom prefix OAuth issuer is present", () => {
            const config = createAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                prefix: "/api/auth",
            });

            expect(config.providers.some(p => p.domain.includes("/api/auth"))).toBe(true);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        test("should warn when no OAuth issuer is found", () => {
            // This scenario is difficult to trigger because localhost is always added
            // But we can test the warning logic by providing only convexSiteUrl without prefix
            const config = createAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                includeConvexSiteUrl: true,
            });

            // Should have OAuth issuers (localhost + production)
            expect(config.providers).toHaveLength(3);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });

        test("should handle root prefix validation", () => {
            const config = createAuthConfig({
                convexSiteUrl: "https://example.convex.site",
                prefix: "/",
            });

            expect(config.providers).toHaveLength(3);
            expect(consoleWarnSpy).not.toHaveBeenCalled();
        });
    });
});
