import { describe, it, expect } from "vitest";
import {
    isOAuthToken,
    getOAuthClientId,
    DEFAULT_OAUTH_ISSUER_PATTERN,
    generateCode,
    generateClientSecret
} from "../oauth";

describe("OAuth Token Helpers", () => {
    describe("DEFAULT_OAUTH_ISSUER_PATTERN", () => {
        it("should be /oauth", () => {
            expect(DEFAULT_OAUTH_ISSUER_PATTERN).toBe("/oauth");
        });
    });

    describe("isOAuthToken", () => {
        it("should return true for valid OAuth token identity", () => {
            const identity = {
                issuer: "https://example.com/oauth",
                subject: "user123",
            };
            expect(isOAuthToken(identity)).toBe(true);
        });

        it("should return true when issuer ends with /oauth", () => {
            const identity = {
                issuer: "https://my-app.convex.site/oauth",
                subject: "jh7abcdefghijk123456789",
            };
            expect(isOAuthToken(identity)).toBe(true);
        });

        it("should return false for Convex Auth identity", () => {
            const identity = {
                issuer: "https://convex.dev",
                subject: "user123",
            };
            expect(isOAuthToken(identity)).toBe(false);
        });

        it("should return false when issuer is missing", () => {
            const identity = { subject: "user123" };
            expect(isOAuthToken(identity)).toBe(false);
        });

        it("should return false when subject is missing", () => {
            const identity = { issuer: "https://example.com/oauth" };
            expect(isOAuthToken(identity)).toBe(false);
        });

        it("should return false for null identity", () => {
            expect(isOAuthToken(null)).toBe(false);
        });

        it("should return false for undefined identity", () => {
            expect(isOAuthToken(undefined)).toBe(false);
        });

        it("should accept custom issuer pattern", () => {
            const identity = {
                issuer: "https://example.com/custom-oauth-path",
                subject: "user123",
            };
            expect(isOAuthToken(identity, "/custom-oauth-path")).toBe(true);
            expect(isOAuthToken(identity, "/oauth")).toBe(false);
        });
    });

    describe("getOAuthClientId", () => {
        it("should return client ID when present", () => {
            const identity = { cid: "client123" };
            expect(getOAuthClientId(identity)).toBe("client123");
        });

        it("should return undefined when cid is missing", () => {
            const identity = {};
            expect(getOAuthClientId(identity)).toBeUndefined();
        });

        it("should return undefined for null identity", () => {
            expect(getOAuthClientId(null)).toBeUndefined();
        });

        it("should return undefined for undefined identity", () => {
            expect(getOAuthClientId(undefined)).toBeUndefined();
        });
    });

    describe("generateCode", () => {
        it("should generate a code with default length", () => {
            const code = generateCode();
            expect(code).toBeDefined();
            expect(typeof code).toBe("string");
            expect(code.length).toBeGreaterThan(0);
        });

        it("should generate a code with specified length", () => {
            const code = generateCode(32);
            expect(code).toBeDefined();
            expect(code.length).toBeGreaterThanOrEqual(32);
        });

        it("should generate different codes on each call", () => {
            const code1 = generateCode();
            const code2 = generateCode();
            expect(code1).not.toBe(code2);
        });

        it("should generate URL-safe codes", () => {
            const code = generateCode(100);
            // OAuth unreserved characters: A-Za-z0-9-._~
            expect(code).toMatch(/^[A-Za-z0-9_~.-]+$/);
        });
    });

    describe("generateClientSecret", () => {
        it("should generate a secret with default length", () => {
            const secret = generateClientSecret();
            expect(secret).toBeDefined();
            expect(typeof secret).toBe("string");
            expect(secret.length).toBeGreaterThan(0);
        });

        it("should generate a secret with specified length", () => {
            const secret = generateClientSecret(64);
            expect(secret).toBeDefined();
            expect(secret.length).toBeGreaterThanOrEqual(64);
        });

        it("should generate different secrets on each call", () => {
            const secret1 = generateClientSecret();
            const secret2 = generateClientSecret();
            expect(secret1).not.toBe(secret2);
        });

        it("should generate hex secrets", () => {
            const secret = generateClientSecret(100);
            expect(secret).toMatch(/^[A-Fa-f0-9]+$/);
        });
    });

});
