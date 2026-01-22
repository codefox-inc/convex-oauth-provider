import { describe, test, expect } from "vitest";
import { hashToken, verifyToken, isHashedToken } from "../token_security";

describe("Token Security", () => {
    describe("hashToken", () => {
        test("should hash a token to SHA-256", async () => {
            const token = "my-secret-token";
            const hash = await hashToken(token);

            expect(hash).toBeDefined();
            expect(typeof hash).toBe("string");
            expect(hash).not.toBe(token);
            expect(hash.length).toBe(64); // SHA-256 hex is 64 chars
        });

        test("should produce same hash for same token", async () => {
            const token = "consistent-token";
            const hash1 = await hashToken(token);
            const hash2 = await hashToken(token);

            expect(hash1).toBe(hash2);
        });

        test("should produce different hashes for different tokens", async () => {
            const token1 = "token1";
            const token2 = "token2";
            const hash1 = await hashToken(token1);
            const hash2 = await hashToken(token2);

            expect(hash1).not.toBe(hash2);
        });

        test("should handle empty string", async () => {
            const hash = await hashToken("");
            expect(hash).toBeDefined();
            expect(hash.length).toBe(64);
        });

        test("should handle long tokens", async () => {
            const longToken = "a".repeat(1000);
            const hash = await hashToken(longToken);
            expect(hash).toBeDefined();
            expect(hash.length).toBe(64);
        });
    });

    describe("verifyToken", () => {
        test("should verify matching token and hash", async () => {
            const token = "my-token";
            const hash = await hashToken(token);
            const isValid = await verifyToken(token, hash);

            expect(isValid).toBe(true);
        });

        test("should reject non-matching token and hash", async () => {
            const token1 = "correct-token";
            const token2 = "wrong-token";
            const hash = await hashToken(token1);
            const isValid = await verifyToken(token2, hash);

            expect(isValid).toBe(false);
        });

        test("should handle empty token", async () => {
            const emptyHash = await hashToken("");
            const isValid = await verifyToken("", emptyHash);
            expect(isValid).toBe(true);
        });

        test("should reject when hash is invalid", async () => {
            const isValid = await verifyToken("any-token", "invalid-hash");
            expect(isValid).toBe(false);
        });
    });

    describe("isHashedToken", () => {
        test("should return true for SHA-256 hash (64 hex chars)", () => {
            const hash = "a".repeat(64);
            expect(isHashedToken(hash)).toBe(true);
        });

        test("should return false for non-hash strings", () => {
            expect(isHashedToken("plaintext-token")).toBe(false);
            expect(isHashedToken("short")).toBe(false);
            expect(isHashedToken("a".repeat(63))).toBe(false); // 63 chars
            expect(isHashedToken("a".repeat(65))).toBe(false); // 65 chars
        });

        test("should return false for non-hex characters", () => {
            const notHex = "g".repeat(64); // 'g' is not hex
            expect(isHashedToken(notHex)).toBe(false);
        });

        test("should return true for valid lowercase hex hash", () => {
            const hash = "0123456789abcdef".repeat(4); // 64 hex chars
            expect(isHashedToken(hash)).toBe(true);
        });

        test("should return false for uppercase hex hash", () => {
            const hash = "0123456789ABCDEF".repeat(4); // 64 hex chars but uppercase
            expect(isHashedToken(hash)).toBe(false); // Implementation only accepts lowercase
        });

        test("should return false for empty string", () => {
            expect(isHashedToken("")).toBe(false);
        });

        test("should return false for null/undefined", () => {
            expect(isHashedToken(null as any)).toBe(false);
            expect(isHashedToken(undefined as any)).toBe(false);
        });
    });

    describe("Integration: Hash and Verify Flow", () => {
        test("should complete full hash-verify cycle", async () => {
            const originalToken = "access_token_xyz123";

            // 1. Hash the token
            const hashedToken = await hashToken(originalToken);
            expect(hashedToken).toBeDefined();
            expect(isHashedToken(hashedToken)).toBe(true);

            // 2. Verify with correct token
            const isValidCorrect = await verifyToken(originalToken, hashedToken);
            expect(isValidCorrect).toBe(true);

            // 3. Verify with wrong token
            const isValidWrong = await verifyToken("wrong_token", hashedToken);
            expect(isValidWrong).toBe(false);
        });
    });
});
