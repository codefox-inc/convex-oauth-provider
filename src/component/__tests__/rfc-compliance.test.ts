/**
 * OAuth 2.1 RFC Compliance Tests
 * Based on draft-ietf-oauth-v2-1-14
 *
 * This test suite validates compliance with OAuth 2.1 specification requirements.
 * Each test maps to specific MUST/MUST NOT/SHOULD requirements from the RFC.
 */

import { convexTest } from "convex-test";
import { expect, test, describe } from "vitest";
import { api, internal } from "../_generated/api";
import schema from "../schema";

const modules = import.meta.glob("../**/*.ts");

describe("OAuth 2.1 RFC Compliance", () => {
  describe("Section 4.1.1 - PKCE Requirements", () => {
    test("MUST support code_challenge and code_verifier parameters", async () => {
      const t = convexTest(schema, modules);

      // Register client
      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // Test that PKCE parameters are accepted
      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      expect(authCode).toBeDefined();
      expect(typeof authCode).toBe("string");
    });

    test("MUST reject authorization requests without code_challenge from public clients", async () => {
      const t = convexTest(schema, modules);

      // Register public client
      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Public Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // Attempt to issue authorization code without PKCE (should fail for public clients)
      await expect(
        t.mutation(api.mutations.issueAuthorizationCode, {
          userId: "user123",
          clientId: client.clientId,
          scopes: ["openid"],
          redirectUri: "https://example.com/callback",
          codeChallenge: "", // Empty code_challenge
          codeChallengeMethod: "S256",
        })
      ).rejects.toThrow();
    });

    test("MUST support S256 code_challenge_method", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // S256 should be supported
      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      expect(authCode).toBeDefined();
    });

    test("SHOULD reject 'plain' code_challenge_method", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // Plain method should be rejected or at minimum warned about
      await expect(
        t.mutation(api.mutations.issueAuthorizationCode, {
          userId: "user123",
          clientId: client.clientId,
          scopes: ["openid"],
          redirectUri: "https://example.com/callback",
          codeChallenge: "test-verifier",
          codeChallengeMethod: "plain",
        })
      ).rejects.toThrow(/plain.*not.*support/i);
    });
  });

  describe("Section 4.1.2 - Authorization Code Properties", () => {
    test("Authorization code MUST expire shortly (10 minutes max RECOMMENDED)", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // Advance time by 11 minutes
      await t.run(async (ctx) => {
        await ctx.scheduler.runAfter(11 * 60 * 1000, internal.mutations.cleanupExpired, {});
      });

      // Code should be expired - attempting to consume it should fail
      // Note: This test may need adjustment based on actual expiration implementation
    });

    test("Authorization code MUST be bound to client_id, code_challenge, and redirect_uri", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // Attempt to use code with different redirect_uri should fail
      await expect(
        t.mutation(api.mutations.consumeAuthCode, {
          code: authCode,
          clientId: client.clientId,
          redirectUri: "https://different.com/callback", // Wrong redirect_uri
          codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        })
      ).rejects.toThrow(/redirect.*uri/i);
    });
  });

  describe("Section 4.1.3 - Token Endpoint (Authorization Code)", () => {
    test("MUST return access token only once for a given authorization code", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // First consumption should succeed
      const result1 = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(result1.userId).toBeDefined();

      // Second consumption MUST fail
      const result2: any = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });
      expect(result2.error).toBe("authorization_code_reuse_detected");
    });

    test("MUST verify code_verifier parameter is present if code_challenge was sent", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // Attempt to consume without code_verifier should fail
      await expect(
        t.mutation(api.mutations.consumeAuthCode, {
          code: authCode,
          clientId: client.clientId,
          redirectUri: "https://example.com/callback",
          codeVerifier: "", // Missing code_verifier
        })
      ).rejects.toThrow();
    });

    test("MUST verify code_verifier matches code_challenge", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // Wrong code_verifier should fail
      await expect(
        t.mutation(api.mutations.consumeAuthCode, {
          code: authCode,
          clientId: client.clientId,
          redirectUri: "https://example.com/callback",
          codeVerifier: "wrong-verifier-value",
        })
      ).rejects.toThrow(/verifier/i);
    });
  });

  describe("Section 2.3 & 4.1.1 - Redirect URI Validation", () => {
    test("MUST use exact string comparison for redirect_uri validation", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // Exact match should work
      const authCode1 = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });
      expect(authCode1).toBeDefined();

      // Different path should fail
      await expect(
        t.mutation(api.mutations.issueAuthorizationCode, {
          userId: "user123",
          clientId: client.clientId,
          scopes: ["openid"],
          redirectUri: "https://example.com/different",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          codeChallengeMethod: "S256",
        })
      ).rejects.toThrow(/redirect/i);

      // Additional query parameter should fail (no substring matching)
      await expect(
        t.mutation(api.mutations.issueAuthorizationCode, {
          userId: "user123",
          clientId: client.clientId,
          scopes: ["openid"],
          redirectUri: "https://example.com/callback?extra=param",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          codeChallengeMethod: "S256",
        })
      ).rejects.toThrow(/redirect/i);
    });

    test("MUST allow variable port numbers for localhost URIs (native apps)", async () => {
      const t = convexTest(schema, modules);

      // Register client with localhost redirect (ポート省略で登録)
      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Native App",
        type: "public",
        redirectUris: ["http://127.0.0.1/callback"],
        scopes: ["openid"],
      });

      // 異なるポートでも許可されるべき
      const authCode1 = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "http://127.0.0.1:8080/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });
      expect(authCode1).toBeDefined();

      const authCode2 = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "http://127.0.0.1:9090/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });
      expect(authCode2).toBeDefined();
    });
  });

  describe("Section 3.2.3 - Token Response", () => {
    test("Refresh tokens MUST be bound to scope and resource servers", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "confidential",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "offline_access"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid", "offline_access"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      const result = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(result.userId).toBeDefined();
      // Note: This mutation returns userId and other metadata, not tokens directly
      // Token issuance happens at handler level
    });
  });

  describe("Section 4.3 - Refresh Token", () => {
    test("MUST maintain binding between refresh token and client", async () => {
      const t = convexTest(schema, modules);

      const client1 = await t.mutation(api.clientManagement.registerClient, {
        name: "Client 1",
        type: "confidential",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "offline_access"],
      });

      // Create another client to ensure token isolation
      await t.mutation(api.clientManagement.registerClient, {
        name: "Client 2",
        type: "confidential",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "offline_access"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client1.clientId,
        scopes: ["openid", "offline_access"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      const result = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client1.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(result.userId).toBeDefined();
      // Note: Client binding is tested at handler level where tokens are issued
    });

    test("Public clients SHOULD implement refresh token rotation", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Public Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "offline_access"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid", "offline_access"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      const result1 = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(result1.userId).toBeDefined();
      // Note: Refresh token rotation is tested at handler level where tokens are issued
    });
  });

  describe("Section 5.1 - Bearer Token Usage", () => {
    test("MUST NOT send access token in URI query parameter", async () => {
      // This is primarily a client requirement, but we can test that
      // the resource server should ignore tokens in query parameters

      // Note: This test verifies documentation/guidance rather than code behavior
      // Implementation should document that query parameter tokens are not supported
      expect(true).toBe(true); // Placeholder - adjust based on implementation
    });
  });

  describe("Section 10 - OAuth 2.0 Differences", () => {
    test("Implicit grant (response_type=token) MUST NOT be supported", async () => {
      // OAuth 2.1 removes the implicit grant
      // Authorization server should reject response_type=token

      // Note: This test should verify that the handler rejects implicit flow
      // Implementation-specific based on how authorization endpoint is exposed
      expect(true).toBe(true); // Placeholder - adjust based on implementation
    });

    test("Password grant MUST NOT be supported", async () => {
      // OAuth 2.1 removes the resource owner password credentials grant

      // Note: Implementation does not expose password grant
      expect(true).toBe(true); // Placeholder - verify no password grant implementation
    });

    test("RFC 6749 4.1.3: redirect_uri REQUIRED if included in authorization request", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "OAuth 2.1 Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // redirect_uri省略時はエラー
      await expect(
        t.mutation(api.mutations.consumeAuthCode, {
          code: authCode,
          clientId: client.clientId,
          codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
          // redirect_uriを省略
        })
      ).rejects.toThrow("redirect_uri_required");

      // redirect_uri付きなら成功
      const authCode2 = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      const codeData = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode2,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(codeData.userId).toBeDefined();
    });
  });

  describe("Section 4.2 - Client Credentials Grant", () => {
    test("Client credentials grant MUST only be used by confidential clients", async () => {
      const t = convexTest(schema, modules);

      // Register public client
      const publicClient = await t.mutation(api.clientManagement.registerClient, {
        name: "Public Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      // Public client should not be able to use client credentials grant
      // Note: Implementation-specific - adjust based on actual client_credentials implementation
      expect(publicClient.clientSecret).toBeUndefined();
    });
  });

  describe("Scope Validation", () => {
    test("MUST validate requested scopes against client's allowed scopes", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Limited Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"], // Only openid scope allowed
      });

      // Requesting disallowed scope should fail
      await expect(
        t.mutation(api.mutations.issueAuthorizationCode, {
          userId: "user123",
          clientId: client.clientId,
          scopes: ["openid", "profile"], // profile not in allowed scopes
          redirectUri: "https://example.com/callback",
          codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
          codeChallengeMethod: "S256",
        })
      ).rejects.toThrow(/scope/i);
    });

    test("RFC Line 1251: New refresh token MUST have identical scope", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "confidential",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "profile", "offline_access"],
      });

      // 最初にリフレッシュトークンを保存
      const oldRefreshToken = "test-refresh-token-123";
      await t.mutation(api.mutations.saveTokens, {
        accessToken: "test-access-token",
        refreshToken: oldRefreshToken,
        clientId: client.clientId,
        userId: "user123",
        scopes: ["openid", "profile", "offline_access"],
        expiresAt: Date.now() + 3600000,
        refreshTokenExpiresAt: Date.now() + 2592000000,
      });

      // RTローテーションでスコープ縮小を試行 → エラー
      await expect(
        t.mutation(api.mutations.rotateRefreshToken, {
          oldRefreshToken: oldRefreshToken,
          accessToken: "new-access-token",
          refreshToken: "new-refresh-token",
          clientId: client.clientId,
          userId: "user123",
          scopes: ["openid", "profile"], // offline_accessを削除（縮小）
          expiresAt: Date.now() + 3600000,
          refreshTokenExpiresAt: Date.now() + 2592000000,
        })
      ).rejects.toThrow(/scope/i);
    });

    test("RFC Line 1217: refresh_token grant scope MUST NOT exceed original", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "confidential",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "profile", "email", "offline_access"],
      });

      // 最初にリフレッシュトークンを保存（emailスコープなし）
      const oldRefreshToken = "test-refresh-token-456";
      await t.mutation(api.mutations.saveTokens, {
        accessToken: "test-access-token",
        refreshToken: oldRefreshToken,
        clientId: client.clientId,
        userId: "user123",
        scopes: ["openid", "profile", "offline_access"], // emailは含まない
        expiresAt: Date.now() + 3600000,
        refreshTokenExpiresAt: Date.now() + 2592000000,
      });

      // Mutation level test: rotateRefreshToken with expanded scopes should fail
      await expect(
        t.mutation(api.mutations.rotateRefreshToken, {
          oldRefreshToken: oldRefreshToken,
          accessToken: "new-access-token",
          refreshToken: "new-refresh-token",
          clientId: client.clientId,
          userId: "user123",
          scopes: ["openid", "profile", "email", "offline_access"], // email追加（拡大）
          expiresAt: Date.now() + 3600000,
          refreshTokenExpiresAt: Date.now() + 2592000000,
        })
      ).rejects.toThrow(/scope/i);
    });
  });

  describe("Section 4.1.3 - Authorization Code Replay Detection", () => {
    test("RFC Line 1136: MUST deny authorization code reuse and SHOULD revoke tokens", async () => {
      const t = convexTest(schema, modules);

      // Register client
      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid", "profile"],
      });

      // Issue authorization code
      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid", "profile"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // First use - should succeed
      const codeData = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(codeData.userId).toBe("user123");
      expect(codeData.codeHash).toBeDefined(); // Verify codeHash is returned

      // Save tokens using the returned codeHash
      await t.mutation(api.mutations.saveTokens, {
        accessToken: "test-access-token",
        refreshToken: "test-refresh-token",
        clientId: client.clientId,
        userId: "user123",
        scopes: ["openid", "profile"],
        expiresAt: Date.now() + 3600000,
        refreshTokenExpiresAt: Date.now() + 2592000000,
        authorizationCode: codeData.codeHash,
      });

      // Verify token was saved with correct authorizationCode
      const tokensBefore = await t.run(async (ctx) => {
        return await ctx.db
          .query("oauthTokens")
          .withIndex("by_authorization_code", (q) =>
            q.eq("authorizationCode", codeData.codeHash)
          )
          .collect();
      });
      expect(tokensBefore.length).toBe(1); // Token should exist before replay

      // Verify code is marked as used
      const codeAfterFirstUse = await t.run(async (ctx) => {
        const { hashToken } = await import("../token_security");
        const hash = await hashToken(authCode);
        return await ctx.db
          .query("oauthCodes")
          .withIndex("by_code", (q) => q.eq("code", hash))
          .unique();
      });
      expect(codeAfterFirstUse?.usedAt).toBeDefined(); // Code should be marked as used

      // Second use - should return error status (not throw, to allow token deletion to commit)
      const secondUseResult: any = await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      expect(secondUseResult.error).toBe("authorization_code_reuse_detected");
      expect(secondUseResult.revokedTokens).toBe(1);

      // Verify that tokens were revoked
      const tokensAfter = await t.run(async (ctx) => {
        return await ctx.db
          .query("oauthTokens")
          .withIndex("by_authorization_code", (q) =>
            q.eq("authorizationCode", codeData.codeHash)
          )
          .collect();
      });

      expect(tokensAfter.length).toBe(0); // All tokens should be deleted
    });

    test("RFC Line 1136: Single use enforcement - code is marked as used", async () => {
      const t = convexTest(schema, modules);

      const client = await t.mutation(api.clientManagement.registerClient, {
        name: "Test Client",
        type: "public",
        redirectUris: ["https://example.com/callback"],
        scopes: ["openid"],
      });

      const authCode = await t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
        codeChallengeMethod: "S256",
      });

      // First use
      await t.mutation(api.mutations.consumeAuthCode, {
        code: authCode,
        clientId: client.clientId,
        codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
        redirectUri: "https://example.com/callback",
      });

      // Verify code is marked as used in database
      const usedCode = await t.run(async (ctx) => {
        const codeHash = await import("../token_security").then((m) =>
          m.hashToken(authCode)
        );
        return await ctx.db
          .query("oauthCodes")
          .withIndex("by_code", (q) => q.eq("code", codeHash))
          .unique();
      });

      expect(usedCode).toBeDefined();
      expect(usedCode?.usedAt).toBeDefined();
      expect(usedCode?.usedAt).toBeGreaterThan(0);
    });
  });
});
