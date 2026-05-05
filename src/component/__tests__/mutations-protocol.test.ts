import { convexTest } from "convex-test";
import { describe, expect, test } from "vitest";
import { api } from "../_generated/api";
import schema from "../schema";

const modules = import.meta.glob("../**/*.ts");

const validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const validCodeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const wrongCodeVerifier = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

async function issueCodeWithSavedToken() {
  const t = convexTest(schema, modules);
  const client = await t.mutation(api.clientManagement.registerClient, {
    name: "Native Protocol Client",
    type: "public",
    redirectUris: ["https://example.com/callback"],
    scopes: ["openid"],
  });

  const code = await t.mutation(api.mutations.issueAuthorizationCode, {
    userId: "user123",
    clientId: client.clientId,
    scopes: ["openid"],
    redirectUri: "https://example.com/callback",
    codeChallenge: validCodeChallenge,
    codeChallengeMethod: "S256",
  });

  const codeData = await t.mutation(api.mutations.consumeAuthCode, {
    code,
    clientId: client.clientId,
    redirectUri: "https://example.com/callback",
    codeVerifier: validCodeVerifier,
  });

  await t.mutation(api.mutations.saveTokens, {
    accessToken: "access-token",
    refreshToken: "refresh-token",
    clientId: client.clientId,
    userId: "user123",
    scopes: ["openid"],
    expiresAt: Date.now() + 3600000,
    refreshTokenExpiresAt: Date.now() + 2592000000,
    authorizationCode: codeData.codeHash,
  });

  return { t, client, code, codeHash: codeData.codeHash };
}

async function getReplayState(
  t: ReturnType<typeof convexTest>,
  codeHash: string
) {
  return await t.run(async (ctx) => {
    const db = ctx.db as any;
    const code = await db
      .query("oauthCodes")
      .withIndex("by_code", (q: any) => q.eq("code", codeHash))
      .unique();
    const tokens = await db
      .query("oauthTokens")
      .withIndex("by_authorization_code", (q: any) =>
        q.eq("authorizationCode", codeHash)
      )
      .collect();

    return {
      replayDetectedAt: code?.replayDetectedAt,
      tokenCount: tokens.length,
    };
  });
}

describe("OAuth mutation protocol enforcement", () => {
  test.each([
    ["short code_challenge", "A".repeat(42)],
    ["long code_challenge", "A".repeat(129)],
    ["invalid code_challenge character", `${"A".repeat(42)}!`],
  ])("issueAuthorizationCode rejects %s", async (_caseName, codeChallenge) => {
    const t = convexTest(schema, modules);
    const client = await t.mutation(api.clientManagement.registerClient, {
      name: "PKCE Client",
      type: "public",
      redirectUris: ["https://example.com/callback"],
      scopes: ["openid"],
    });

    await expect(
      t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://example.com/callback",
        codeChallenge,
        codeChallengeMethod: "S256",
      })
    ).rejects.toThrow("invalid_code_challenge");
  });

  test.each([
    ["short code_verifier", "A".repeat(42)],
    ["long code_verifier", "A".repeat(129)],
    ["invalid code_verifier character", `${"A".repeat(42)}!`],
  ])("consumeAuthCode rejects %s", async (_caseName, codeVerifier) => {
    const t = convexTest(schema, modules);
    const client = await t.mutation(api.clientManagement.registerClient, {
      name: "PKCE Client",
      type: "public",
      redirectUris: ["https://example.com/callback"],
      scopes: ["openid"],
    });
    const code = await t.mutation(api.mutations.issueAuthorizationCode, {
      userId: "user123",
      clientId: client.clientId,
      scopes: ["openid"],
      redirectUri: "https://example.com/callback",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
    });

    await expect(
      t.mutation(api.mutations.consumeAuthCode, {
        code,
        clientId: client.clientId,
        redirectUri: "https://example.com/callback",
        codeVerifier,
      })
    ).rejects.toThrow("invalid_code_verifier");
  });

  test("https loopback redirect_uri requires exact port match", async () => {
    const t = convexTest(schema, modules);
    const client = await t.mutation(api.clientManagement.registerClient, {
      name: "HTTPS Loopback Client",
      type: "public",
      redirectUris: ["https://127.0.0.1/callback"],
      scopes: ["openid"],
    });

    await expect(
      t.mutation(api.mutations.issueAuthorizationCode, {
        userId: "user123",
        clientId: client.clientId,
        scopes: ["openid"],
        redirectUri: "https://127.0.0.1:8080/callback",
        codeChallenge: validCodeChallenge,
        codeChallengeMethod: "S256",
      })
    ).rejects.toThrow("redirect_uri_mismatch");
  });

  test("authorization code resource is persisted and mismatched token resource is rejected before consumption", async () => {
    const t = convexTest(schema, modules);
    const client = await t.mutation(api.clientManagement.registerClient, {
      name: "Resource Client",
      type: "public",
      redirectUris: ["https://example.com/callback"],
      scopes: ["openid"],
    });

    const code = await t.mutation(api.mutations.issueAuthorizationCode, {
      userId: "user123",
      clientId: client.clientId,
      scopes: ["openid"],
      redirectUri: "https://example.com/callback",
      codeChallenge: validCodeChallenge,
      codeChallengeMethod: "S256",
      resource: "https://api.example.com/mcp",
    });

    await expect(
      t.mutation(api.mutations.consumeAuthCode, {
        code,
        clientId: client.clientId,
        redirectUri: "https://example.com/callback",
        codeVerifier: validCodeVerifier,
        resource: "https://api.example.com/other",
      })
    ).rejects.toThrow("invalid_target");

    const codeData = await t.mutation(api.mutations.consumeAuthCode, {
      code,
      clientId: client.clientId,
      redirectUri: "https://example.com/callback",
      codeVerifier: validCodeVerifier,
      resource: "https://api.example.com/mcp",
    });

    expect(codeData.resource).toBe("https://api.example.com/mcp");
  });

  test.each([
    [
      "client_id mismatch",
      {
        clientId: "wrong-client",
        redirectUri: "https://example.com/callback",
        codeVerifier: validCodeVerifier,
        error: "invalid_grant",
      },
    ],
    [
      "redirect_uri mismatch",
      {
        redirectUri: "https://example.com/other",
        codeVerifier: validCodeVerifier,
        error: "redirect_uri_mismatch",
      },
    ],
    [
      "invalid code_verifier",
      {
        redirectUri: "https://example.com/callback",
        codeVerifier: wrongCodeVerifier,
        error: "invalid_code_verifier",
      },
    ],
  ])(
    "used auth code with %s does not revoke tokens or tombstone the code",
    async (_caseName, replayArgs) => {
      const { t, client, code, codeHash } = await issueCodeWithSavedToken();

      await expect(
        t.mutation(api.mutations.consumeAuthCode, {
          code,
          clientId: "clientId" in replayArgs ? replayArgs.clientId : client.clientId,
          redirectUri: replayArgs.redirectUri,
          codeVerifier: replayArgs.codeVerifier,
        })
      ).rejects.toThrow(replayArgs.error);

      await expect(
        getReplayState(t, codeHash)
      ).resolves.toEqual({
        replayDetectedAt: undefined,
        tokenCount: 1,
      });
    }
  );
});
