/**
 * Bug-hunting tests (RED tests demonstrating each critical bug).
 *
 * Each test in this file documents an outstanding bug.
 * They are expected to FAIL until the bug is fixed.
 */

import { describe, expect, test, vi } from "vitest";
import { convexTest } from "convex-test";
import { isLoopbackRedirectUri, matchRedirectUri } from "../mutations";
import schema from "../schema";
import { api, internal } from "../_generated/api";
import { generateClientSecret, getJWKS, getIssuerUrl, getSigningKeyId } from "../../lib/oauth";
import { hashToken } from "../token_security";
import { decodeJwt, exportJWK, exportPKCS8, generateKeyPair } from "jose";
import { tokenHandler, userInfoHandler, registerHandler, authorizeHandler, openIdConfigurationHandler, type OAuthComponentAPI } from "../handlers";
import type { OAuthConfig } from "../../lib/oauth";

const modules = import.meta.glob("../**/*.ts");

const validCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

describe("Bug 1: isLoopbackRedirectUri ignores RFC-compliant IPv6 loopback URIs with brackets", () => {
    // `URL.hostname` returns "[::1]" for IPv6 loopback URIs (per WHATWG URL spec).
    // But mutations.ts compares against the bracketless "::1", so loopback variable-port
    // exception (RFC 8252 §7.3) is never granted for IPv6 native apps.
    test("http://[::1]/cb must be recognized as a loopback redirect URI", () => {
        expect(isLoopbackRedirectUri("http://[::1]/cb")).toBe(true);
    });

    test("matchRedirectUri must permit variable IPv6 loopback ports per RFC 8252", () => {
        // Registered with no port, request with explicit port — should match.
        expect(matchRedirectUri("http://[::1]:43210/cb", ["http://[::1]/cb"])).toBe(
            true,
        );
    });
});

describe("Bug 3: getJWKS does not surface use/alg on keys that omit them", () => {
    // JWKS responses MUST advertise the key usage and algorithm so resource servers can
    // pick the right verification primitive. The deprecated `getPublicJWK` adds them
    // explicitly; the new `getJWKS` keeps whatever the JWKS already contains and never
    // adds defaults, breaking interoperability with the typical RSA signing setup.
    test("getJWKS must default use='sig' and alg='RS256' for an RSA key without those hints", async () => {
        const jwks = await getJWKS({
            jwks: JSON.stringify({
                keys: [{ kty: "RSA", n: "abc", e: "AQAB", kid: "k1" }],
            }),
            privateKey: "",
            siteUrl: "https://example.com",
        });
        expect(jwks.keys[0]).toMatchObject({ use: "sig", alg: "RS256" });
    });
});

describe("Bug 4: verifyPkce accepts the OAuth-2.1-prohibited 'plain' code_challenge_method", () => {
    // OAuth 2.1 §4.1.1 makes S256 mandatory ("plain" MUST NOT be supported).
    // `issueAuthorizationCode` rejects "plain", but the actual PKCE verifier
    // (`verifyPkce` inside `mutations.ts`) still has a "plain" branch that
    // succeeds when verifier === challenge. That branch must be unreachable —
    // otherwise any legacy / smuggled "plain" code can still mint a token.
    test("consumeAuthCode must reject a stored authorization code that carries codeChallengeMethod='plain'", async () => {
        const t = convexTest(schema, modules);

        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Plain-PKCE Client",
            type: "public",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });

        // Insert an authorization code directly into the DB with the prohibited
        // "plain" method to simulate either legacy data or a bypass of the
        // issuance-time guard.
        const codeVerifier = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_-.~0123456789abcd"; // 44 chars, ABNF-valid
        const plaintextCode = "plain-pkce-code-1234567890";
        const codeHash = await hashToken(plaintextCode);
        await t.run(async (ctx) => {
            await ctx.db.insert("oauthCodes", {
                code: codeHash,
                clientId: client.clientId,
                userId: "user123",
                scopes: ["openid"],
                redirectUri: "https://cb",
                codeChallenge: codeVerifier, // plain method: challenge == verifier
                codeChallengeMethod: "plain",
                expiresAt: Date.now() + 60_000,
            });
        });

        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code: plaintextCode,
                clientId: client.clientId,
                codeVerifier,
                redirectUri: "https://cb",
            }),
        ).rejects.toThrow(/plain|unsupported|S256/i);
    });
});

async function makeJwtConfig(extra: Partial<OAuthConfig> = {}): Promise<OAuthConfig> {
    const { privateKey, publicKey } = await generateKeyPair("RS256", { extractable: true });
    const privateKeyPem = await exportPKCS8(privateKey);
    const jwk = await exportJWK(publicKey);
    return {
        privateKey: privateKeyPem,
        jwks: JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "RS256", use: "sig" }] }),
        siteUrl: "https://example.com",
        allowDynamicClientRegistration: true,
        ...extra,
    };
}

function makeApi(overrides: Partial<OAuthComponentAPI> = {}): OAuthComponentAPI {
    return {
        queries: {
            getClient: async (_ctx: any, { clientId }: { clientId: string }) => ({
                clientId,
                type: "confidential" as const,
                redirectUris: ["https://cb"],
                allowedScopes: ["openid", "profile", "offline_access"],
            }),
            getRefreshToken: async () => null,
            getTokensByUser: async () => [],
            ...overrides.queries,
        } as any,
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
        } as any,
        clientManagement: {
            registerClient: async () => ({
                clientId: "client",
                clientSecret: "secret",
                clientIdIssuedAt: 0,
            }),
            verifyClientSecret: async () => true,
            ...overrides.clientManagement,
        } as any,
    };
}

describe("Bug 5: refresh-token-issued ID token omits auth_time even when one was set in the original authentication", () => {
    // OIDC Core §12.2: "if there is an auth_time Claim in the original ID Token,
    // it MUST be present in the new ID Token". This implementation does not preserve
    // auth_time across refresh.
    test("ID token issued via refresh_token must carry the original auth_time", async () => {
        const jwtConfig = await makeJwtConfig();

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: "client",
                    refresh_token: "rt",
                    client_secret: "secret",
                }),
            }),
            jwtConfig,
            makeApi({
                queries: {
                    getRefreshToken: async () => ({
                        clientId: "client",
                        userId: "user",
                        scopes: ["openid", "offline_access"],
                        refreshTokenExpiresAt: Date.now() + 3600 * 1000,
                        // Note: schema currently does not even surface authTime here.
                        // The bug is the loss; not having a field to read it from is part of the bug.
                        authTime: 1_700_000_000,
                    }) as any,
                } as any,
            }),
        );

        expect(response.status).toBe(200);
        const body = await response.json();
        expect(body.id_token).toBeDefined();
        const claims = decodeJwt(body.id_token);
        expect(claims.auth_time).toBe(1_700_000_000);
    });
});

describe("Bug 6: replay detection misses descendants because rotateRefreshToken loses the authorizationCode link", () => {
    // OAuth 2.1 (draft-ietf-oauth-v2-1) §4.1.4: when authorization code replay is detected,
    // "the authorization server SHOULD revoke all tokens (access tokens, refresh tokens, ...
    // and other credentials) that were issued based on that authorization".
    // The current implementation only revokes the *first* token row, because
    // `rotateRefreshToken` does not propagate `authorizationCode`. After one
    // refresh, the chain is invisible to the replay-revocation query.
    test("rotateRefreshToken must propagate the originating authorizationCode", async () => {
        const t = convexTest(schema, modules);

        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Replay-chain Client",
            type: "confidential",
            redirectUris: ["https://cb"],
            scopes: ["openid", "offline_access"],
        });

        const codeHash = "a".repeat(64); // pretend hash, only used as the link key
        await t.mutation(api.mutations.saveTokens, {
            accessToken: "initial-access",
            refreshToken: "initial-refresh",
            clientId: client.clientId,
            userId: "user123",
            scopes: ["openid", "offline_access"],
            expiresAt: Date.now() + 3_600_000,
            refreshTokenExpiresAt: Date.now() + 30 * 24 * 3_600_000,
            authorizationCode: codeHash,
        });

        await t.mutation(api.mutations.rotateRefreshToken, {
            oldRefreshToken: "initial-refresh",
            accessToken: "rotated-access",
            refreshToken: "rotated-refresh",
            clientId: client.clientId,
            userId: "user123",
            scopes: ["openid", "offline_access"],
            expiresAt: Date.now() + 3_600_000,
            refreshTokenExpiresAt: Date.now() + 30 * 24 * 3_600_000,
        });

        const rotated = await t.run(async (ctx) => {
            return await ctx.db
                .query("oauthTokens")
                .withIndex("by_authorization_code", (q) =>
                    q.eq("authorizationCode", codeHash),
                )
                .collect();
        });

        // After rotation, the descendant token MUST still be reachable from the
        // original authorization-code link so that replay revocation can find it.
        expect(rotated.length).toBeGreaterThanOrEqual(1);
    });
});

describe("Bug 7: token endpoint silently overrides form client_id with the Basic-auth client_id when they disagree", () => {
    // OAuth 2.1 §2.4 and RFC 6749 require unambiguous client identification.
    // If both Basic credentials and a form client_id are supplied, they MUST be
    // identical and the server MUST reject otherwise. The current handler
    // silently chooses the Basic-auth value (`clientId = basicCredentials.clientId`)
    // and discards the form value, so mixed-up callers are not warned and the
    // client-confusion attack surface stays open.
    test("token endpoint must reject conflicting client_id between Basic auth and form body", async () => {
        const getClient = vi.fn(async (_ctx: any, { clientId }: { clientId: string }) => ({
            clientId,
            type: "confidential" as const,
            redirectUris: ["https://cb"],
            allowedScopes: ["openid"],
            tokenEndpointAuthMethod: "client_secret_basic" as const,
        }));

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "clientB-from-form",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                }),
                headers: {
                    "Content-Type": "application/x-www-form-urlencoded",
                    Authorization: `Basic ${btoa("clientA-from-basic:secret")}`,
                },
            }),
            await makeJwtConfig(),
            makeApi({ queries: { getClient } as any }),
        );

        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
    });
});

describe("Bug 8: bcrypt truncates the 128-char client secret at 72 bytes, so half the secret carries no entropy", () => {
    // `OAUTH_CONSTANTS.CLIENT_SECRET_LENGTH = 64` random bytes are formatted as 128
    // hex characters. bcrypt (including bcryptjs) silently truncates input above 72
    // bytes, so the last 56 hex chars of every issued secret are ignored by
    // verification. Two secrets that match in the first 72 chars are
    // indistinguishable — i.e. the system claims 64 random bytes of entropy but only
    // protects 36.
    test("generated client secrets must fit within bcrypt's 72-byte input limit", () => {
        expect(generateClientSecret(64)).toHaveLength(64);
    });

    test("verifyClientSecret must keep accepting existing long secrets for patch-release compatibility", async () => {
        const t = convexTest(schema, modules);
        const bcrypt = await import("bcryptjs");

        const real = "a".repeat(128);
        await t.run(async (ctx) => {
            await ctx.db.insert("oauthClients", {
                name: "Legacy Long Secret Client",
                clientId: "legacy-long-secret-client",
                clientSecret: bcrypt.hashSync(real, 4),
                type: "confidential",
                redirectUris: ["https://cb"],
                allowedScopes: ["openid"],
                createdAt: Date.now(),
                tokenEndpointAuthMethod: "client_secret_basic",
            });
        });

        await expect(
            t.mutation(api.clientManagement.verifyClientSecret, {
                clientId: "legacy-long-secret-client",
                clientSecret: real,
            }),
        ).resolves.toBe(true);
    });

    test("verifyClientSecret must reject a tampered generated secret", async () => {
        const t = convexTest(schema, modules);

        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "Truncation Client",
            type: "confidential",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });
        const real = result.clientSecret as string;
        const tampered = real.slice(0, -1) + (real.charAt(real.length - 1) === "0" ? "1" : "0");

        const realOk = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: result.clientId,
            clientSecret: real,
        });
        expect(realOk).toBe(true);

        const tamperedOk = await t.mutation(api.clientManagement.verifyClientSecret, {
            clientId: result.clientId,
            clientSecret: tampered,
        });
        expect(tamperedOk).toBe(false);
    });
});

describe("Bug 9: userInfoHandler treats the Bearer auth scheme as case-sensitive", () => {
    // RFC 7235 §2.1 (and RFC 6750 §2.1) make HTTP auth-scheme names case-insensitive.
    // `authHeader.startsWith("Bearer ")` rejects valid 'bearer ' / 'BEARER ' values
    // outright, surfacing the missing-credentials challenge instead of attempting JWT
    // validation.
    test("userInfoHandler must accept 'bearer' / 'BEARER' as Bearer-scheme credentials", async () => {
        const jwtConfig = await makeJwtConfig();

        // Mint a valid access token via the token endpoint so we have a real JWT.
        const tokenResponse = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            jwtConfig,
            makeApi({
                mutations: {
                    consumeAuthCode: async () => ({
                        userId: "user",
                        scopes: ["openid"],
                        codeChallenge: "challenge",
                        codeChallengeMethod: "S256",
                        redirectUri: "https://cb",
                        codeHash: "hash",
                    }),
                } as any,
            }),
        );
        const { access_token } = await tokenResponse.json();

        for (const scheme of ["bearer", "BEARER", "Bearer"]) {
            const response = await userInfoHandler(
                {} as any,
                new Request("https://example.com/oauth/userinfo", {
                    headers: { Authorization: `${scheme} ${access_token}` },
                }),
                jwtConfig,
                async () => ({ sub: "user" }),
            );
            expect(response.status, `scheme=${scheme}`).toBe(200);
        }
    });
});

describe("Bug 10: revokeAuthorization leaves pending authorization codes intact, so users can still mint tokens after revoking", () => {
    // A user (or admin) that revokes an authorization expects the action to invalidate
    // every credential issued under it. `revokeAuthorization` only clears the
    // authorization record and existing tokens — it does not delete the (up-to-10-min)
    // window of unconsumed auth codes. A racing client can still trade an in-flight
    // code for new tokens after the user has clicked "Disconnect".
    test("an authorization code that pre-existed the revoke call must be unusable afterwards", async () => {
        const t = convexTest(schema, modules);

        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Revoke Race Client",
            type: "public",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });

        // Pretend the user has been through consent once (authorization record exists).
        await t.mutation(api.mutations.upsertAuthorization, {
            userId: "user123",
            clientId: client.clientId,
            scopes: ["openid"],
        });

        // A second /authorize click issues a fresh code that has not yet been exchanged.
        const pendingCode = await t.mutation(api.mutations.issueAuthorizationCode, {
            userId: "user123",
            clientId: client.clientId,
            scopes: ["openid"],
            redirectUri: "https://cb",
            codeChallenge: validCodeChallenge,
            codeChallengeMethod: "S256",
        });

        // The user now revokes the authorization from the management UI.
        await t.mutation(api.mutations.revokeAuthorization, {
            userId: "user123",
            clientId: client.clientId,
        });

        // Despite the explicit revoke, the still-pending auth code is happily consumable.
        await expect(
            t.mutation(api.mutations.consumeAuthCode, {
                code: pendingCode,
                clientId: client.clientId,
                redirectUri: "https://cb",
                codeVerifier: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk",
            }),
        ).rejects.toThrow();
    });
});

describe("Bug 11: cleanupExpired deletes used auth codes prematurely, defeating replay revocation", () => {
    // Replay revocation (oauthCodes.replayDetectedAt + the by_authorization_code link)
    // is only effective while the originating auth code row still exists. Codes expire
    // at `Date.now() + 10min` (CODE_EXPIRY_MS) regardless of `usedAt`, so as soon as
    // 10 minutes pass after issuance the code is dropped — yet the tokens minted from
    // it still live for up to 1 hour (access) / 30 days (refresh). After cleanup, any
    // replay attempt simply 404s on the code lookup, and `consumeAuthCode` never
    // reaches the token-revocation branch.
    test("a used auth code must survive `cleanupExpired` as long as tokens it issued may still be live", async () => {
        const t = convexTest(schema, modules);

        await t.run(async (ctx) => {
            await ctx.db.insert("oauthCodes", {
                code: "a".repeat(64),
                clientId: "c1",
                userId: "u1",
                scopes: ["openid"],
                redirectUri: "https://cb",
                codeChallenge: validCodeChallenge,
                codeChallengeMethod: "S256",
                expiresAt: Date.now() - 1_000, // expired 1s ago (auth-code TTL is 10min)
                usedAt: Date.now() - 2_000,    // was used 2s ago — replay tombstone
            });
        });

        await t.mutation(internal.mutations.cleanupExpired, {});

        const remaining = await t.run(async (ctx) => {
            return await ctx.db
                .query("oauthCodes")
                .withIndex("by_code", (q) => q.eq("code", "a".repeat(64)))
                .unique();
        });

        // The replay-tombstone row must outlive the 10-min auth-code TTL so that
        // subsequent replays can still trigger revocation. Today it does not.
        expect(remaining).not.toBeNull();
    });
});

describe("Bug 12: deleteClient leaves oauthAuthorizations rows orphaned", () => {
    // `clientManagement.deleteClient` already wipes tokens and codes for the deleted
    // client, but it never touches `oauthAuthorizations`. Every user that ever
    // consented to the client is left with a dangling consent row pointing at a
    // non-existent client. UI helpers such as `listUserAuthorizations` then surface
    // "Unknown App" rows and continue to behave as if the user is still authorized.
    test("deleting a client must also remove its authorization records", async () => {
        const t = convexTest(schema, modules);

        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Soon-to-be-deleted Client",
            type: "public",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });

        await t.mutation(api.mutations.upsertAuthorization, {
            userId: "user123",
            clientId: client.clientId,
            scopes: ["openid"],
        });

        await t.mutation(api.clientManagement.deleteClient, {
            clientId: client.clientId,
        });

        const remaining = await t.run(async (ctx) => {
            return await ctx.db
                .query("oauthAuthorizations")
                .withIndex("by_user_client", (q) =>
                    q.eq("userId", "user123").eq("clientId", client.clientId),
                )
                .unique();
        });

        // Currently the row is still there, pointing at a deleted client.
        expect(remaining).toBeNull();
    });
});

describe("Bug 13: api.mutations.deleteClient leaves tokens and codes orphaned (separate from clientManagement.deleteClient)", () => {
    // The component exports **two** `deleteClient` mutations:
    //   * `api.clientManagement.deleteClient` (the documented path) — at least removes
    //     tokens and codes (still leaves authorizations — see Bug 12).
    //   * `api.mutations.deleteClient` — only removes the client row.
    // Any host that wires up the latter (or copies it via codegen) is left with
    // every issued access token and refresh token still verifying against a JWKS
    // that no longer represents an active client; the JWT-side revocation hook
    // (`checkAuthorization`) won't fire either because the consent record is
    // intact. Two functions with the same name and dramatically different
    // safety levels is the bug.
    test("deleting a client must invalidate the credentials it issued, regardless of which deleteClient is called", async () => {
        const t = convexTest(schema, modules);

        const client = await t.mutation(api.clientManagement.registerClient, {
            name: "Two-API Client",
            type: "public",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });

        await t.mutation(api.mutations.saveTokens, {
            accessToken: "at",
            refreshToken: "rt",
            clientId: client.clientId,
            userId: "user123",
            scopes: ["openid"],
            expiresAt: Date.now() + 3_600_000,
            refreshTokenExpiresAt: Date.now() + 30 * 86_400_000,
        });

        await t.mutation(api.mutations.deleteClient, { clientId: client.clientId });

        const leftover = await t.run(async (ctx) => {
            return await ctx.db
                .query("oauthTokens")
                .withIndex("by_user", (q) => q.eq("userId", "user123"))
                .collect();
        });

        // Currently `api.mutations.deleteClient` does NOT delete tokens.
        expect(leftover.filter((token) => token.clientId === client.clientId)).toHaveLength(0);
    });
});

describe("Bug 14: getIssuerUrl produces a double slash when convexSiteUrl ends with '/'", () => {
    // `normalizePrefix` strips the prefix's trailing slash but doesn't trim the
    // *issuer base URL* itself. A perfectly common config value like
    // `CONVEX_SITE_URL=https://example.com/` therefore yields the issuer
    // `https://example.com//oauth`. That string is what gets baked into the
    // `iss` claim of every JWT and into the OIDC discovery document — and
    // strict verifiers (PyJWT strict, Auth0 SDK, etc.) will reject it as not
    // matching the canonical URL.
    test("issuer URL must not contain consecutive slashes", () => {
        const url = getIssuerUrl({
            convexSiteUrl: "https://example.com/",
            siteUrl: "https://example.com/",
            privateKey: "",
            jwks: "{}",
            prefix: "/oauth",
        });
        expect(url).not.toMatch(/(^https?:\/\/[^/]+)\/\//);
        expect(url).toBe("https://example.com/oauth");
    });
});

describe("Bug 15: tokenHandler leaks internal error messages into the OAuth error_description body", () => {
    // The token endpoint catches everything, maps a known error-message prefix list
    // to OAuth error codes, and otherwise falls through to `new OAuthError(
    // "invalid_request", message)` where `message` is the raw `Error.message`.
    // OAuth 2.1 §10.4 / OWASP "don't leak internals" — but here any internal
    // failure inside a query/mutation surfaces directly to the requesting client
    // (and any logs the client forwards).
    test("an unhandled internal error must not echo its message back to the client", async () => {
        const getClient = vi.fn(async () => {
            // Simulate an unexpected internal failure (e.g. DB connectivity issue).
            throw new Error("Internal DB stack trace: /Users/fshindo/secret/path/file.ts:42");
        });

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            await makeJwtConfig(),
            makeApi({ queries: { getClient } as any }),
        );

        const body = await response.json();
        // The error_description must not contain the raw internal error string.
        expect(body.error_description ?? "").not.toContain("Internal DB stack trace");
        expect(body.error_description ?? "").not.toMatch(/\/Users\//);
    });
});

describe("Bug 16: registerHandler (DCR) also echoes raw internal error messages to anonymous callers", () => {
    // Same shape as Bug 15, but the DCR endpoint is open to the **entire internet**
    // when `allowDynamicClientRegistration` is on. Any anonymous client can
    // submit a request that triggers an unhandled exception inside the
    // component and receive the internal error text directly.
    test("DCR must not echo internal error details to anonymous callers", async () => {
        const registerClient = vi.fn(async () => {
            throw new Error("Internal: secret SQL params /tmp/run/12345");
        });

        const response = await registerHandler(
            {} as any,
            new Request("https://example.com/oauth/register", {
                method: "POST",
                body: JSON.stringify({
                    redirect_uris: ["https://client.example.com/cb"],
                }),
                headers: { "Content-Type": "application/json" },
            }),
            await makeJwtConfig({ allowDynamicClientRegistration: true }),
            makeApi({ clientManagement: { registerClient } as any }),
        );

        const body = await response.json();
        expect(body.error_description ?? "").not.toContain("Internal:");
        expect(body.error_description ?? "").not.toMatch(/\/tmp\//);
    });
});

describe("Bug 17: userInfoHandler success response omits Cache-Control: no-store", () => {
    // OAuth 2.0 §5.1 (and RFC 7235 best practice) require that responses carrying
    // bearer-token-protected user info include `Cache-Control: no-store`.
    // `userInfoHandler` returns the user profile with only the CORS headers; no
    // Cache-Control is ever set. Intermediate caches and well-meaning browser
    // back/forward caches can therefore retain the user's identity payload.
    test("userinfo 200 response must carry Cache-Control: no-store", async () => {
        const jwtConfig = await makeJwtConfig();

        // Mint a real access token for the test.
        const tokenResponse = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "authorization_code",
                    client_id: "client",
                    code: "code",
                    redirect_uri: "https://cb",
                    code_verifier: "verifier",
                    client_secret: "secret",
                }),
            }),
            jwtConfig,
            makeApi({
                mutations: {
                    consumeAuthCode: async () => ({
                        userId: "user",
                        scopes: ["openid", "profile"],
                        codeChallenge: "challenge",
                        codeChallengeMethod: "S256",
                        redirectUri: "https://cb",
                        codeHash: "hash",
                    }),
                } as any,
            }),
        );
        const { access_token } = await tokenResponse.json();

        const response = await userInfoHandler(
            {} as any,
            new Request("https://example.com/oauth/userinfo", {
                headers: { Authorization: `Bearer ${access_token}` },
            }),
            jwtConfig,
            async () => ({ sub: "user", name: "Real User" }),
        );

        expect(response.status).toBe(200);
        expect(response.headers.get("Cache-Control") ?? "").toContain("no-store");
    });
});

describe("Bug 18: upsertAuthorization merges scopes monotonically — narrowed consent is silently widened back", () => {
    // The "skip consent" path checks the stored authorization scope list via
    // `OAuthProvider.hasAuthorization`. Because `upsertAuthorization` unions the
    // new scopes into whatever the user previously granted, a user that narrows
    // their consent (e.g. removes `email`) continues to look fully consented to
    // every scope they EVER consented to. The "Skip consent" gate then accepts
    // calls for scopes the user has explicitly walked back.
    test("a follow-up consent narrowing must shrink the stored scopes, not union with the prior set", async () => {
        const t = convexTest(schema, modules);

        await t.mutation(api.mutations.upsertAuthorization, {
            userId: "user1",
            clientId: "client1",
            scopes: ["openid", "profile", "email"],
        });

        // Same user re-consents to a narrower scope set.
        await t.mutation(api.mutations.upsertAuthorization, {
            userId: "user1",
            clientId: "client1",
            scopes: ["openid"],
        });

        const auth = await t.query(api.queries.getAuthorization, {
            userId: "user1",
            clientId: "client1",
        });

        // Stored scopes must reflect the most recent grant, otherwise the
        // "user consented to email" claim continues to be true forever.
        expect(auth?.scopes.sort()).toEqual(["openid"]);
    });
});

describe("Bug 19: cleanupExpired deletes whole oauthTokens rows by access-token expiry, taking the still-valid refresh token with them", () => {
    // `oauthTokens` rows carry both an access-token hash and a refresh-token hash.
    // Access tokens live 1h; refresh tokens live 30 days. `cleanupExpired` deletes
    // any row whose `expiresAt` (= access-token expiry) is in the past — without
    // looking at `refreshTokenExpiresAt`. As soon as the 1h access window closes
    // (and cleanup runs), the still-valid refresh token is wiped along with it.
    // The next refresh request returns `invalid_grant`, forcing the user back
    // through the full authorization flow once every 1h instead of every 30 days.
    test("cleanupExpired must preserve rows whose refresh token is still within its own expiry", async () => {
        const t = convexTest(schema, modules);

        await t.run(async (ctx) => {
            await ctx.db.insert("oauthTokens", {
                accessToken: "x".repeat(64),
                refreshToken: "y".repeat(64),
                clientId: "client",
                userId: "user",
                scopes: ["openid", "offline_access"],
                expiresAt: Date.now() - 1_000, // access token expired
                refreshTokenExpiresAt: Date.now() + 30 * 86_400_000, // refresh still valid
            });
        });

        await t.mutation(internal.mutations.cleanupExpired, {});

        const remaining = await t.run(async (ctx) => {
            return await ctx.db.query("oauthTokens").collect();
        });

        expect(remaining.length).toBeGreaterThanOrEqual(1);
    });
});

describe("Bug 20: tokenHandler returns unsupported_grant_type for a missing grant_type (should be invalid_request)", () => {
    // RFC 6749 §5.2 distinguishes the two:
    //   * invalid_request          — "missing a required parameter"
    //   * unsupported_grant_type   — "grant type ... is not supported"
    // Today the handler falls through to `unsupported_grant_type` whether the
    // client OMITS grant_type entirely or supplies an unsupported value. The
    // former should surface as `invalid_request` so a misconfigured client can
    // distinguish "you forgot grant_type" from "I do not implement that grant".
    test("missing grant_type must surface as invalid_request", async () => {
        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    // grant_type intentionally omitted
                    client_id: "client",
                    client_secret: "secret",
                }),
            }),
            await makeJwtConfig(),
            makeApi(),
        );

        expect(response.status).toBe(400);
        const body = await response.json();
        expect(body.error).toBe("invalid_request");
    });
});

describe("Bug 21: api.queries.getClient leaks the bcrypt-hashed clientSecret", () => {
    // `listClients` carefully strips `clientSecret` before returning, but the
    // companion `getClient` query returns the raw `oauthClients` row — including
    // the bcrypt hash. Hosts that wire this query up to the frontend (the SDK
    // exposes it directly via `OAuthProvider.getClient`) ship the hash to the
    // browser. The hash is bcrypt(10) so it's not catastrophic, but it leaks
    // information about secret strength and lets a determined attacker mount an
    // offline bcrypt attack while only being able to interact with the consent
    // page.
    test("getClient response must not include the stored clientSecret", async () => {
        const t = convexTest(schema, modules);

        const result = await t.mutation(api.clientManagement.registerClient, {
            name: "Leaky Client",
            type: "confidential",
            redirectUris: ["https://cb"],
            scopes: ["openid"],
        });

        const client = await t.query(api.queries.getClient, {
            clientId: result.clientId,
        });

        expect(client).not.toBeNull();
        // The hashed secret must not be exposed through the read API; `listClients`
        // already strips it for the very same reason.
        expect((client as any)?.clientSecret).toBeUndefined();
    });
});

describe("Bug 22: authorizeHandler does not honor prompt=none semantics (returns access_denied instead of login_required/consent_required)", () => {
    // OIDC Core §3.1.2.1 defines:
    //   * login_required   — prompt=none AND end-user not authenticated
    //   * consent_required — prompt=none AND end-user authenticated but consent missing
    //   * interaction_required — generic interaction-required fallback
    // The handler returns the catch-all `access_denied` in both cases instead.
    // Relying-party SDKs that follow the spec (Auth0, NextAuth, openid-client) use
    // these specific error codes to distinguish "show login" from "show consent"
    // from "user refused". With access_denied, they cannot tell the difference.
    test("prompt=none without authenticated user must redirect with error=login_required", async () => {
        const response = await authorizeHandler(
            {} as any,
            new Request(
                "https://example.com/oauth/authorize?response_type=code&client_id=client&redirect_uri=https%3A%2F%2Fcb&scope=openid&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&code_challenge_method=S256&prompt=none&consent=approve",
                {
                    method: "GET",
                    headers: { Origin: "https://example.com" },
                },
            ),
            {
                ...(await makeJwtConfig()),
                getUserId: async () => null, // not authenticated
            },
            makeApi({
                queries: {
                    getClient: async (_ctx: any, { clientId }: { clientId: string }) => ({
                        clientId,
                        type: "public" as const,
                        redirectUris: ["https://cb"],
                        allowedScopes: ["openid"],
                        tokenEndpointAuthMethod: "none" as const,
                    }),
                } as any,
            }),
        );

        expect(response.status).toBe(302);
        const redirect = new URL(response.headers.get("Location") as string);
        expect(redirect.searchParams.get("error")).toBe("login_required");
    });
});

describe("Bug 23: getSigningKeyId trusts config.keyId without checking the JWKS, producing JWTs that cannot be verified", () => {
    // `getSigningKeyId` returns `config.keyId` verbatim when it is set.
    // `getJWKS` keeps each key's existing `kid` unchanged. If those two
    // sources disagree (config says "xyz", JWKS publishes "abc"), every
    // freshly minted JWT carries `kid: "xyz"`, but the JWKS endpoint only
    // advertises `kid: "abc"`. A standards-conformant verifier looks up by
    // `kid` and rejects the token — the provider becomes a write-only key
    // factory.
    test("getSigningKeyId must refuse a keyId that isn't actually published in the JWKS", () => {
        const config: OAuthConfig = {
            privateKey: "",
            jwks: JSON.stringify({
                keys: [{ kty: "RSA", n: "abc", e: "AQAB", kid: "published-key" }],
            }),
            siteUrl: "https://example.com",
            keyId: "config-says-something-else", // mismatch with JWKS
        };
        expect(() => getSigningKeyId(config)).toThrow(/not present in JWKS/);
    });
});

describe("Bug 24: refresh_token grant leaks token state via resource/expiry errors before validating client ownership", () => {
    // Order of checks inside `tokenHandler`'s refresh-token branch:
    //   1. Token exists?               (returns "invalid_grant: Invalid refresh token")
    //   2. Resource binding matches?   (returns "invalid_target")
    //   3. Expiry not reached?         (returns "invalid_grant: Refresh token expired")
    //   4. clientId matches oldToken?  (returns "invalid_grant: Client mismatch")
    //
    // An attacker who *steals* a refresh token but doesn't know the originating
    // client can authenticate as a different (own) client and probe the token's
    // state by varying the `resource` parameter:
    //   - "invalid_target" → the token IS bound to a specific resource (≠ what I sent)
    //   - "invalid_grant: Client mismatch" → token has no resource binding
    //   - "invalid_grant: Refresh token expired" → token is past its expiry window
    // The right ordering is to validate `oldToken.clientId === clientId` FIRST and
    // surface a uniform "invalid_grant" for everything else.
    test("refresh_token grant must surface a uniform invalid_grant when clientId does not match oldToken", async () => {
        const jwtConfig = await makeJwtConfig();

        const response = await tokenHandler(
            {} as any,
            new Request("https://example.com/oauth/token", {
                method: "POST",
                body: new URLSearchParams({
                    grant_type: "refresh_token",
                    client_id: "attacker-client",
                    refresh_token: "stolen",
                    client_secret: "attacker-secret",
                    resource: "https://api.attacker.com/anything",
                }),
            }),
            jwtConfig,
            makeApi({
                queries: {
                    // Token belongs to a different client, but the attacker authenticated as their own client.
                    getRefreshToken: async () => ({
                        clientId: "victim-client",
                        userId: "victim-user",
                        scopes: ["openid", "offline_access"],
                        refreshTokenExpiresAt: Date.now() + 3_600_000,
                        resource: "https://api.victim.com/private", // bound to a different resource
                    }) as any,
                } as any,
            }),
        );

        const body = await response.json();
        // Today the attacker learns "invalid_target" (so they know the token is resource-bound)
        // BEFORE the clientId mismatch is ever checked.
        expect(body.error).toBe("invalid_grant");
    });
});

describe("Bug 25: OIDC discovery omits request_uri_parameter_supported, leaving its spec-defined default (=true) lying about behavior", () => {
    // OIDC Discovery 1.0 §3 lists the parameter defaults:
    //   request_uri_parameter_supported  default true
    //   request_parameter_supported      default false
    //   claims_parameter_supported       default false
    //
    // Our implementation does NOT process `request_uri` — \`authorizeHandler\` simply
    // ignores any \`request_uri=…\` query parameter. But the discovery response omits
    // `request_uri_parameter_supported`, so spec-conformant clients (OIDC certified
    // SDKs) read the default (true) and believe we honor it. They then send a
    // \`request_uri\` reference that we silently drop, taking them off the documented
    // request-object path with no warning.
    test("discovery response must explicitly publish request_uri_parameter_supported=false (or implement the parameter)", async () => {
        const response = await openIdConfigurationHandler(
            {} as any,
            new Request("https://example.com/.well-known/openid-configuration"),
            await makeJwtConfig(),
        );

        const body = await response.json();
        expect(body.request_uri_parameter_supported).toBe(false);
    });
});

describe("Bug 2: clientManagement.registerClient rejects IPv6 loopback http://[::1]/cb redirect_uri", () => {
    // The IsValidRedirectUri helper inside clientManagement also misses the bracketed form,
    // so DCR (and direct client registration) cannot persist a redirect URI built from
    // the IPv6 loopback literal — even though RFC 8252 explicitly authorises it.
    test("registerClient must accept http://[::1]:8080/cb as a valid redirect URI", async () => {
        const t = convexTest(schema, modules);
        await expect(
            t.mutation(api.clientManagement.registerClient, {
                name: "IPv6 Native App",
                type: "public",
                redirectUris: ["http://[::1]:8080/cb"],
                scopes: ["openid"],
            }),
        ).resolves.toMatchObject({ clientId: expect.any(String) });
    });
});
