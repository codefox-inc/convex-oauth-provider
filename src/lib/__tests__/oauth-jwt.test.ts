import { describe, it, expect, beforeEach } from "vitest";
import {
    sign,
    verifyAccessToken,
    getJWKS,
    getPublicJWK,
    resetKeysForTest,
    getIssuerUrl,
    getAllowedOrigin,
    createCorsHeaders,
    handleCorsOptions,
    OAuthError,
    getSigningKeyId,
} from "../oauth";
import type { OAuthConfig } from "../oauth";

// Test keys generated with OpenSSL
const TEST_PRIVATE_KEY = `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDUpgMiz+zobsK9
kFcnKhPBilSSIdkm0+/B/Af/Cy2qgQKdU5KvjBEM3N22Ie3PgcyQ1Qk9x6KnyHpS
CWMhPDd+76Ite1Ae8jx+q/N6NeLaaWb2wTx4c9QnKPxS4dBsf0L3eiiLGC8fHLfC
nro97I/87Lef1aiL+Dk9Le8ZOD82dckYSUxuI9Ds0yp1fxhfMy2GixKr1z2BSPSc
EPgcLFs8urNaQAQTXR9OQnTyMXPCuGhrGzn3pXLqUCDguNEH1Id3NdMazJ1CmLhQ
u1R4QEXO8+NkfivNVqa2vGfQpFDQJdTQCD1ue21ZsF1W9fIcmXQU4M05IbtaildD
/PsrSIK9AgMBAAECggEAJSuqtypYy01XIZsqPNiUUPus6klb47devM4hGLIbxqbb
7ePGq4Rkk5bE85oNL31NJJD0l1W+5yy6Qv5Mk2nq+neJZgFc4TfvHqZQfk+Oiqar
fp0LBLQchMbbimJaFCkPq+Iw1ZWB4SKcNXsY64ufJLM9KsWGe4cFfF374jDsjchp
50AIL4RrimLaWKp1yWgRcWToBWjaoAEdjMiGKOQkite8JwkZZYRSMqAWX7LnOV4q
gRG8sGLtyWSGpXWZYvTf5kPqZ4qYWicKro7BorYeSCcZuJG7AWZBrx9TpD7L+LFc
R49UZAdDt/pdipvRrryCG/NIpAKK3WBGOD3C203TuQKBgQDv96VLRwKez1S28VUu
aL8P72gPnSEn9O0sC1B6EKCRDoxP2o6qvUKvycsYcJuaBEmNoqqsEBozwNJK6qL7
QO63ctj2KU1JAn1WgZmAl+pqOqZ3mX8PdLTsw/9aTxMmBN/LMw2dcs3l7tWjm+ju
vhqSJ9iTQTcqLwt79KPmKIWnaQKBgQDi2xwey3ucHzHXTNZVB4vsh1izwKl9rqT3
2/bV6jKiBJCucbFC13VxqIn0Nm07NY+cxVEfjvsPmczDlj7M4EW2NAs8xINe5KY0
VizyS/PBU62N8kLTW8Vt3vvO2XmyuBH5v6uI8OuCD1YobpauF5+4FoKiiLKNSIsY
U+PxeOTKNQKBgGmh2OhfNN8Vo1P4vid0wo5QM72TzJGbNoAJ5v4krZnNDqTkL6Mn
NuDM8pMqlsRgmMQ5U+n0GKSpf6isytvRRIQKkUki+ztlVikrWZgKx4zFjpvdPNpf
5HjI+nIVlvdIc/8t1RN3Av3xeafQrOPTWTz3P1XrAk6WcPa6xR8+vT7pAoGAY25w
O9sqWbqeiOSnyOse3FRSf68BWxISQoVKAma9PKBNnfg9HrP7SQ77MGwuolYOlUMz
FGcCCct6oXuYGQpv47WZ+0+S2SPU6XmgB69crq7zkhTOT3+Y4Fhs/DP8EGZ3koT9
NW+Leh0owV3/c1ztZ62OIplR0XUrakVS0oMPnMUCgYBph0Dx9paH59ZkdNE0ZSTF
PXPCPi93VdlvHrMzULUNYiFSE/o8PMpV3D7UTlqiBwd4vPGVjawrPZRtuqEuZJcV
VtHxjpq0V41wXi/Dn5gSJwJjEUGaI5ftADIZFwOGy+DIOrC1XYvWMQlYp2ML6Q7w
xVl8tka0TkDpXl5tvvqy9A==
-----END PRIVATE KEY-----`;

const TEST_PUBLIC_KEY = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1KYDIs/s6G7CvZBXJyoT
wYpUkiHZJtPvwfwH/wstqoECnVOSr4wRDNzdtiHtz4HMkNUJPceip8h6UgljITw3
fu+iLXtQHvI8fqvzejXi2mlm9sE8eHPUJyj8UuHQbH9C93ooixgvHxy3wp66PeyP
/Oy3n9Woi/g5PS3vGTg/NnXJGElMbiPQ7NMqdX8YXzMthosSq9c9gUj0nBD4HCxb
PLqzWkAEE10fTkJ08jFzwrhoaxs596Vy6lAg4LjRB9SHdzXTGsydQpi4ULtUeEBF
zvPjZH4rzVamtrxn0KRQ0CXU0Ag9bnttWbBdVvXyHJl0FODNOSG7WopXQ/z7K0iC
vQIDAQAB
-----END PUBLIC KEY-----`;

const TEST_JWKS = JSON.stringify({
    keys: [
        {
            kty: "RSA",
            n: "1KYDIs_s6G7CvZBXJyoTwYpUkiHZJtPvwfwH_wstqoECnVOSr4wRDNzdtiHtz4HMkNUJPceip8h6UgljITw3fu-iLXtQHvI8fqvzejXi2mlm9sE8eHPUJyj8UuHQbH9C93ooixgvHxy3wp66PeyP_Oy3n9Woi_g5PS3vGTg_NnXJGElMbiPQ7NMqdX8YXzMthosSq9c9gUj0nBD4HCxbPLqzWkAEE10fTkJ08jFzwrhoaxs596Vy6lAg4LjRB9SHdzXTGsydQpi4ULtUeEBFzvPjZH4rzVamtrxn0KRQ0CXU0Ag9bnttWbBdVvXyHJl0FODNOSG7WopXQ_z7K0iCvQ",
            e: "AQAB",
            use: "sig",
            alg: "RS256",
            kid: "test-key-1"
        }
    ]
});
const TEST_JWKS_NO_KID = JSON.stringify({
    keys: [
        {
            kty: "RSA",
            n: "1KYDIs_s6G7CvZBXJyoTwYpUkiHZJtPvwfwH_wstqoECnVOSr4wRDNzdtiHtz4HMkNUJPceip8h6UgljITw3fu-iLXtQHvI8fqvzejXi2mlm9sE8eHPUJyj8UuHQbH9C93ooixgvHxy3wp66PeyP_Oy3n9Woi_g5PS3vGTg_NnXJGElMbiPQ7NMqdX8YXzMthosSq9c9gUj0nBD4HCxbPLqzWkAEE10fTkJ08jFzwrhoaxs596Vy6lAg4LjRB9SHdzXTGsydQpi4ULtUeEBFzvPjZH4rzVamtrxn0KRQ0CXU0Ag9bnttWbBdVvXyHJl0FODNOSG7WopXQ_z7K0iCvQ",
            e: "AQAB",
            use: "sig",
            alg: "RS256",
        }
    ]
});

describe("OAuth JWT and Utilities", () => {
    beforeEach(() => {
        resetKeysForTest();
    });

    describe("JWT Signing and Verification", () => {
        it("should sign a JWT", async () => {
            const token = await sign(
                { custom: "claim" },
                "user123",
                "test-audience",
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com"
            );

            expect(token).toBeDefined();
            expect(typeof token).toBe("string");
            expect(token.split(".")).toHaveLength(3); // JWT has 3 parts
        });

        it("should verify a signed JWT", async () => {
            const token = await sign(
                { custom: "claim" },
                "user123",
                "test-audience",
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com",
                "test-key-1"  // Match the kid in TEST_JWKS
            );

            const payload = await verifyAccessToken(
                token,
                { jwks: TEST_JWKS },
                "https://example.com",
                "test-audience"
            );

            expect(payload.sub).toBe("user123");
            expect(payload.aud).toBe("test-audience");
            expect(payload.iss).toBe("https://example.com");
        });

        it("should verify with JWKS missing kid", async () => {
            const token = await sign(
                { custom: "claim" },
                "user123",
                "test-audience",
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com"
            );
            const config: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: TEST_JWKS_NO_KID,
                privateKey: TEST_PRIVATE_KEY,
            };

            const payload = await verifyAccessToken(
                token,
                config,
                "https://example.com",
                "test-audience"
            );

            expect(payload.sub).toBe("user123");
        });

        it("should fail verification with wrong audience", async () => {
            const token = await sign(
                {},
                "user123",
                "correct-audience",
                "1h",
                TEST_PRIVATE_KEY,
                "",
                "test-key-1"  // Match the kid in TEST_JWKS
            );

            await expect(
                verifyAccessToken(token, { jwks: TEST_JWKS }, "", "wrong-audience")
            ).rejects.toThrow();
        });

        it("should use applicationID as default audience", async () => {
            const token = await sign(
                {},
                "user123",
                "oauth-provider",  // audience matches applicationID
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com",
                "test-key-1"
            );

            const payload = await verifyAccessToken(
                token,
                { jwks: TEST_JWKS, applicationID: "oauth-provider" },
                "https://example.com"
                // No expectedAudience - should use applicationID
            );

            expect(payload.sub).toBe("user123");
            expect(payload.aud).toBe("oauth-provider");
        });

        it("should default to 'convex' when applicationID is not set", async () => {
            const token = await sign(
                {},
                "user123",
                "convex",  // default audience
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com",
                "test-key-1"
            );

            const payload = await verifyAccessToken(
                token,
                { jwks: TEST_JWKS },  // No applicationID
                "https://example.com"
                // No expectedAudience - should default to "convex"
            );

            expect(payload.sub).toBe("user123");
            expect(payload.aud).toBe("convex");
        });

        it("should prefer expectedAudience over applicationID", async () => {
            const token = await sign(
                {},
                "user123",
                "explicit-audience",  // matches expectedAudience
                "1h",
                TEST_PRIVATE_KEY,
                "https://example.com",
                "test-key-1"
            );

            const payload = await verifyAccessToken(
                token,
                { jwks: TEST_JWKS, applicationID: "oauth-provider" },
                "https://example.com",
                "explicit-audience"  // This should take precedence
            );

            expect(payload.sub).toBe("user123");
            expect(payload.aud).toBe("explicit-audience");
        });
    });

    describe("JWKS Functions", () => {
        it("should get JWKS from config", async () => {
            const config: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: TEST_JWKS,
                privateKey: TEST_PRIVATE_KEY
            };

            const jwks = await getJWKS(config);
            expect(jwks.keys).toHaveLength(1);
            expect(jwks.keys[0].kty).toBe("RSA");
            expect(jwks.keys[0].kid).toBe("test-key-1"); // Preserves existing kid
        });

        it("should add default kid when missing", async () => {
            const jwksWithoutKid = JSON.stringify({
                keys: [{
                    kty: "RSA",
                    n: "test",
                    e: "AQAB"
                }]
            });
            const config: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: jwksWithoutKid,
                privateKey: TEST_PRIVATE_KEY
            };

            const jwks = await getJWKS(config);
            expect(jwks.keys[0].kid).toBe("default-key"); // Should add default kid
        });

        it("should get public JWK from PEM", async () => {
            const jwk = await getPublicJWK(TEST_PUBLIC_KEY);
            expect(jwk.kty).toBe("RSA");
            expect(jwk.use).toBe("sig");
            expect(jwk.alg).toBe("RS256");
            expect(jwk.kid).toBe("default-key");
        });

        it("should strip private JWK parameters", async () => {
            const jwksWithPrivate = JSON.stringify({
                keys: [{
                    kty: "RSA",
                    n: "test",
                    e: "AQAB",
                    d: "private",
                    p: "private",
                    q: "private",
                }]
            });
            const config: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: jwksWithPrivate,
                privateKey: TEST_PRIVATE_KEY
            };

            const jwks = await getJWKS(config);
            expect(jwks.keys[0].d).toBeUndefined();
            expect(jwks.keys[0].p).toBeUndefined();
            expect(jwks.keys[0].q).toBeUndefined();
        });

        it("should cache JWK results", async () => {
            const jwk1 = await getPublicJWK(TEST_PUBLIC_KEY);
            const jwk2 = await getPublicJWK(TEST_PUBLIC_KEY);
            expect(jwk1).toBe(jwk2); // Same reference = cached
        });
    });

    describe("Utility Functions", () => {
        it("should get issuer URL", () => {
            const config: OAuthConfig = {
                siteUrl: "https://example.com",
                privateKey: TEST_PRIVATE_KEY,
                jwks: TEST_JWKS
            };
            expect(getIssuerUrl(config)).toBe("https://example.com/oauth");
        });

        it("should prefer convexSiteUrl for issuer", () => {
            const config: OAuthConfig = {
                siteUrl: "https://wrong.com",
                convexSiteUrl: "https://correct.convex.site",
                privateKey: TEST_PRIVATE_KEY,
                jwks: TEST_JWKS
            };
            expect(getIssuerUrl(config)).toBe("https://correct.convex.site/oauth");
        });

        it("should resolve signing key id from config", () => {
            const configFromJwks: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: TEST_JWKS,
                privateKey: TEST_PRIVATE_KEY
            };
            expect(getSigningKeyId(configFromJwks)).toBe("test-key-1");

            const configWithOverride: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: TEST_JWKS,
                privateKey: TEST_PRIVATE_KEY,
                keyId: "override-key"
            };
            expect(getSigningKeyId(configWithOverride)).toBe("override-key");

            const configWithMissingKid: OAuthConfig = {
                siteUrl: "https://example.com",
                jwks: TEST_JWKS_NO_KID,
                privateKey: TEST_PRIVATE_KEY
            };
            expect(getSigningKeyId(configWithMissingKid)).toBe("default-key");
        });
    });

    describe("CORS Functions", () => {
        const config: OAuthConfig = {
            siteUrl: "https://example.com",
            allowedOrigins: "https://app1.com,https://app2.com",
            privateKey: TEST_PRIVATE_KEY,
            jwks: TEST_JWKS
        };

        it("should allow null origin (CLI clients)", () => {
            expect(getAllowedOrigin(null, config)).toBeNull();
        });

        it("should allow explicitly listed origins", () => {
            expect(getAllowedOrigin("https://app1.com", config)).toBe("https://app1.com");
            expect(getAllowedOrigin("https://app2.com", config)).toBe("https://app2.com");
        });

        it("should allow siteUrl as origin", () => {
            expect(getAllowedOrigin("https://example.com", config)).toBe("https://example.com");
        });

        it("should allow convexSiteUrl as origin", () => {
            const configWithConvex: OAuthConfig = {
                ...config,
                convexSiteUrl: "https://test.convex.site"
            };
            expect(getAllowedOrigin("https://test.convex.site", configWithConvex))
                .toBe("https://test.convex.site");
        });

        it("should allow localhost origins", () => {
            expect(getAllowedOrigin("http://localhost:3000", config)).toBe("http://localhost:3000");
            expect(getAllowedOrigin("http://localhost", config)).toBe("http://localhost");
            expect(getAllowedOrigin("http://127.0.0.1:8080", config)).toBe("http://127.0.0.1:8080");
        });

        it("should reject unlisted origins", () => {
            expect(getAllowedOrigin("https://evil.com", config)).toBeNull();
        });

        it("should create CORS headers", () => {
            const headers = createCorsHeaders("https://app1.com", config);
            expect(headers["Access-Control-Allow-Origin"]).toBe("https://app1.com");
            expect(headers["Access-Control-Allow-Methods"]).toBe("GET, POST, OPTIONS");
            expect(headers["Content-Type"]).toBe("application/json");
        });

        it("should create CORS headers with null origin", () => {
            const headers = createCorsHeaders(null, config);
            expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
        });

        it("should omit Access-Control-Allow-Origin for unlisted origins", () => {
            const headers = createCorsHeaders("https://evil.com", config);
            expect(headers["Access-Control-Allow-Origin"]).toBeUndefined();
        });

        it("should handle OPTIONS preflight", () => {
            const request = new Request("https://example.com/test", {
                method: "OPTIONS",
                headers: { "Origin": "https://app1.com" }
            });

            const response = handleCorsOptions(request, config);
            expect(response).not.toBeNull();
            expect(response?.status).toBe(200);
            expect(response?.headers.get("Access-Control-Allow-Origin")).toBe("https://app1.com");
        });

        it("should return null for non-OPTIONS requests", () => {
            const request = new Request("https://example.com/test", {
                method: "GET"
            });

            const response = handleCorsOptions(request, config);
            expect(response).toBeNull();
        });
    });

    describe("OAuthError", () => {
        it("should create OAuth error", () => {
            const error = new OAuthError("invalid_request", "Missing parameter");
            expect(error.code).toBe("invalid_request");
            expect(error.message).toBe("Missing parameter");
            expect(error.statusCode).toBe(400);
            expect(error.name).toBe("OAuthError");
        });

        it("should create error with custom status code", () => {
            const error = new OAuthError("unauthorized", "Access denied", 401);
            expect(error.statusCode).toBe(401);
        });

        it("should convert to Response", () => {
            const error = new OAuthError("invalid_grant", "Token expired", 400);
            const response = error.toResponse({ "X-Custom": "header" });

            expect(response.status).toBe(400);
            expect(response.headers.get("X-Custom")).toBe("header");
        });

        it("should format error response correctly", async () => {
            const error = new OAuthError("invalid_client", "Client not found");
            const response = error.toResponse({});
            const body = await response.json();

            expect(body).toEqual({
                error: "invalid_client",
                error_description: "Client not found"
            });
        });
    });

    describe("Key Caching", () => {
        it("should reset key cache", async () => {
            // First call - cache miss
            await getPublicJWK(TEST_PUBLIC_KEY);

            // Reset cache
            resetKeysForTest();

            // Should work after reset
            const jwk = await getPublicJWK(TEST_PUBLIC_KEY);
            expect(jwk).toBeDefined();
        });
    });
});
