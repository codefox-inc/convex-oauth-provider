# @codefox-inc/oauth-provider

## 0.4.2

### Patch Changes

- b280a4d: Fix several OAuth/OIDC compliance and security issues in the
  authorization, token, discovery, and userinfo flows.
  - Detect refresh-token reuse during rotation and revoke the full refresh-token
    family plus the stored authorization record.
  - Revoke stored authorizations when authorization-code replay is detected, so
    resource servers that check authorization records can reject already-issued
    access tokens.
  - Preserve used authorization-code tombstones while descendant refresh tokens
    are still valid, keeping replay detection effective across refresh-token
    rotations.
  - Honor OIDC `prompt=none` semantics by returning `login_required` or
    `consent_required` when needed, and by allowing silent success when existing
    consent already covers the requested scopes and resource.
  - Tighten token endpoint validation for conflicting client authentication,
    missing `grant_type`, refresh-token client ownership, refresh-token resource
    binding, and refresh-token scope preservation.
  - Improve protocol metadata and response behavior for discovery, userinfo,
    redirect URI handling, client-secret verification, and JWKS key selection.

  After upgrading, regenerate Convex component references and ensure resource
  servers wire authorization checks if they need revocation to affect
  already-issued JWT access tokens before `exp`. Newly issued client secrets now
  fit within bcrypt's 72-byte input limit; existing longer secrets remain
  accepted for patch-release compatibility and should be rotated when practical
  to fully remove bcrypt truncation exposure.

## 0.4.1

### Patch Changes

- Preserve provider-supported `offline_access` for dynamically registered
  clients so later consent requests can issue refresh tokens.

## 0.4.0

### Minor Changes

- e8e06f8: Improve OAuth/OIDC/MCP protocol compliance.
  - Bind RFC 8707 `resource` values to authorization codes and refresh tokens,
    and use the approved resource as the JWT access token audience.
  - Emit RFC 9068-style access tokens with `typ`, `client_id`, `scope`, and
    `jti`, and accept both `at+jwt` and `application/at+jwt` during
    verification.
  - Tighten redirect URI, PKCE, client authentication method, DCR,
    `offline_access`, `max_age`, and UserInfo challenge handling.
  - Add `resource` support to the public authorization-code helper and example
    consent flow.
  - Update the example MCP Worker to validate inbound bearer tokens as a
    resource server and avoid passing client access tokens through to Convex.

  Host migration note: custom consent flows must preserve the `resource`
  authorization request parameter and pass it to `issueAuthorizationCode`.
  Example MCP deployments also need an internal Worker-to-Convex credential such
  as `MCP_CONVEX_AUTH_TOKEN`; the example uses it as a Convex admin/internal
  credential and passes the verified OAuth `sub` into internal task functions
  for user scoping.

## 0.3.2

### Patch Changes

- 305247a: Fix DCR failure in Convex mutations by replacing async bcrypt methods
  with sync variants

  `bcrypt.hash()` and `bcrypt.compare()` use `setTimeout` internally, which is
  not allowed in Convex queries and mutations. Replaced with `bcrypt.hashSync()`
  and `bcrypt.compareSync()`.

## 0.3.1

### Patch Changes

- 6a8a9e7: Update dependencies to resolve security vulnerabilities
  - @modelcontextprotocol/sdk ^1.25.3 → ^1.27.1 (cross-client data leak fix)
  - hono ^4.11.7 → ^4.12.8 (serveStatic, cookie/SSE injection fixes)
  - wrangler ^4.15.2 → ^4.75.0 (undici vulnerabilities)
  - pkg-pr-new ^0.0.62 → ^0.0.66 (undici vulnerabilities)
  - convex 1.31.6 → 1.34.0

## 0.3.0

### Minor Changes

- 6cf70ad: Add Better Auth support and applicationID configuration

  ### New features
  - Added `applicationID` option to customize JWT audience claim (default:
    `"convex"`)
  - Useful for distinguishing OAuth tokens from other authentication systems
    (e.g., set `applicationID: "my-oauth"` when using Better Auth)

  ### Breaking changes
  - `verifyAccessToken` now only accepts config object with `jwks`, PEM string
    support removed
  - Migration: Replace `verifyAccessToken(token, pemString, issuer)` with
    `verifyAccessToken(token, { jwks }, issuer)`

  ### Documentation
  - Updated README to support both Convex Auth and Better Auth
  - Added collapsible sections for detailed documentation
  - Added examples for Better Auth integration
  - Added tests for `applicationID` audience behavior

## 0.2.4

### Patch Changes

- 3c8255a: Update hono to 4.11.7 to fix security vulnerabilities
  - Fixes cache middleware ignoring `Cache-Control: private` leading to Web
    Cache Deception
  - Fixes arbitrary key read in Serve static Middleware (Cloudflare Workers
    Adapter)

## 0.2.3

### Patch Changes

- a666b2d: Improve README documentation
  - Add "Why?" section explaining the motivation (MCP clients require OAuth)
  - Simplify environment variable setup (use Convex Auth defaults:
    JWT_PRIVATE_KEY, JWKS)
  - Remove confusing Environment Variables Reference section
  - Streamline code examples

## 0.2.2

### Patch Changes

- a4f4041: Fix DCR to use config.allowedScopes as default when client omits
  scope

  Previously, when a client registered via DCR without specifying scopes, it
  defaulted to hardcoded `["openid", "profile", "email"]`. This could conflict
  with custom `allowedScopes` configurations.

  Now, unspecified scopes default to `config.allowedScopes`, ensuring clients
  receive all provider-supported scopes.

## 0.2.1

### Patch Changes

- ddd1e48: Fix ESM import extensions for Node.js compatibility

  Added `.js` extensions to all relative imports in component files to ensure
  proper ESM module resolution in Node.js environments.

## 0.2.0

### Minor Changes

- 6cc7bac: Initial release of OAuth 2.1/OpenID Connect Provider for Convex
  - OAuth 2.1 compliant authorization and token endpoints
  - OpenID Connect Discovery support
  - PKCE required (S256 only)
  - Secure token storage with SHA-256 hashing
  - JWT access tokens with RS256 signing
  - Refresh token rotation
  - Dynamic client registration (opt-in)
  - Authorization management for user consent tracking
  - RFC 8252 loopback redirect URI support

## 0.1.0

### Minor Changes

- Initial release of OAuth 2.1 / OpenID Connect Provider as a Convex component
  - OAuth 2.1 compliant token endpoint
  - OpenID Connect Discovery
  - JWKS endpoint
  - UserInfo endpoint
  - Dynamic client registration
  - PKCE support
  - JWT access tokens
