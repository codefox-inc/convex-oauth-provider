# @codefox-inc/oauth-provider

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
