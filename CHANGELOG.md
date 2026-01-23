# @codefox-inc/oauth-provider

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
