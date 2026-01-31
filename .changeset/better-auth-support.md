---
"@codefox-inc/oauth-provider": minor
---

Add Better Auth support and applicationID configuration

### New features

- Added `applicationID` option to customize JWT audience claim (default: `"convex"`)
- Useful for distinguishing OAuth tokens from other authentication systems (e.g., set `applicationID: "my-oauth"` when using Better Auth)

### Breaking changes

- `verifyAccessToken` now only accepts config object with `jwks`, PEM string support removed
- Migration: Replace `verifyAccessToken(token, pemString, issuer)` with `verifyAccessToken(token, { jwks }, issuer)`

### Documentation

- Updated README to support both Convex Auth and Better Auth
- Added collapsible sections for detailed documentation
- Added examples for Better Auth integration
- Added tests for `applicationID` audience behavior
