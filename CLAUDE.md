# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OAuth 2.1 / OpenID Connect Provider implemented as a Convex component. It provides full OAuth 2.1 compliance with PKCE enforcement, JWT access tokens, refresh token rotation, and Dynamic Client Registration.

## Commands

```bash
# Development (starts Convex backend, Vite frontend, Cloudflare Worker, and build watcher)
bun run dev

# Build
bun run build              # TypeScript compilation
bun run build:codegen      # Generate Convex code + build
bun run build:clean        # Clean rebuild

# Testing
bun run test                   # Run all tests
bun run test:watch             # Watch mode
bun run test -- -t "test name" # Run single test by name
bun run test -- src/component/__tests__/oauth.test.ts  # Run single file

# Quality
bun run typecheck          # TypeScript check (includes example/)
bun run lint               # ESLint
```

## Architecture

### Convex Component Structure

This is a **Convex component** (not a standalone app). The component lives in `src/component/` and is consumed by apps via `convex.config.ts`.

```
src/
├── client/           # SDK for consuming apps
│   ├── index.ts      # OAuthProvider class - main SDK entry point
│   ├── routes.ts     # registerOAuthRoutes() helper
│   └── auth-helper.ts # createAuthHelper() for unified auth
├── component/        # Convex component (backend)
│   ├── schema.ts     # Database tables (oauthClients, oauthCodes, oauthTokens, oauthAuthorizations)
│   ├── handlers.ts   # HTTP handlers (authorize, token, userinfo, register, jwks)
│   ├── mutations.ts  # Internal mutations (issueAuthorizationCode, consumeAuthCode, etc.)
│   ├── queries.ts    # Internal queries (getClient, getRefreshToken, etc.)
│   └── clientManagement.ts # Client registration/verification
├── lib/
│   └── oauth.ts      # JWT signing, token verification, PKCE, error handling
└── react/            # React hooks (optional)

example/              # Full working example
├── convex/           # Example Convex backend
├── src/              # React frontend with consent UI
└── worker/           # Cloudflare Worker for MCP server
```

### Key Data Flow

1. **Authorization**: Client → `/oauth/authorize` → validates → redirects to `SITE_URL` consent page
2. **Consent**: User approves → `issueAuthorizationCode()` → creates auth code + authorization record
3. **Token Exchange**: Client → `/oauth/token` with code + PKCE verifier → returns JWT access token
4. **Resource Access**: Resource servers validate the JWT access token using JWKS, issuer, `typ`, audience, and required scopes

### Component Tables

- `oauthClients`: Registered OAuth clients (clientId, redirectUris, allowedScopes)
- `oauthCodes`: Short-lived authorization codes (10 min, single-use)
- `oauthTokens`: Access/refresh tokens (hashed with SHA-256)
- `oauthAuthorizations`: User consent records (persists beyond token expiry)

## Key Implementation Details

### Security Requirements (OAuth 2.1)

- PKCE with S256 **required** for all flows (plain method rejected)
- Redirect URI exact match (with RFC 8252 loopback variable port exception only)
- RFC 8707 `resource` is bound to authorization codes and refresh tokens; token requests cannot add a new resource later
- JWT access tokens follow RFC 9068 conventions (`typ: at+jwt`, `client_id`, `scope`, `jti`)
- `offline_access` requires explicit OIDC consent (`prompt` contains `consent`)
- ID tokens include `auth_time`; `max_age` is handled safely when the host cannot prove the current authentication time
- All tokens stored as SHA-256 hashes
- Client secrets hashed with bcrypt
- Authorization codes single-use with replay detection

### Host Integration Notes

- Custom consent UIs must preserve the authorization request `resource` parameter and pass it to `OAuthProvider.issueAuthorizationCode`.
- Resource servers should terminate bearer tokens: verify `iss`, `aud`, `typ`, expiration, and scopes locally, then call their backend with an internal credential instead of passing the inbound OAuth token through.
- The example Worker uses `MCP_CONVEX_AUTH_TOKEN` as a Convex admin/internal Worker-to-Convex credential, then passes the verified OAuth `sub` into internal task functions for user scoping. This is example host plumbing, not an OAuth signing key.

### Testing

Tests use `convex-test` for mocking Convex. Test files are in `__tests__/` directories:
- `oauth.test.ts` - Full OAuth flow tests
- `rfc-compliance.test.ts` - OAuth 2.1 spec compliance tests
- `token-security.test.ts` - Token hashing tests

### Environment Variables

Required for OAuth Provider:
- `OAUTH_PRIVATE_KEY` - RSA private key (PEM format)
- `OAUTH_JWKS` - JSON Web Key Set
- `SITE_URL` - App's public URL (consent page location)
- `CONVEX_SITE_URL` - Convex deployment URL (issuer)

Example Worker:
- `MCP_CONVEX_AUTH_TOKEN` - Convex admin/internal credential used after inbound MCP access token verification
- `MCP_RESOURCE` - Optional canonical MCP protected resource URI; defaults to the Worker `/mcp` URL

## Example App

The `example/` directory contains a working implementation with:
- Task Manager UI with anonymous auth
- OAuth consent page (`/oauth/authorize`)
- MCP server on Cloudflare Workers (`/mcp`)

Live demo: https://oauth-provider-example.codefox-inc.workers.dev
