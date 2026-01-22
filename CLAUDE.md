# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is an OAuth 2.1 / OpenID Connect Provider implemented as a Convex component. It provides full OAuth 2.1 compliance with PKCE enforcement, JWT access tokens, refresh token rotation, and Dynamic Client Registration.

## Commands

```bash
# Development (starts Convex backend, Vite frontend, Cloudflare Worker, and build watcher)
npm run dev

# Build
npm run build              # TypeScript compilation
npm run build:codegen      # Generate Convex code + build
npm run build:clean        # Clean rebuild

# Testing
npm test                   # Run all tests
npm run test:watch         # Watch mode
npm test -- -t "test name" # Run single test by name
npm test -- src/component/__tests__/oauth.test.ts  # Run single file

# Quality
npm run typecheck          # TypeScript check (includes example/)
npm run lint               # ESLint
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
4. **API Access**: Client uses Bearer token → Convex validates via JWKS

### Component Tables

- `oauthClients`: Registered OAuth clients (clientId, redirectUris, allowedScopes)
- `oauthCodes`: Short-lived authorization codes (10 min, single-use)
- `oauthTokens`: Access/refresh tokens (hashed with SHA-256)
- `oauthAuthorizations`: User consent records (persists beyond token expiry)

## Key Implementation Details

### Security Requirements (OAuth 2.1)

- PKCE with S256 **required** for all flows (plain method rejected)
- Redirect URI exact match (with RFC 8252 localhost variable port exception)
- All tokens stored as SHA-256 hashes
- Client secrets hashed with bcrypt
- Authorization codes single-use with replay detection

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

## Example App

The `example/` directory contains a working implementation with:
- Task Manager UI with anonymous auth
- OAuth consent page (`/oauth/authorize`)
- MCP server on Cloudflare Workers (`/mcp`)

Live demo: https://oauth-provider-example.codefox-inc.workers.dev
