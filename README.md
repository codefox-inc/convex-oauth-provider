# @codefox-inc/oauth-provider

OAuth 2.1 / OpenID Connect Provider implemented as a Convex component.

> **⚠️ Beta Software** - Production use at your own risk.

Tested with [Convex Auth](https://labs.convex.dev/auth) and [@convex-dev/better-auth](https://labs.convex.dev/better-auth).

## Why?

Most MCP clients (like Claude Code or ChatGPT) require your app to be an OAuth provider. If you want to connect your Convex app to MCP clients, you need to implement OAuth 2.1.

This component turns your Convex app into a fully compliant OAuth 2.1 provider, so you can:
- Connect to MCP clients out of the box
- Let clients register automatically via Dynamic Client Registration
- Let users control what permissions each app gets
- Focus on your app, not OAuth complexity

## Installation

```bash
npm install @codefox-inc/oauth-provider
```

## Features

- **OAuth 2.1 compliant** authorization and token endpoints
- **OpenID Connect Discovery** for automatic client configuration
- **PKCE required** for all authorization code flows (S256 only)
- **Secure token storage** using SHA-256 hashing for tokens and authorization codes
- **JWT access tokens** with RS256 signing
- **Refresh token rotation** for enhanced security
- **Dynamic client registration** (opt-in)
- **Authorization management** for user consent tracking
- **JWKS endpoint** for token verification

<details>
<summary><strong>OAuth 2.1 Compliance</strong></summary>

This implementation follows [OAuth 2.1 (draft-ietf-oauth-v2-1-14)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-14) specification:

### Supported Grant Types
- ✅ **Authorization Code with PKCE** (public and confidential clients)
- ✅ **Refresh Token** (with token rotation)

### Unsupported Features (OAuth 2.0 Legacy)
- ❌ **Implicit Grant** (removed in OAuth 2.1 for security reasons)
- ❌ **Resource Owner Password Credentials Grant** (removed in OAuth 2.1)
- ❌ **PKCE Plain Method** (only S256 is supported per OAuth 2.1 best practices)

### Key Security Requirements
- **PKCE Enforcement**: All authorization code flows require PKCE with S256 method
- **Redirect URI Validation**: Exact string matching (with localhost variable port exception per RFC 8252)
- **Authorization Code**: Single-use, expires in 10 minutes
- **Token Hashing**: All tokens stored as SHA-256 hashes
- **Refresh Token Rotation**: New refresh token issued on each use, old token invalidated

</details>

<details>
<summary><strong>Security Features</strong></summary>

### Built-in Security Controls

- **PKCE Enforcement**: All authorization code flows require PKCE (code_challenge/code_verifier)
- **Redirect URI Validation**: Strict checking against registered URIs
- **Scope Validation**: Only registered scopes are allowed per client
- **Token Hashing**: Access and refresh tokens are stored as SHA-256 hashes
- **Client Secret Hashing**: Confidential client secrets use bcrypt
- **Internal Mutations**: Critical operations like `issueAuthorizationCode` are not directly accessible
- **DCR Disabled by Default**: Dynamic Client Registration must be explicitly enabled

### Authorization Flow Security

The `/oauth/authorize` endpoint performs comprehensive validation:
1. Client ID verification
2. Redirect URI matching against registered URIs
3. Scope validation against client's allowed scopes
4. PKCE requirement (code_challenge with S256 method)
5. User authentication via `getUserId` hook

</details>

<details>
<summary><strong>Scopes and Token Types</strong></summary>

### Supported Scopes

- **`openid`**: Required for OpenID Connect authentication and ID tokens
- **`profile`**: Grants access to user profile information (name, picture)
- **`email`**: Grants access to user email address
- **`offline_access`**: Enables refresh token issuance for long-lived access

### Refresh Token Requirements

Refresh tokens are **only issued** when the `offline_access` scope is requested and granted during the initial authorization:

- ✅ **With `offline_access`**: Client receives both access token and refresh token
- ❌ **Without `offline_access`**: Client receives only access token (no refresh token)

**Refresh Token Grant Flow:**
- Use the `refresh_token` grant type to obtain new access tokens
- The original authorization must have included the `offline_access` scope
- Refresh tokens are automatically rotated on each use (old token is invalidated)
- The new refresh token maintains the same scope as the original

This follows OAuth 2.1 and OpenID Connect specifications, ensuring that long-lived refresh tokens are only issued with explicit user consent.

</details>

## OAuth Token Detection Helper

Provides helper functions to distinguish between OAuth tokens and session tokens:

```typescript
import { isOAuthToken, getOAuthClientId } from "@codefox-inc/oauth-provider";

const identity = await ctx.auth.getUserIdentity();

if (isOAuthToken(identity)) {
    // Handle OAuth token (MCP client, third-party apps, etc.)
    const clientId = getOAuthClientId(identity);
    console.log("OAuth client:", clientId);
} else {
    // Handle Convex Auth session (first-party user)
}
```

## Setup

### 1. Set Environment Variables

This component works with any authentication system. Choose the setup that matches your stack:

#### Option A: With Convex Auth

If you're using [Convex Auth](https://labs.convex.dev/auth), you already have the required environment variables configured (`JWT_PRIVATE_KEY`, `JWKS`, `SITE_URL`).

#### Option B: With Better Auth

If you're using [@convex-dev/better-auth](https://labs.convex.dev/better-auth), you can share the same keys:

```bash
npx convex env set OAUTH_PRIVATE_KEY "$(cat private.pem)"  # Or use JWT_PRIVATE_KEY
npx convex env set OAUTH_JWKS '{"keys":[...]}'             # Or use JWKS
npx convex env set SITE_URL "https://your-app.example.com"
```

**Important:** When using Better Auth, set `applicationID: "oauth-provider"` in your OAuthProvider config to distinguish OAuth tokens from Better Auth session tokens.

<details>
<summary><strong>Option C: Manual Setup</strong></summary>

Generate RSA keys manually:

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Generate JWKS (use https://mkjwk.org or this script)
node -e "
const jose = require('jose');
const fs = require('fs');
const privateKey = fs.readFileSync('private.pem', 'utf8');
(async () => {
  const key = await jose.importPKCS8(privateKey, 'RS256');
  const jwk = await jose.exportJWK(key);
  console.log(JSON.stringify({ keys: [{ ...jwk, use: 'sig', alg: 'RS256', kid: 'default-key' }] }));
})();
"
```

Set environment variables:

```bash
npx convex env set JWT_PRIVATE_KEY "-----BEGIN RSA PRIVATE KEY-----\n..."
npx convex env set JWKS '{"keys":[...]}'
npx convex env set SITE_URL "https://your-app.example.com"
```

</details>

### 2. Register Component

```typescript
// convex/convex.config.ts
import { defineApp } from "convex/server";
import oauthProvider from "@codefox-inc/oauth-provider/convex.config";

const app = defineApp();
app.use(oauthProvider, { name: "oauthProvider" });

export default app;
```

### 3. Configure HTTP Routes

#### Option A: Using the Helper Function (Recommended)

```typescript
// convex/http.ts
import { httpAction } from "./_generated/server";
import { httpRouter } from "convex/server";
import { OAuthProvider, registerOAuthRoutes } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";
import { api } from "./_generated/api";

const http = httpRouter();

const oauthProvider = new OAuthProvider(components.oauthProvider, {
    privateKey: process.env.JWT_PRIVATE_KEY!,
    jwks: process.env.JWKS!,
    siteUrl: process.env.SITE_URL!,

    // REQUIRED: Authenticate user for authorization endpoint
    getUserId: async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity();
        return identity?.subject ?? null;
    },
});

// Register all OAuth routes automatically
registerOAuthRoutes(http, httpAction, oauthProvider, {
    siteUrl: process.env.SITE_URL!,
    // OPTIONAL: Override the prefix used for route registration.
    // By default, this uses oauthProvider's config prefix.
    // prefix: "/oauth",
    getUserProfile: async (ctx, userId) => {
        // Return user profile for /oauth/userinfo endpoint
        const user = await ctx.runQuery(api.users.get, { userId });
        return user ? {
            sub: userId,
            name: user.name,
            email: user.email,
            picture: user.pictureUrl
        } : null;
    },
});

export default http;
```

#### Option B: With Better Auth

```typescript
// convex/http.ts
import { httpAction } from "./_generated/server";
import { httpRouter } from "convex/server";
import { OAuthProvider, registerOAuthRoutes } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";
import { api } from "./_generated/api";

const http = httpRouter();

const oauthProvider = new OAuthProvider(components.oauthProvider, {
    privateKey: process.env.OAUTH_PRIVATE_KEY ?? process.env.JWT_PRIVATE_KEY!,
    jwks: process.env.OAUTH_JWKS ?? process.env.JWKS!,
    siteUrl: process.env.SITE_URL!,

    // IMPORTANT: Set applicationID to distinguish from Better Auth tokens
    applicationID: "oauth-provider",

    getUserId: async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity();
        return identity?.subject ?? null;
    },
});

// Register Better Auth routes first (if using @convex-dev/better-auth)
// authComponent.registerRoutes(http, createAuth, { cors: true });

// Then register OAuth routes
registerOAuthRoutes(http, httpAction, oauthProvider, {
    siteUrl: process.env.SITE_URL!,
    getUserProfile: async (ctx, userId) => {
        const user = await ctx.runQuery(api.users.get, { userId });
        return user ? {
            sub: userId,
            name: user.name,
            email: user.email,
            picture: user.pictureUrl
        } : null;
    },
});

export default http;
```

<details>
<summary><strong>Option C: Manual Route Registration</strong></summary>

```typescript
// convex/http.ts
import { httpAction } from "./_generated/server";
import { httpRouter } from "convex/server";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";

const http = httpRouter();

const oauthProvider = new OAuthProvider(components.oauthProvider, {
    privateKey: process.env.JWT_PRIVATE_KEY!,
    jwks: process.env.JWKS!,
    siteUrl: process.env.SITE_URL!,

    // REQUIRED: Authenticate user for authorization endpoint
    getUserId: async (ctx, request) => {
        const identity = await ctx.auth.getUserIdentity();
        return identity?.subject ?? null;
    },
});

// OpenID Connect Discovery
http.route({
    path: "/oauth/.well-known/openid-configuration",
    method: "GET",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.openIdConfiguration(ctx, req)
    ),
});

// JWKS endpoint
http.route({
    path: "/oauth/.well-known/jwks.json",
    method: "GET",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.jwks(ctx, req)
    ),
});

// Authorization endpoint (validates and issues auth codes)
http.route({
    path: "/oauth/authorize",
    method: "GET",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.authorize(ctx, req)
    ),
});

// Token endpoint
http.route({
    path: "/oauth/token",
    method: "POST",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.token(ctx, req)
    ),
});

// UserInfo endpoint
http.route({
    path: "/oauth/userinfo",
    method: "GET",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.userInfo(ctx, req, async (userId) => {
            const user = await ctx.runQuery(api.users.get, { userId });
            return user ? { sub: userId, name: user.name, email: user.email } : null;
        })
    ),
});

// Dynamic Client Registration (optional)
http.route({
    path: "/oauth/register",
    method: "POST",
    handler: httpAction((ctx, req) =>
        oauthProvider.handlers.register(ctx, req)
    ),
});

export default http;
```

</details>

## UserInfo Endpoint

Requires `openid` scope. Returns claims based on scopes:
- `openid`: Always returns `sub`
- `profile`: Adds `name`, `picture`
- `email`: Adds `email` (and `email_verified` if available)

<details>
<summary><strong>Client Registration</strong></summary>

### Register OAuth Client (Admin)

```typescript
// convex/oauthAdmin.ts
import { mutation } from "./_generated/server";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";

export const registerOAuthClient = mutation({
    handler: async (ctx, args: {
        name: string;
        redirectUris: string[];
        scopes: string[];
        type: "confidential" | "public";
    }) => {
        // Check admin permissions
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) throw new Error("Unauthorized");

        const oauthProvider = new OAuthProvider(components.oauthProvider, {
            privateKey: process.env.JWT_PRIVATE_KEY!,
            jwks: process.env.JWKS!,
            siteUrl: process.env.SITE_URL!,
        });

        const result = await oauthProvider.registerClient(ctx, {
            name: args.name,
            redirectUris: args.redirectUris,
            scopes: args.scopes,
            type: args.type,
        });

        // IMPORTANT: Save clientSecret securely - it's only returned once!
        return result;
    },
});
```

</details>

## Authorization Flow

### Automatic Authorization Handler

The `/oauth/authorize` endpoint handles the complete authorization flow automatically:

```
GET /oauth/authorize?
  response_type=code
  &client_id=CLIENT_ID
  &redirect_uri=REDIRECT_URI
  &scope=openid+profile+email
  &state=STATE
  &code_challenge=CHALLENGE
  &code_challenge_method=S256
  &nonce=NONCE
```

The handler:
1. Validates the client ID
2. Checks redirect_uri against registered URIs
3. Validates requested scopes
4. Requires PKCE (code_challenge)
5. Authenticates the user via `getUserId`
6. Issues authorization code
7. Redirects back to the client with the code

<details>
<summary><strong>Custom Authorization Flow (Advanced)</strong></summary>

If you need custom consent UI, you can use the SDK methods directly:

```typescript
// convex/oauth.ts
import { mutation } from "./_generated/server";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";

export const approveAuthorization = mutation({
    handler: async (ctx, args: {
        clientId: string;
        scopes: string[];
        redirectUri: string;
        codeChallenge: string;
        codeChallengeMethod: string;
        nonce?: string;
    }) => {
        // Verify user is authenticated
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) throw new Error("Not authenticated");

        const oauthProvider = new OAuthProvider(components.oauthProvider, {
            privateKey: process.env.JWT_PRIVATE_KEY!,
            jwks: process.env.JWKS!,
            siteUrl: process.env.SITE_URL!,
        });

        // Issue authorization code (automatically creates authorization record)
        const authCode = await oauthProvider.issueAuthorizationCode(ctx, {
            userId: identity.subject,
            clientId: args.clientId,
            scopes: args.scopes,
            redirectUri: args.redirectUri,
            codeChallenge: args.codeChallenge,
            codeChallengeMethod: args.codeChallengeMethod,
            nonce: args.nonce,
        });

        return authCode;
    },
});
```

</details>

<details>
<summary><strong>Authorization Management</strong></summary>

### List User's Authorized Apps

```typescript
import { query } from "./_generated/server";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";

export const listAuthorizedApps = query({
    handler: async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) return [];

        const oauthProvider = new OAuthProvider(components.oauthProvider, {
            privateKey: process.env.JWT_PRIVATE_KEY!,
            jwks: process.env.JWKS!,
            siteUrl: process.env.SITE_URL!,
        });

        return await oauthProvider.listUserAuthorizations(ctx, identity.subject);
    },
});
```

### Revoke Authorization

```typescript
import { mutation } from "./_generated/server";
import { OAuthProvider } from "@codefox-inc/oauth-provider";
import { components } from "./_generated/api";

export const revokeApp = mutation({
    handler: async (ctx, args: { clientId: string }) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) throw new Error("Not authenticated");

        const oauthProvider = new OAuthProvider(components.oauthProvider, {
            privateKey: process.env.JWT_PRIVATE_KEY!,
            jwks: process.env.JWKS!,
            siteUrl: process.env.SITE_URL!,
        });

        // Deletes authorization and all associated tokens
        await oauthProvider.revokeAuthorization(ctx, identity.subject, args.clientId);
    },
});
```

</details>

<details>
<summary><strong>Configuration Options (OAuthConfig)</strong></summary>

```typescript
interface OAuthConfig {
    // REQUIRED: RSA private key in PEM format
    privateKey: string;

    // REQUIRED: JWKS for token verification (public keys only)
    jwks: string;

    // REQUIRED: Your application URL
    siteUrl: string;

    // OPTIONAL: Convex deployment URL (if different from siteUrl)
    convexSiteUrl?: string;

    // OPTIONAL: OAuth endpoint prefix (default: "/oauth")
    // Normalized to a leading slash, trailing slash removed; "/" means root.
    // Must match the route prefix you register in http.ts.
    prefix?: string;

    // OPTIONAL: Comma-separated list of allowed CORS origins
    allowedOrigins?: string;

    // OPTIONAL: Allowed scopes for dynamic client registration
    allowedScopes?: string[];

    // OPTIONAL: JWT audience claim (default: "convex")
    // Set to "oauth-provider" when using Better Auth to distinguish tokens
    applicationID?: string;

    // REQUIRED: Function to get authenticated user ID
    // Must return a Convex users table Id (string)
    // Returns null if user is not authenticated
    getUserId?: (ctx: ActionCtx, request: Request) => Promise<string | null> | string | null;

    // OPTIONAL: Enable dynamic client registration (default: false)
    allowDynamicClientRegistration?: boolean;
}
```

</details>

## Token Verification

### In Convex Functions

```typescript
import { query } from "./_generated/server";

export const protectedQuery = query({
    handler: async (ctx) => {
        const identity = await ctx.auth.getUserIdentity();
        if (!identity) throw new Error("Not authenticated");

        // Token is already verified by Convex Auth
        // Use identity.subject for user ID
        return { userId: identity.subject };
    },
});
```

<details>
<summary><strong>External Token Verification</strong></summary>

```typescript
import { verifyAccessToken } from "@codefox-inc/oauth-provider";

const payload = await verifyAccessToken(
    token,
    {
        jwks: process.env.JWKS!,
        siteUrl: process.env.SITE_URL!,
        // If using Better Auth, specify the applicationID
        // applicationID: "oauth-provider",
    },
    issuerUrl
);

console.log("User ID:", payload.sub);
console.log("Scopes:", payload.scp);
console.log("Client ID:", payload.cid);
```

</details>

<details>
<summary><strong>Distinguishing OAuth Tokens from Session Tokens</strong></summary>

When using multiple auth systems (e.g., Better Auth + OAuth Provider), you can distinguish tokens by checking the issuer:

```typescript
import { isOAuthToken, getOAuthClientId } from "@codefox-inc/oauth-provider";

// Option 1: Using helper functions
const identity = await ctx.auth.getUserIdentity();
if (isOAuthToken(identity)) {
    const clientId = getOAuthClientId(identity);
    // Handle OAuth token (MCP clients, third-party apps)
} else {
    // Handle session token (first-party users)
}

// Option 2: Check issuer directly
if (identity?.issuer?.includes("/oauth")) {
    // This is an OAuth token
}
```

</details>

## Testing

```bash
npm test
```

## License

Apache-2.0
