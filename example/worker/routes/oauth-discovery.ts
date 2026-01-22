/**
 * OAuth Discovery endpoints for MCP clients
 * Based on codefox-business-suite implementation
 */
import { Hono } from 'hono'

type Bindings = {
  CONVEX_URL?: string
  CONVEX_SITE_URL?: string
  SITE_URL?: string
  OAUTH_PREFIX?: string
}

const oauthDiscoveryRoutes = new Hono<{ Bindings: Bindings }>()

// Helper: Get Convex Site URL for OAuth endpoints
function getConvexSiteUrl(env: Bindings): string {
  let siteUrl = env.CONVEX_SITE_URL
  if (!siteUrl) {
    const convexUrl = env.CONVEX_URL || process.env.CONVEX_URL
    if (convexUrl) {
      siteUrl = convexUrl.replace('.cloud', '.site')
    }
  }
  return siteUrl || ''
}

// Helper: Get App URL (public-facing URL)
function getAppUrl(env: Bindings, requestUrl: string): string {
  return env.SITE_URL || process.env.SITE_URL || new URL(requestUrl).origin
}

// Helper: Generate OAuth discovery response
function getOAuthDiscoveryResponse(env: Bindings, requestUrl: string) {
  const convexSiteUrl = getConvexSiteUrl(env)
  if (!convexSiteUrl) {
    return null
  }
  const prefix = env.OAUTH_PREFIX || process.env.OAUTH_PREFIX || "/oauth"

  return {
    issuer: `${convexSiteUrl}${prefix}`,
    authorization_endpoint: `${convexSiteUrl}${prefix}/authorize`,
    token_endpoint: `${convexSiteUrl}${prefix}/token`,
    userinfo_endpoint: `${convexSiteUrl}${prefix}/userinfo`,
    jwks_uri: `${convexSiteUrl}${prefix}/.well-known/jwks.json`,
    registration_endpoint: `${convexSiteUrl}${prefix}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
  }
}

// GET /.well-known/oauth-authorization-server - Discovery Endpoint for MCP Client
oauthDiscoveryRoutes.get('/.well-known/oauth-authorization-server', (c) => {
  const response = getOAuthDiscoveryResponse(c.env, c.req.url)
  if (!response) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }
  return c.json(response)
})

// GET /.well-known/oauth-authorization-server/* - Handle paths with suffix (e.g., /mcp)
oauthDiscoveryRoutes.get('/.well-known/oauth-authorization-server/*', (c) => {
  const response = getOAuthDiscoveryResponse(c.env, c.req.url)
  if (!response) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }
  return c.json(response)
})

// GET /.well-known/openid-configuration - OpenID Connect Discovery
oauthDiscoveryRoutes.get('/.well-known/openid-configuration', (c) => {
  const response = getOAuthDiscoveryResponse(c.env, c.req.url)
  if (!response) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }
  return c.json(response)
})

// GET /.well-known/openid-configuration/* - Handle paths with suffix
oauthDiscoveryRoutes.get('/.well-known/openid-configuration/*', (c) => {
  const response = getOAuthDiscoveryResponse(c.env, c.req.url)
  if (!response) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }
  return c.json(response)
})

// GET /.well-known/oauth-protected-resource - Resource Discovery (RFC 9728)
oauthDiscoveryRoutes.get('/.well-known/oauth-protected-resource', (c) => {
  const convexSiteUrl = getConvexSiteUrl(c.env)
  const appUrl = getAppUrl(c.env, c.req.url)
  const prefix = c.env.OAUTH_PREFIX || process.env.OAUTH_PREFIX || "/oauth"

  if (!convexSiteUrl) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }

  return c.json({
    resource: appUrl,
    authorization_servers: [`${convexSiteUrl}${prefix}`],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
  })
})

// Handle wildcard for protected resource (e.g., /mcp appended)
oauthDiscoveryRoutes.get('/.well-known/oauth-protected-resource/*', (c) => {
  const convexSiteUrl = getConvexSiteUrl(c.env)
  const appUrl = getAppUrl(c.env, c.req.url)
  const prefix = c.env.OAUTH_PREFIX || process.env.OAUTH_PREFIX || "/oauth"

  if (!convexSiteUrl) {
    return c.json(
      { error: 'Missing configuration: CONVEX_URL or CONVEX_SITE_URL' },
      500
    )
  }

  return c.json({
    resource: appUrl,
    authorization_servers: [`${convexSiteUrl}${prefix}`],
    scopes_supported: ['openid', 'profile', 'email', 'offline_access'],
  })
})

export { oauthDiscoveryRoutes }
