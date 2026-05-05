import { Hono } from 'hono'
import type { Context } from 'hono'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { ConvexClient } from 'convex/browser'
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify } from 'jose'
import { createMcpServer } from '../mcp/server'

type Bindings = {
  CONVEX_URL?: string;
  CONVEX_SITE_URL?: string;
  SITE_URL?: string;
  OAUTH_PREFIX?: string;
  MCP_RESOURCE?: string;
  MCP_CONVEX_AUTH_TOKEN?: string;
}

const mcpRoutes = new Hono<{ Bindings: Bindings }>()
const ACCESS_TOKEN_TYP_VALUES = new Set(['at+jwt', 'application/at+jwt'])

// Helper: Token Extraction
function extractToken(c: Context): string | null {
  const authHeader = c.req.header('Authorization')
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }
  return null
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/$/, '')}${path.startsWith('/') ? path : `/${path}`}`
}

function getConvexSiteUrl(env: Bindings): string | null {
  if (env.CONVEX_SITE_URL) {
    return env.CONVEX_SITE_URL
  }
  const convexUrl = env.CONVEX_URL || process.env.CONVEX_URL
  if (convexUrl) {
    return convexUrl.replace('.cloud', '.site')
  }
  return null
}

function getAuthorizationServerIssuer(env: Bindings): string | null {
  const convexSiteUrl = getConvexSiteUrl(env)
  if (!convexSiteUrl) {
    return null
  }
  const prefix = env.OAUTH_PREFIX || process.env.OAUTH_PREFIX || '/oauth'
  return joinUrl(convexSiteUrl, prefix)
}

function getPublicBaseUrl(c: Context<{ Bindings: Bindings }>): string {
  return c.env?.SITE_URL || process.env.SITE_URL || new URL(c.req.url).origin
}

function getCanonicalMcpResource(c: Context<{ Bindings: Bindings }>): string {
  const configuredResource = c.env?.MCP_RESOURCE || process.env.MCP_RESOURCE
  const baseUrl = getPublicBaseUrl(c)
  const resourceUrl = configuredResource
    ? new URL(
      configuredResource.startsWith('http')
        ? configuredResource
        : configuredResource.startsWith('/')
          ? configuredResource
          : `/${configuredResource}`,
      baseUrl
    )
    : new URL('/mcp', baseUrl)

  resourceUrl.hash = ''
  resourceUrl.search = ''
  return resourceUrl.toString()
}

function getProtectedResourceMetadataUrl(c: Context<{ Bindings: Bindings }>): string {
  const resourceUrl = new URL(getCanonicalMcpResource(c))
  const resourcePath = resourceUrl.pathname === '/' ? '' : resourceUrl.pathname
  return new URL(
    `/.well-known/oauth-protected-resource${resourcePath}`,
    resourceUrl.origin
  ).toString()
}

function invalidTokenChallenge(c: Context<{ Bindings: Bindings }>): string {
  return `Bearer realm="mcp", error="invalid_token", resource_metadata="${getProtectedResourceMetadataUrl(c)}"`
}

async function verifyMcpAccessToken(
  c: Context<{ Bindings: Bindings }>,
  token: string
): Promise<'valid' | 'invalid' | 'missing_oauth_configuration'> {
  try {
    const header = decodeProtectedHeader(token)
    const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : ''
    if (!ACCESS_TOKEN_TYP_VALUES.has(typ)) {
      return 'invalid'
    }

    const issuer = getAuthorizationServerIssuer(c.env)
    if (!issuer) {
      return 'missing_oauth_configuration'
    }

    const expectedAudience = getCanonicalMcpResource(c)
    const jwks = createRemoteJWKSet(
      new URL(`${issuer}/.well-known/jwks.json`)
    )
    const { payload } = await jwtVerify(token, jwks, {
      audience: expectedAudience,
      issuer,
    })
    return payload.aud === expectedAudience ? 'valid' : 'invalid'
  } catch {
    return 'invalid'
  }
}

// Helper: Get Convex URL
function getConvexUrl(env: Bindings): string | null {
  if (process.env.CONVEX_URL) {
    return process.env.CONVEX_URL
  }
  if (env.CONVEX_URL) {
    return env.CONVEX_URL
  }
  return null
}

function getMcpConvexAuthToken(env: Bindings): string | null {
  return env.MCP_CONVEX_AUTH_TOKEN || process.env.MCP_CONVEX_AUTH_TOKEN || null
}

// Handle all MCP requests (GET/POST/DELETE)
mcpRoutes.all('/', async (c) => {
  const token = extractToken(c)
  if (!token) {
    c.header(
      'WWW-Authenticate',
      `Bearer realm="mcp", resource_metadata="${getProtectedResourceMetadataUrl(c)}"`
    )
    return c.json({ error: 'Missing authentication token' }, 401)
  }

  const tokenVerification = await verifyMcpAccessToken(c, token)
  if (tokenVerification === 'missing_oauth_configuration') {
    return c.json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Missing CONVEX_URL or CONVEX_SITE_URL configuration',
      },
      id: null,
    }, 500)
  }
  if (tokenVerification === 'invalid') {
    c.header('WWW-Authenticate', invalidTokenChallenge(c))
    return c.json({ error: 'Invalid token audience' }, 401)
  }

  // Setup Convex Client
  const convexUrl = getConvexUrl(c.env)
  if (!convexUrl) {
    return c.json({
      jsonrpc: '2.0',
      error: { code: -32603, message: 'Missing CONVEX_URL configuration' },
      id: null,
    }, 500)
  }

  const convexAuthToken = getMcpConvexAuthToken(c.env)
  if (!convexAuthToken) {
    return c.json({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Missing MCP_CONVEX_AUTH_TOKEN configuration',
      },
      id: null,
    }, 500)
  }

  const convex = new ConvexClient(convexUrl)
  convex.setAuth(() => Promise.resolve(convexAuthToken))

  // Create MCP Server with tools
  const mcpServer = createMcpServer(convex)

  // Create Web Standard Streamable HTTP Transport (Stateless mode)
  const transport = new WebStandardStreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  })

  try {
    await mcpServer.connect(transport)
    return await transport.handleRequest(c.req.raw)
  } catch (e: unknown) {
    console.error('[MCP] Error:', e)
    const message = e instanceof Error ? e.message : String(e)
    return c.json({
      jsonrpc: '2.0',
      error: { code: -32603, message: `Internal Server Error: ${message}` },
      id: null,
    }, 500)
  } finally {
    await transport.close()
  }
})

export { mcpRoutes }
