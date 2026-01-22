import { Hono } from 'hono'
import type { Context } from 'hono'
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js'
import { ConvexClient } from 'convex/browser'
import { createMcpServer } from '../mcp/server'

type Bindings = {
  CONVEX_URL?: string;
}

const mcpRoutes = new Hono<{ Bindings: Bindings }>()

// Helper: Token Extraction
function extractToken(c: Context): string | null {
  const authHeader = c.req.header('Authorization')
  if (authHeader?.startsWith('Bearer ')) {
    return authHeader.substring(7)
  }
  return c.req.query('token') || null
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

// Handle all MCP requests (GET/POST/DELETE)
mcpRoutes.all('/', async (c) => {
  const token = extractToken(c)
  if (!token) {
    c.header('WWW-Authenticate', 'Bearer realm="mcp"')
    return c.json({ error: 'Missing authentication token' }, 401)
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

  const convex = new ConvexClient(convexUrl)
  convex.setAuth(() => Promise.resolve(token))

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
