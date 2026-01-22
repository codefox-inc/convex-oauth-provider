import { Hono } from 'hono'
import { cors } from 'hono/cors'
import { oauthDiscoveryRoutes } from './routes/oauth-discovery'
import { mcpRoutes } from './routes/mcp'

type Bindings = {
  CONVEX_URL?: string;
  CONVEX_SITE_URL?: string;
  SITE_URL?: string;
  ASSETS: Fetcher;
}

const app = new Hono<{ Bindings: Bindings }>()

// Global CORS Middleware
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'HEAD'],
  allowHeaders: ['Content-Type', 'Authorization', 'mcp-protocol-version'],
  exposeHeaders: ['Content-Length', 'WWW-Authenticate'],
  maxAge: 86400,
}))

// OAuth Discovery (/.well-known/oauth-*)
app.route('/', oauthDiscoveryRoutes)

// MCP Server (/mcp)
app.route('/mcp', mcpRoutes)

// SPA Fallback - serve static assets
app.get('*', async (c) => {
  return c.env.ASSETS.fetch(c.req.raw)
})

export default app
