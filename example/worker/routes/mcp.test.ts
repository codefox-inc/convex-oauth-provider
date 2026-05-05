import { exportJWK, generateKeyPair, SignJWT } from 'jose'
import { beforeEach, describe, expect, test, vi } from 'vitest'
import { mcpRoutes } from './mcp'

type Jwks = { keys: JsonWebKey[] }

const mocks = vi.hoisted(() => {
  const handleRequest = vi.fn(async () => Response.json({ ok: true }))
  return {
    connect: vi.fn(),
    handleRequest,
    close: vi.fn(),
    setAuth: vi.fn(),
  }
})

vi.mock('@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js', () => ({
  WebStandardStreamableHTTPServerTransport: vi.fn(
    function WebStandardStreamableHTTPServerTransport() {
      return {
        handleRequest: mocks.handleRequest,
        close: mocks.close,
      }
    }
  ),
}))

vi.mock('convex/browser', () => ({
  ConvexClient: vi.fn(function ConvexClient() {
    return {
      setAuth: mocks.setAuth,
    }
  }),
}))

vi.mock('../mcp/server', () => ({
  createMcpServer: vi.fn(() => ({
    connect: mocks.connect,
  })),
}))

async function createSignedAccessToken({
  audience,
  issuer = 'https://issuer.example.com/oauth',
  typ = 'at+jwt',
}: {
  audience: string | string[]
  issuer?: string
  typ?: string
}): Promise<{ token: string; jwks: Jwks }> {
  const { publicKey, privateKey } = await generateKeyPair('RS256')
  const publicJwk = await exportJWK(publicKey)
  publicJwk.kid = 'test-key'
  publicJwk.alg = 'RS256'
  publicJwk.use = 'sig'

  const token = await new SignJWT({})
    .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ })
    .setIssuer(issuer)
    .setAudience(audience)
    .setIssuedAt()
    .setExpirationTime('5m')
    .sign(privateKey)

  return { token, jwks: { keys: [publicJwk] } }
}

function mockJwksFetch(jwks: Jwks): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: RequestInfo | URL) => {
      const url = input instanceof Request ? input.url : String(input)
      if (url === 'https://issuer.example.com/oauth/.well-known/jwks.json') {
        return Response.json(jwks)
      }
      return new Response('not found', { status: 404 })
    })
  )
}

describe('mcpRoutes', () => {
  beforeEach(() => {
    vi.unstubAllGlobals()
    vi.clearAllMocks()
    mocks.handleRequest.mockResolvedValue(Response.json({ ok: true }))
  })

  test('rejects query string token fallback and advertises protected resource metadata', async () => {
    const response = await mcpRoutes.request('https://example.com/?token=query-token')

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"'
    )
  })

  test('rejects bearer token whose audience does not match the canonical MCP resource', async () => {
    const { token, jwks } = await createSignedAccessToken({
      audience: 'https://example.com/other',
    })
    mockJwksFetch(jwks)

    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: `Bearer ${token}` },
    }, {
      CONVEX_SITE_URL: 'https://issuer.example.com',
    })

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"')
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"'
    )
    expect(await response.json()).toEqual({ error: 'Invalid token audience' })
  })

  test('rejects bearer token whose audience cannot be inspected', async () => {
    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: 'Bearer opaque-token' },
    })

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"')
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"'
    )
    expect(await response.json()).toEqual({ error: 'Invalid token audience' })
  })

  test('rejects bearer token without an access-token JWT typ', async () => {
    const { token, jwks } = await createSignedAccessToken({
      audience: 'https://example.com/mcp',
      typ: 'JWT',
    })
    mockJwksFetch(jwks)

    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: `Bearer ${token}` },
    }, {
      CONVEX_SITE_URL: 'https://issuer.example.com',
    })

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"')
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"'
    )
    expect(mocks.setAuth).not.toHaveBeenCalled()
  })

  test('derives the metadata challenge from path-qualified MCP_RESOURCE', async () => {
    const response = await mcpRoutes.request('https://edge.example.com/', {
      headers: { Authorization: 'Bearer malformed-token' },
    }, {
      MCP_RESOURCE: 'https://api.example.com/custom/mcp',
    })

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain('error="invalid_token"')
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://api.example.com/.well-known/oauth-protected-resource/custom/mcp"'
    )
  })

  test('verifies access tokens with the authorization server JWKS and uses worker credentials for Convex', async () => {
    const { token, jwks } = await createSignedAccessToken({
      audience: 'https://example.com/mcp',
    })
    mockJwksFetch(jwks)

    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: `Bearer ${token}` },
    }, {
      CONVEX_SITE_URL: 'https://issuer.example.com',
      CONVEX_URL: 'https://convex.example.com',
      MCP_CONVEX_AUTH_TOKEN: 'worker-internal-token',
    })

    expect(response.status).toBe(200)
    expect(mocks.setAuth).toHaveBeenCalledTimes(1)
    const authFactory = mocks.setAuth.mock.calls[0]?.[0] as () => Promise<string>
    await expect(authFactory()).resolves.toBe('worker-internal-token')
    await expect(authFactory()).resolves.not.toBe(token)
  })

  test('fails explicitly instead of passing the inbound token to Convex when worker credentials are missing', async () => {
    const { token, jwks } = await createSignedAccessToken({
      audience: 'https://example.com/mcp',
    })
    mockJwksFetch(jwks)

    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: `Bearer ${token}` },
    }, {
      CONVEX_SITE_URL: 'https://issuer.example.com',
      CONVEX_URL: 'https://convex.example.com',
    })

    expect(response.status).toBe(500)
    await expect(response.json()).resolves.toMatchObject({
      jsonrpc: '2.0',
      error: {
        code: -32603,
        message: 'Missing MCP_CONVEX_AUTH_TOKEN configuration',
      },
    })
    expect(mocks.setAuth).not.toHaveBeenCalled()
  })
})
