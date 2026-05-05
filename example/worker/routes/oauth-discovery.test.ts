import { describe, expect, test } from 'vitest'
import { oauthDiscoveryRoutes } from './oauth-discovery'

describe('oauthDiscoveryRoutes', () => {
  test('returns the MCP resource URL for protected resource metadata wildcard route', async () => {
    const response = await oauthDiscoveryRoutes.request(
      'https://example.com/.well-known/oauth-protected-resource/mcp',
      undefined,
      { CONVEX_SITE_URL: 'https://issuer.example.com' }
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      resource: 'https://example.com/mcp',
    })
  })

  test('does not expose arbitrary wildcard protected resource metadata paths', async () => {
    const response = await oauthDiscoveryRoutes.request(
      'https://example.com/.well-known/oauth-protected-resource/admin',
      undefined,
      { CONVEX_SITE_URL: 'https://issuer.example.com' }
    )

    expect(response.status).toBe(404)
  })
})
