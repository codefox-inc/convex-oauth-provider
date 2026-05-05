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

  test('derives path-qualified protected resource metadata from MCP_RESOURCE', async () => {
    const response = await oauthDiscoveryRoutes.request(
      'https://api.example.com/.well-known/oauth-protected-resource/custom/mcp',
      undefined,
      {
        CONVEX_SITE_URL: 'https://issuer.example.com',
        MCP_RESOURCE: 'https://api.example.com/custom/mcp',
      }
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      resource: 'https://api.example.com/custom/mcp',
    })
  })

  test('does not advertise offline_access in protected resource metadata scopes', async () => {
    const response = await oauthDiscoveryRoutes.request(
      'https://example.com/.well-known/oauth-protected-resource/mcp',
      undefined,
      { CONVEX_SITE_URL: 'https://issuer.example.com' }
    )

    expect(response.status).toBe(200)
    const body = await response.json() as { scopes_supported: string[] }
    expect(body.scopes_supported).toEqual(['openid', 'profile', 'email'])
  })

  test('advertises S256 and supported token endpoint auth methods in authorization server metadata', async () => {
    const response = await oauthDiscoveryRoutes.request(
      'https://example.com/.well-known/oauth-authorization-server',
      undefined,
      { CONVEX_SITE_URL: 'https://issuer.example.com' }
    )

    expect(response.status).toBe(200)
    await expect(response.json()).resolves.toMatchObject({
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: [
        'client_secret_basic',
        'client_secret_post',
        'none',
      ],
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
