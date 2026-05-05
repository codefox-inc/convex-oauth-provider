import { describe, expect, test } from 'vitest'
import { mcpRoutes } from './mcp'

function createJwt(payload: Record<string, unknown>): string {
  const encode = (value: unknown) =>
    btoa(JSON.stringify(value))
      .replaceAll('+', '-')
      .replaceAll('/', '_')
      .replaceAll('=', '')

  return `${encode({ alg: 'none', typ: 'JWT' })}.${encode(payload)}.signature`
}

describe('mcpRoutes', () => {
  test('rejects query string token fallback and advertises protected resource metadata', async () => {
    const response = await mcpRoutes.request('https://example.com/?token=query-token')

    expect(response.status).toBe(401)
    expect(response.headers.get('WWW-Authenticate')).toContain(
      'resource_metadata="https://example.com/.well-known/oauth-protected-resource/mcp"'
    )
  })

  test('rejects bearer token whose audience does not match the canonical MCP resource', async () => {
    const token = createJwt({ aud: 'https://example.com/other' })
    const response = await mcpRoutes.request('https://example.com/', {
      headers: { Authorization: `Bearer ${token}` },
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
})
