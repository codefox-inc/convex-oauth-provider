---
"@codefox-inc/oauth-provider": minor
---

Improve OAuth/OIDC/MCP protocol compliance.

- Bind RFC 8707 `resource` values to authorization codes and refresh tokens, and use the approved resource as the JWT access token audience.
- Emit RFC 9068-style access tokens with `typ`, `client_id`, `scope`, and `jti`, and accept both `at+jwt` and `application/at+jwt` during verification.
- Tighten redirect URI, PKCE, client authentication method, DCR, `offline_access`, `max_age`, and UserInfo challenge handling.
- Add `resource` support to the public authorization-code helper and example consent flow.
- Update the example MCP Worker to validate inbound bearer tokens as a resource server and avoid passing client access tokens through to Convex.

Host migration note: custom consent flows must preserve the `resource` authorization request parameter and pass it to `issueAuthorizationCode`. Example MCP deployments also need an internal Worker-to-Convex credential such as `MCP_CONVEX_AUTH_TOKEN`.
