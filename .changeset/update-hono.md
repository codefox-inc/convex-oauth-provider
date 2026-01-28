---
"@codefox-inc/oauth-provider": patch
---

Update hono to 4.11.7 to fix security vulnerabilities

- Fixes cache middleware ignoring `Cache-Control: private` leading to Web Cache Deception
- Fixes arbitrary key read in Serve static Middleware (Cloudflare Workers Adapter)
