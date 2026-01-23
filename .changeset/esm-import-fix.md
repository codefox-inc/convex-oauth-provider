---
"@codefox-inc/oauth-provider": patch
---

Fix ESM import extensions for Node.js compatibility

Added `.js` extensions to all relative imports in component files to ensure proper ESM module resolution in Node.js environments.
