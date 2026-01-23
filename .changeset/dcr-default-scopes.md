---
"@codefox-inc/oauth-provider": patch
---

Fix DCR to use config.allowedScopes as default when client omits scope

Previously, when a client registered via DCR without specifying scopes, it defaulted to hardcoded `["openid", "profile", "email"]`. This could conflict with custom `allowedScopes` configurations.

Now, unspecified scopes default to `config.allowedScopes`, ensuring clients receive all provider-supported scopes.
