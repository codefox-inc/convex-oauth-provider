---
"@codefox-inc/oauth-provider": patch
---

Fix DCR failure in Convex mutations by replacing async bcrypt methods with sync variants

`bcrypt.hash()` and `bcrypt.compare()` use `setTimeout` internally, which is not allowed in Convex queries and mutations. Replaced with `bcrypt.hashSync()` and `bcrypt.compareSync()`.
