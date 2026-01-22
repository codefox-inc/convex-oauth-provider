---
name: changeset
description: Create a changeset file for changes. Use when "create changeset", "prepare release", or "bump version".
allowed-tools: Read, Glob, Grep, Bash(git diff:*), Bash(git log:*), Bash(git status:*), Write
---

# Changeset Creation

Create appropriate changesets for repository changes.

## Steps

1. **Check changes**: Review with `git diff` and `git status`
2. **Identify packages**: Determine which packages were changed
3. **Determine version bump**: Follow the rules below for major/minor/patch
4. **Create changeset file**: Create a Markdown file in `.changeset/`

## Version Bump Guidelines

| Bump | When to use | Examples |
|------|-------------|----------|
| **major** | Breaking changes (for 1.x.x+) | Removed API, changed argument types, added required arguments |
| **minor** | New features | New methods, new optional arguments, new exports |
| **patch** | Bug fixes, internal improvements | Behavior fixes, typo fixes, performance improvements |

### Special Rules for 0.x.x Versions

`0.x.x` indicates development stage:
- **Breaking changes use minor** bump (not major)
- patch is used for bug fixes as usual

## Changeset File Format

```markdown
---
"@codefox-inc/<package-name>": <bump-type>
---

Summary of changes

- Specific change 1
- Specific change 2
```

## File Naming Convention

- Random word combinations (e.g., `funny-lions-dance.md`)
- Or descriptive kebab-case (e.g., `add-reaction-feature.md`)

## Writing Style

- **Don't use `###` on the first line** (it follows `- commit-hash:` and won't render as a heading)
- List specific changes with bullet points
- Technically accurate but user-friendly

## Good Example

### Simple change

```markdown
---
"@codefox-inc/oauth-provider": patch
---

Improve registerOAuthRoutes extensibility

- Added `authorizeHandler` option to enable custom redirect after authentication check
- Modified to pass `ctx` to `getUserProfile` callback, enabling DB access
```

### Multiple sections (using headings)

```markdown
---
"@codefox-inc/oauth-provider": minor
---

Add authorization management features and SDK helpers

### Authorization management

- Added `oauth_authorizations` table to persist user authorization state
- `listUserAuthorizations` / `revokeAuthorization` enable listing and revoking authorized apps

### SDK helpers

- `createAuthHelper`: Unified authentication helper supporting both Convex Auth and OAuth tokens
- `registerOAuthRoutes`: Helper to register HTTP routes in one line
```

## Bad Example

```markdown
---
"@codefox-inc/oauth-provider": patch
---

fix bug
```

Reason: Doesn't explain what was fixed. Users can't determine impact.
