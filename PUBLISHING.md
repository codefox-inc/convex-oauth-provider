# Publishing

This package uses [Changesets](https://github.com/changesets/changesets) for version management and publishing.

## Automated Release (Recommended)

Releases are automated via GitHub Actions. When changes are pushed to `main`:

1. If there are changesets, a "Version Packages" PR is created
2. When merged, the package is automatically published to npmjs.com

### Setup (Repository Admin)

Add `NPM_TOKEN` to GitHub repository secrets:
1. Create an access token on npmjs.com (Account Settings → Access Tokens → Automation)
2. Add it to GitHub: Settings → Secrets → Actions → New repository secret → `NPM_TOKEN`

## Creating a Changeset

When you make changes that should be released:

```sh
npm run changeset
```

This will prompt you to:
1. Select the type of change (patch, minor, major)
2. Write a summary of the changes

Commit the generated changeset file with your changes.

## Manual Release (Local)

If you need to release manually:

```sh
# 1. Login to npm (or configure .npmrc for GitHub Packages)
npm login

# 2. Version the package (applies changesets)
npm run version

# 3. Build and publish
npm run release
```

## Package Scripts

- `npm run changeset` - Create a new changeset
- `npm run version` - Apply changesets and update package version
- `npm run release` - Build and publish to registry

## Building a Test Package

```sh
npm run build:clean
npm pack
```

You can then install the .tgz file in another project:
```sh
npm install ./path/to/codefox-inc-oauth-provider-0.1.0.tgz
```
