# Developing guide

## Running locally

```sh
bun install
bun run dev
```

## Testing

```sh
bun install --frozen-lockfile
bun run build:clean
bun run typecheck
bun run lint
bun run test
```
