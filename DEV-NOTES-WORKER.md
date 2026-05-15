# Developer Notes: Commerce Shield Worker Source

## Current state

This repository contains the Shopify admin app shell (Express + web UI) and the Cloudflare Worker project used for production.

The deployed Worker origin for this environment is currently:

- https://commerce-shield-prod.ncassidy.workers.dev

## Confirmed Worker entrypoint

The active Worker entrypoint is:

- `src/index.js` (JavaScript), as set by `main = "src/index.js"` in `worker/wrangler.toml`.

## Source-of-truth paths in this repo

- `worker/wrangler.toml`
- `worker/src/index.js`
- `worker/schema.sql`
- `worker/.dev.vars.example`
- `shared/intent-scoring.js`
- `shared/worker-security.js`

## Why this matters

Edits in this repository affect production behavior after a deploy from this repository (`npm run worker:deploy`).

## Worker runbook

1. Install worker dependencies: `npm run worker:install`
2. Create `worker/.dev.vars` from `worker/.dev.vars.example`
3. Local dev: `npm run worker:dev`
4. Initialize D1 schema: `npm run worker:db:init`
5. Deploy: `npm run worker:deploy`

## Recommended next steps

1. Add CI job that validates and deploys `worker/` from this repository.
2. Keep this workspace production-only and avoid reintroducing dev-store app URLs in docs/config.
3. Optionally migrate `worker/src/index.js` to TypeScript and set `main` accordingly.

## Quick verification checklist

- `wrangler.toml` exists in the repo where deploy runs
- `main` points to the expected file
- Deploy command is documented and reproducible
- `shopify.app.toml` URLs match deployed Worker routes
