# Developer Notes: Commerce Shield Worker Source

## Current state

This repository now contains the Shopify admin app shell (Express + web UI) and the Cloudflare Worker project.

The deployed URL used by this app is:

- https://commerce-shield.ncassidy.workers.dev

## Confirmed Worker entrypoint

The Worker project was located in local staging copies at:

- `C:/Users/NCassidy/Downloads/gerberchildrenswear-ncassidy-staging-main/apps/commerce-shield/worker`
- `C:/Users/NCassidy/Downloads/gerberchildrenswear-ncassidy-staging-main/gcw-dev/gcw-dev/apps/commerce-shield/worker`

In both places, the Wrangler config sets:

- `main = "src/index.js"`

So the active Worker entrypoint is:

- `src/index.js` (JavaScript), **not** `src/worker.ts`.

## Source-of-truth paths in this repo

- `worker/wrangler.toml`
- `worker/src/index.js`
- `worker/schema.sql`
- `worker/.dev.vars.example`
- `shared/intent-scoring.js`
- `shared/worker-security.js`

## Why this matters

If we only edit this repository, Worker production behavior at `commerce-shield.ncassidy.workers.dev` may not change unless the Worker project source is also updated and deployed.

## Worker runbook

1. Install worker dependencies: `npm run worker:install`
2. Create `worker/.dev.vars` from `worker/.dev.vars.example`
3. Local dev: `npm run worker:dev`
4. Initialize D1 schema: `npm run worker:db:init`
5. Deploy: `npm run worker:deploy`

## Recommended next steps

1. Add CI job that validates and deploys `worker/` from this repository.
2. Add environment-specific Wrangler configs if staging/prod split is needed.
3. Optionally migrate `worker/src/index.js` to TypeScript and set `main` accordingly.

## Quick verification checklist

- `wrangler.toml` exists in the repo where deploy runs
- `main` points to the expected file
- Deploy command is documented and reproducible
- `shopify.app.toml` URLs match deployed Worker routes

## D1 migrations

When new tables are added, re-run the DB init command to apply them:

```powershell
npm run worker:db:init
```

Or apply individually with Wrangler:

```powershell
cd worker
npx wrangler d1 execute commerce-shield-db --file=schema.sql
```

### Crawler Allowlist table (added 2026-05)

If upgrading an existing D1 instance, run the following to add the `allowed_crawlers` table without affecting existing data:

```sql
CREATE TABLE IF NOT EXISTS allowed_crawlers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop TEXT NOT NULL,
  company TEXT NOT NULL,
  crawler_name TEXT NOT NULL,
  ua_pattern TEXT NOT NULL DEFAULT '',
  contact_email TEXT NOT NULL DEFAULT '',
  purpose TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'pending',
  token TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_allowed_crawlers_shop_status ON allowed_crawlers(shop, status);
CREATE INDEX IF NOT EXISTS idx_allowed_crawlers_token ON allowed_crawlers(token);
```
