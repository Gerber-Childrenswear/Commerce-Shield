# Commerce Shield Worker

This directory is the Cloudflare Worker source of truth for Commerce Shield.

## Entrypoint

- Worker config: `wrangler.toml`
- Main module: `src/index.js`

## Prerequisites

- Node.js 18+
- npm 9+
- Cloudflare account access for this Worker
- Wrangler authentication (`wrangler login`)

## Install

From repository root:

```powershell
npm run worker:install
```

Or from this directory:

```powershell
npm install
```

## Environment Setup

1. Copy `.dev.vars.example` to `.dev.vars`.
2. Fill all required values.

Example:

```powershell
Copy-Item .dev.vars.example .dev.vars
```

### Required variables

- `SHOPIFY_APP_URL`
- `SHOPIFY_INTENT_SYNC_URL`
- `INTERNAL_SYNC_SHARED_SECRET`
- `SHOPIFY_ADMIN_SHOP`
- `SHOPIFY_ADMIN_ACCESS_TOKEN` or `SHOPIFY_ADMIN_ACCESS_TOKENS_JSON`
- `SHOPIFY_ADMIN_API_VERSION`
- `COMMERCE_SHIELD_ADMIN_TOKEN`
- `BLOOMREACH_SHARED_SECRET`
- `BLOOMREACH_ALLOWED_ORIGINS`

## Local Development

From repository root:

```powershell
npm run worker:dev
```

## D1 Database Initialization

Run the schema setup before first use:

```powershell
npm run worker:db:init
```

This executes `schema.sql` against `commerce-shield-db`.

## Deploy

From repository root:

```powershell
npm run worker:deploy
```

## Pixel Guard Snippet

Use this script in the Shopify theme/app embed before marketing pixels:

```html
<script src="https://commerce-shield-prod.ncassidy.workers.dev/cs-pixel-guard.js?shop=gerberchildrenswear.myshopify.com"></script>
```

The script only suppresses known marketing/analytics pixel calls for high-confidence bot or automation sessions. Normal shoppers and uncertain sessions are left alone.

The embedded admin's **Install Pixel Guard** button installs this script automatically at the beginning of `layout/theme.liquid`'s `<head>`. It requires `COMMERCE_SHIELD_ADMIN_TOKEN` and Shopify `read_themes` / `write_themes` access.

## Third-Party Dev Checklist

- Confirm `main` in `wrangler.toml` is `src/index.js`.
- Confirm imports to `../../shared/intent-scoring.js` and `../../shared/worker-security.js` resolve.
- Confirm Cloudflare D1 binding name is `DB`.
- Confirm Worker URL is `https://commerce-shield-prod.ncassidy.workers.dev`.
- Run local dev once before deploy to catch config issues.

## Troubleshooting

- Error: cannot find `src/worker.ts`
  - Cause: old assumption from previous setup.
  - Fix: use existing entrypoint `src/index.js` in `wrangler.toml`.

- Error: missing secrets/env
  - Cause: `.dev.vars` not created or incomplete.
  - Fix: copy from `.dev.vars.example` and populate values.
