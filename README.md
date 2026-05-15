# Commerce Shield

Embedded Shopify admin app for bot protection, discount config, MRI engine, and app health monitoring.

## Architecture

- **Backend:** Express.js server (`server.js`) — port 4000
- **Frontend:** React + Vite + TypeScript (`web/`)
- **Deploy:** Cloudflare Workers at your configured Worker origin (current prod: `https://commerce-shield-prod.ncassidy.workers.dev/`)
- **API Version:** Shopify Admin API 2025-10

## Features

- **Bot Event Ingestion** (`/api/bot-event`) — CTV-campaign-safe, ring buffer (10k events), no auth required
- **Discount Config** (`/api/config`) — CRUD backed by Shopify metafields via GraphQL `metafieldsSet`
- **MRI Engine** (`/api/mri-config`) — Conversion optimization controls persisted to metafields
- **Recent Visits** (`/api/recent-visits`) — Analytics with top referrers, landing pages, user agents
- **Auth** — Bearer token via `COMMERCE_SHIELD_ADMIN_TOKEN` with constant-time comparison
- **Rate Limiting** — Sliding-window per IP (60/min admin, 300/min bot-event)

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SHOPIFY_STORE_DOMAIN` | Yes | e.g. `gerberchildrenswear.myshopify.com` |
| `SHOPIFY_ADMIN_API_ACCESS_TOKEN` | Yes | Admin API access token |
| `SHOPIFY_SHOP_ID` | Yes | Numeric shop ID for metafield owner |
| `COMMERCE_SHIELD_ADMIN_TOKEN` | Recommended | Bearer token for admin API auth |
| `PORT` | No | Server port (default: 4000) |
| `LOG_LEVEL` | No | `debug`, `info`, `warn`, `error` (default: `info`) |
| `RATE_LIMIT_MAX` | No | Admin API rate limit per IP/min (default: 60) |
| `BOT_EVENT_RATE_LIMIT_MAX` | No | Bot event rate limit per IP/min (default: 300) |
| `BOT_EVENT_BUFFER_MAX` | No | Ring buffer capacity (default: 10000) |
| `BOT_EVENT_ALLOWED_ORIGINS` | No | Comma-separated allowed CORS origins |

## Run Locally

```powershell
npm install
$env:SHOPIFY_STORE_DOMAIN = 'gerberchildrenswear.myshopify.com'
$env:SHOPIFY_ADMIN_API_ACCESS_TOKEN = '<token>'
$env:COMMERCE_SHIELD_ADMIN_TOKEN = '<admin-secret>'
npm start
# http://localhost:4000
```

## Cloudflare Worker Source

The Worker source of truth now lives in this repo at:

- `worker/wrangler.toml` (entry config)
- `worker/src/index.js` (main entrypoint)
- `shared/intent-scoring.js` and `shared/worker-security.js` (shared modules)

## Storefront Pixel Suppression

Commerce Shield enforces pixel suppression through the Worker-served storefront guard:

```html
<script src="https://<your-worker-origin>/cs-pixel-guard.js?shop=<your-shop>.myshopify.com"></script>
```

Replace `<your-worker-origin>` with your deployed Worker/app origin (for this repo: `SHOPIFY_APP_URL`).

Place this as high in the theme `<head>` as possible, before Meta/Google/TikTok/Pinterest/Snap/Bing/Reddit/Cloudflare analytics pixels. The guard fails open for normal shoppers and uncertain sessions. It only suppresses known marketing/analytics pixel calls when the browser is a high-confidence bot or automation session.

The embedded Commerce Shield admin includes an **Install Pixel Guard** button. It reads the main Shopify theme, inserts the guard immediately after the opening `<head>` in `layout/theme.liquid`, and avoids duplicate installs. The Worker must have `COMMERCE_SHIELD_ADMIN_TOKEN` configured, plus a Shopify Admin token with `read_themes` and `write_themes`.

For a dry run that makes no suppression changes, use:

```html
<script src="https://<your-worker-origin>/cs-pixel-guard.js?shop=<your-shop>.myshopify.com&mode=report"></script>
```

### Worker Commands

```powershell
npm run worker:install
npm run worker:dev
npm run worker:db:init
npm run worker:deploy
```

Copy `worker/.dev.vars.example` to `worker/.dev.vars` and fill required secrets before local dev or deploy.

## Cloudflare Usage Helper Scripts

Two local helper scripts under `scripts/` query Cloudflare GraphQL for recent Worker request volume:

- `node scripts/cf-volume.cjs`
- `node scripts/cf-volume2.cjs`

They require these environment variables:

```powershell
$env:CLOUDFLARE_API_TOKEN = '<token>'
$env:CLOUDFLARE_ACCOUNT_ID = '<account-id>'
$env:CLOUDFLARE_WORKER_NAME = 'commerce-shield-prod' # optional
```

`CLOUDFLARE_WORKER_NAME` defaults to `commerce-shield-prod` when not set.

## Deployment Workflow

1. Make and validate changes in this repository
2. Deploy Worker from this repository with `npm run worker:deploy`
3. Confirm Shopify app URLs in `shopify.app.toml` remain pointed to your configured Worker/app origin
