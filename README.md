# Commerce Shield

Embedded Shopify admin app for bot protection, discount config, MRI engine, and app health monitoring.

## Architecture

- **Backend:** Express.js server (`server.js`) — port 4000
- **Frontend:** React + Vite + TypeScript (`web/`)
- **Deploy:** Cloudflare Workers at `https://commerce-shield.ncassidy.workers.dev/`
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
| `SHOPIFY_STORE_DOMAIN` | Yes | e.g. `gcw-dev.myshopify.com` |
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
$env:SHOPIFY_STORE_DOMAIN = 'gcw-dev.myshopify.com'
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

### Worker Commands

```powershell
npm run worker:install
npm run worker:dev
npm run worker:db:init
npm run worker:deploy
```

Copy `worker/.dev.vars.example` to `worker/.dev.vars` and fill required secrets before local dev or deploy.

## Deployment Workflow

1. All changes land in `ncassidy233/commerce-shield` first
2. Test and review
3. When approved, push to `Gerber-Childrenswear/gcw-dev` → `apps/gcw-admin/`
