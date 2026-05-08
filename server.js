'use strict';

const crypto = require('crypto');
const express = require('express');

const WORKER_ORIGIN = process.env.WORKER_ORIGIN || 'https://commerce-shield-prod.ncassidy.workers.dev';

// Shopify OAuth config
const SHOPIFY_API_KEY = process.env.SHOPIFY_API_KEY || 'dc386b789af148f54d80b54d07e63215';
const SHOPIFY_API_SECRET = process.env.SHOPIFY_API_SECRET || '';
const SHOPIFY_SCOPES = process.env.SHOPIFY_SCOPES || 'read_discounts,write_discounts,read_orders,write_orders,read_products,write_products,read_script_tags,write_script_tags,read_themes,write_themes';
const APP_URL = process.env.APP_URL || 'https://commerce-shield.onrender.com';

// Cloudflare API — used to write the access token into the worker secret after OAuth
const CF_API_TOKEN = process.env.CF_API_TOKEN || '';
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID || '';
const CF_WORKER_NAME = process.env.CF_WORKER_NAME || 'commerce-shield-prod';
const PIXEL_GUARD_TTL_MS = parseInt(process.env.PIXEL_GUARD_TTL_MS || String(24 * 60 * 60 * 1000), 10);
const PIXEL_GUARD_MAX_ENTRIES = 16;

const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

function log(level, message) {
  if (LEVELS[level] == null || LEVELS[level] < LEVELS[LOG_LEVEL]) return;
  console.log(JSON.stringify({ timestamp: new Date().toISOString(), level, message }));
}

const app = express();

// Security headers
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-XSS-Protection', '0');
  // Allow Shopify admin iframe embedding; allow calls to the Cloudflare Worker
  res.setHeader('Content-Security-Policy', "default-src 'self' https://commerce-shield-prod.ncassidy.workers.dev; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors https://*.myshopify.com https://admin.shopify.com");
  res.removeHeader('X-Powered-By');
  next();
});

// Serve static admin UI (built by scripts/gen-ui.cjs from worker/src/index.js)
app.use(express.static('public'));

// ---------------------------------------------------------------------------
// Pixel-guard caching proxy
// Storefront pageviews load /cs-pixel-guard.js. Cloudflare Workers on the
// workers.dev domain charge per request even with edge cache headers, which
// blew us past the 100k/day free quota. Render has no per-request quota, so
// we proxy the script through here with an in-memory TTL cache. The worker
// is hit at most once per ~24h per (shop, mode, enabled) variant; everything
// else is served from this process and downstream browser caches.
// ---------------------------------------------------------------------------
const pixelGuardCache = new Map(); // key -> { body, contentType, fetchedAt }

async function fetchPixelGuard(query) {
  const upstream = `${WORKER_ORIGIN}/cs-pixel-guard.js${query ? `?${query}` : ''}`;
  const r = await fetch(upstream, { headers: { 'User-Agent': 'commerce-shield-render-proxy/1.0' } });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`upstream ${r.status}: ${text.slice(0, 200)}`);
  }
  return {
    body: await r.text(),
    contentType: r.headers.get('content-type') || 'application/javascript; charset=utf-8',
    fetchedAt: Date.now(),
  };
}

app.get('/cs-pixel-guard.js', async (req, res) => {
  const query = req.originalUrl.includes('?') ? req.originalUrl.split('?')[1] : '';
  const key = query;
  const now = Date.now();
  const hit = pixelGuardCache.get(key);

  res.setHeader('Cache-Control', 'public, max-age=86400, s-maxage=86400, stale-while-revalidate=3600');
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('X-Content-Type-Options', 'nosniff');

  if (hit && now - hit.fetchedAt < PIXEL_GUARD_TTL_MS) {
    res.setHeader('Content-Type', hit.contentType);
    res.setHeader('X-CS-Cache', 'HIT');
    return res.send(hit.body);
  }

  try {
    const fresh = await fetchPixelGuard(query);
    pixelGuardCache.set(key, fresh);
    if (pixelGuardCache.size > PIXEL_GUARD_MAX_ENTRIES) {
      const oldestKey = pixelGuardCache.keys().next().value;
      pixelGuardCache.delete(oldestKey);
    }
    res.setHeader('Content-Type', fresh.contentType);
    res.setHeader('X-CS-Cache', hit ? 'REFRESH' : 'MISS');
    return res.send(fresh.body);
  } catch (err) {
    log('error', `pixel-guard upstream failed: ${err.message}`);
    if (hit) {
      // Serve stale on upstream failure rather than break the storefront.
      res.setHeader('Content-Type', hit.contentType);
      res.setHeader('X-CS-Cache', 'STALE');
      return res.send(hit.body);
    }
    return res.status(502).type('application/javascript').send('/* commerce-shield: upstream unavailable */');
  }
});

// Health check
app.get('/api/health', (_req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

// ---------------------------------------------------------------------------
// Shopify OAuth
// In-memory nonce store: nonce -> expiresAt (10 min TTL)
// ---------------------------------------------------------------------------
const oauthNonces = new Map();
const NONCE_TTL_MS = 10 * 60 * 1000;

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

function cleanNonces() {
  const now = Date.now();
  for (const [nonce, exp] of oauthNonces) {
    if (now > exp) oauthNonces.delete(nonce);
  }
}

function validateShopDomain(shop) {
  return typeof shop === 'string' && /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(shop);
}

function validateShopifyHmac(query) {
  const params = Object.assign({}, query);
  const hmac = params.hmac;
  delete params.hmac;
  const message = Object.keys(params).sort().map(k => `${k}=${params[k]}`).join('&');
  const expected = crypto.createHmac('sha256', SHOPIFY_API_SECRET).update(message).digest('hex');
  // Both are hex SHA-256 = 64 chars; timingSafeEqual requires equal length
  if (!hmac || hmac.length !== expected.length) return false;
  return crypto.timingSafeEqual(Buffer.from(hmac, 'utf8'), Buffer.from(expected, 'utf8'));
}

async function updateWorkerSecret(name, value) {
  if (!CF_API_TOKEN || !CF_ACCOUNT_ID) {
    log('warn', `CF credentials not set — cannot update worker secret ${name}`);
    return;
  }
  const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/workers/scripts/${CF_WORKER_NAME}/secrets`;
  const r = await fetch(url, {
    method: 'PUT',
    headers: {
      'Authorization': `Bearer ${CF_API_TOKEN}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({ name, text: value, type: 'secret_text' }),
  });
  if (!r.ok) {
    const text = await r.text().catch(() => '');
    throw new Error(`CF secret update failed (${name}): ${r.status} ${text.slice(0, 200)}`);
  }
}

// Step 1: Initiate OAuth — redirect merchant to Shopify
app.get('/auth', (req, res) => {
  const shop = (typeof req.query.shop === 'string' ? req.query.shop : '').toLowerCase().trim();
  if (!validateShopDomain(shop)) {
    return res.status(400).send('Invalid or missing shop parameter.');
  }
  cleanNonces();
  const nonce = generateNonce();
  oauthNonces.set(nonce, Date.now() + NONCE_TTL_MS);
  const redirectUri = `${APP_URL}/auth/callback`;
  const authUrl = `https://${shop}/admin/oauth/authorize` +
    `?client_id=${encodeURIComponent(SHOPIFY_API_KEY)}` +
    `&scope=${encodeURIComponent(SHOPIFY_SCOPES)}` +
    `&redirect_uri=${encodeURIComponent(redirectUri)}` +
    `&state=${nonce}`;
  log('info', `OAuth initiated for ${shop}`);
  res.redirect(authUrl);
});

// Step 2: Handle Shopify callback, exchange code for access token
app.get('/auth/callback', async (req, res) => {
  const shop = (typeof req.query.shop === 'string' ? req.query.shop : '').toLowerCase().trim();
  const { code, state, hmac } = req.query;

  if (!validateShopDomain(shop)) return res.status(400).send('Invalid shop.');
  if (!hmac || !code || !state) return res.status(400).send('Missing required OAuth parameters.');

  // Validate Shopify HMAC signature
  if (!validateShopifyHmac(req.query)) {
    log('warn', `OAuth HMAC validation failed for ${shop}`);
    return res.status(403).send('Request validation failed.');
  }

  // Validate and consume nonce
  cleanNonces();
  if (!oauthNonces.has(state)) {
    return res.status(403).send('Invalid or expired state token. Please try again.');
  }
  oauthNonces.delete(state);

  // Exchange code for access token
  let accessToken;
  try {
    const tokenRes = await fetch(`https://${shop}/admin/oauth/access_token`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        client_id: SHOPIFY_API_KEY,
        client_secret: SHOPIFY_API_SECRET,
        code,
      }),
    });
    if (!tokenRes.ok) {
      const text = await tokenRes.text().catch(() => '');
      throw new Error(`Token exchange failed: ${tokenRes.status} ${text.slice(0, 200)}`);
    }
    const data = await tokenRes.json();
    accessToken = data.access_token;
    if (!accessToken) throw new Error('No access_token in Shopify response');
  } catch (err) {
    log('error', `OAuth token exchange failed for ${shop}: ${err.message}`);
    return res.status(500).send('OAuth failed. Please try installing the app again.');
  }

  // Write token into the live Cloudflare worker secrets
  try {
    const tokenMap = JSON.stringify({ [shop]: accessToken });
    await Promise.all([
      updateWorkerSecret('SHOPIFY_ADMIN_ACCESS_TOKENS_JSON', tokenMap),
      updateWorkerSecret('SHOPIFY_ADMIN_ACCESS_TOKEN', accessToken),
    ]);
    log('info', `OAuth complete for ${shop} — worker secrets updated`);
  } catch (err) {
    // Non-fatal: token exchange succeeded, secret update failed
    log('error', `Worker secret update failed for ${shop}: ${err.message}`);
  }

  // Redirect into the embedded admin
  res.redirect(`https://${shop}/admin/apps/${SHOPIFY_API_KEY}`);
});

// Explicit static file routes (belt-and-suspenders alongside express.static)
app.get('/commerce-shield-report.html', (_req, res) => res.sendFile('commerce-shield-report.html', { root: 'public' }));

// Catch-all -> index.html
app.get('*', (_req, res) => res.sendFile('index.html', { root: 'public' }));

const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, () => log('info', `Commerce Shield UI listening on http://localhost:${PORT}`));
