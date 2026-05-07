'use strict';

const express = require('express');

const WORKER_ORIGIN = process.env.WORKER_ORIGIN || 'https://commerce-shield-prod.ncassidy.workers.dev';
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

// Explicit static file routes (belt-and-suspenders alongside express.static)
app.get('/commerce-shield-report.html', (_req, res) => res.sendFile('commerce-shield-report.html', { root: 'public' }));

// Catch-all -> index.html
app.get('*', (_req, res) => res.sendFile('index.html', { root: 'public' }));

const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, () => log('info', `Commerce Shield UI listening on http://localhost:${PORT}`));
