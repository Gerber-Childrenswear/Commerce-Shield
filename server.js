'use strict';

const express = require('express');

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

// Health check
app.get('/api/health', (_req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

// Catch-all -> index.html
app.get('*', (_req, res) => res.sendFile('index.html', { root: 'public' }));

const PORT = parseInt(process.env.PORT || '10000', 10);
app.listen(PORT, () => log('info', `Commerce Shield UI listening on http://localhost:${PORT}`));
