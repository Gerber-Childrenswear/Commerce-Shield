'use strict';

const express = require('express');
const crypto = require('crypto');

// ---------------------------------------------------------------------------
// Logger — structured console output with level filtering
// ---------------------------------------------------------------------------
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const LEVELS = { debug: 0, info: 1, warn: 2, error: 3 };

function log(level, message, meta) {
  if (LEVELS[level] == null || LEVELS[level] < LEVELS[LOG_LEVEL]) return;
  const entry = {
    timestamp: new Date().toISOString(),
    level,
    message,
    ...(meta ? { meta } : {}),
  };
  const fn = level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  fn(JSON.stringify(entry));
}

// ---------------------------------------------------------------------------
// App initialisation
// ---------------------------------------------------------------------------
const app = express();

app.use(express.json({ limit: '100kb' }));

// Security headers — MUST be before express.static so static files get them too
app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-XSS-Protection', '0');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'");
  res.removeHeader('X-Powered-By');
  next();
});

app.use(express.static('public'));

// Prevent caching of API responses by intermediary proxies
app.use('/api', (_req, res, next) => {
  res.setHeader('Cache-Control', 'no-store');
  next();
});

// ---------------------------------------------------------------------------
// Authentication middleware
// ---------------------------------------------------------------------------
const ADMIN_API_TOKEN = process.env.COMMERCE_SHIELD_ADMIN_TOKEN || '';

if (!ADMIN_API_TOKEN) {
  log('warn', 'No COMMERCE_SHIELD_ADMIN_TOKEN set — admin API is unauthenticated');
}

function requireAuth(req, res, next) {
  if (!ADMIN_API_TOKEN) return next();
  const header = req.headers.authorization;
  if (!header || !header.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authorization header required' });
  }
  const token = header.slice(7);
  if (token.length !== ADMIN_API_TOKEN.length ||
      !crypto.timingSafeEqual(Buffer.from(token), Buffer.from(ADMIN_API_TOKEN))) {
    return res.status(403).json({ error: 'Invalid token' });
  }
  next();
}

// ---------------------------------------------------------------------------
// Rate limiting factory (sliding-window per IP)
// ---------------------------------------------------------------------------
function createRateLimiter(maxRequests, windowMs) {
  const buckets = new Map();

  setInterval(() => {
    const now = Date.now();
    for (const [ip, bucket] of buckets) {
      bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);
      if (bucket.timestamps.length === 0) buckets.delete(ip);
    }
  }, 300_000).unref();

  return function rateLimitMiddleware(req, res, next) {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    let bucket = buckets.get(ip);
    if (!bucket) {
      bucket = { timestamps: [] };
      buckets.set(ip, bucket);
    }
    bucket.timestamps = bucket.timestamps.filter((t) => now - t < windowMs);
    if (bucket.timestamps.length >= maxRequests) {
      res.setHeader('Retry-After', Math.ceil(windowMs / 1000));
      return res.status(429).json({ error: 'Too many requests' });
    }
    bucket.timestamps.push(now);
    next();
  };
}

const adminRateLimit = createRateLimiter(
  parseInt(process.env.RATE_LIMIT_MAX || '60', 10),
  60_000,
);
const botEventRateLimit = createRateLimiter(
  parseInt(process.env.BOT_EVENT_RATE_LIMIT_MAX || '300', 10),
  60_000,
);

// ---------------------------------------------------------------------------
// In-memory event ring buffer — bounded, O(1) insert, CTV-campaign safe
// ---------------------------------------------------------------------------
const EVENT_BUFFER_MAX = parseInt(process.env.BOT_EVENT_BUFFER_MAX || '10000', 10);
const eventBuffer = [];
let eventBufferHead = 0;
let eventBufferCount = 0;

const counters = {
  total_visits: 0,
  bot_visits: 0,
  bot_blocked: 0,
  disposable_email: 0,
  referrer_counts: {},
  landing_counts: {},
  agent_counts: {},
  hourly_bot: {},
  _sizes: { referrer: 0, landing: 0, agent: 0 },
};

function pushEvent(evt) {
  if (eventBuffer.length < EVENT_BUFFER_MAX) {
    eventBuffer.push(evt);
  } else {
    eventBuffer[eventBufferHead] = evt;
  }
  eventBufferHead = (eventBufferHead + 1) % EVENT_BUFFER_MAX;
  eventBufferCount = Math.min(eventBufferCount + 1, EVENT_BUFFER_MAX);
}

function getRecentEvents(limit) {
  const count = Math.min(limit, eventBufferCount);
  const result = [];
  let idx = (eventBufferHead - 1 + EVENT_BUFFER_MAX) % EVENT_BUFFER_MAX;
  for (let i = 0; i < count; i++) {
    if (eventBuffer[idx] != null) result.push(eventBuffer[idx]);
    idx = (idx - 1 + EVENT_BUFFER_MAX) % EVENT_BUFFER_MAX;
  }
  return result;
}

function incrementCounter(map, sizeKey, key, max) {
  if (!key) return;
  if (key in map) {
    map[key]++;
  } else if (counters._sizes[sizeKey] < (max || 500)) {
    map[key] = 1;
    counters._sizes[sizeKey]++;
  }
}

function topN(map, n) {
  return Object.entries(map)
    .sort((a, b) => b[1] - a[1])
    .slice(0, n)
    .map(([name, count]) => ({ name, count }));
}

// ===========================================================================
// UNAUTHENTICATED ROUTES — registered BEFORE auth middleware
// ===========================================================================

// Health check — must be accessible without admin token
app.get('/api/health', (_req, res) => res.json({ ok: true, timestamp: new Date().toISOString() }));

// ---------------------------------------------------------------------------
// Bot Event Ingestion (storefront -> server, fire-and-forget, no admin auth)
// ---------------------------------------------------------------------------
const ALLOWED_ORIGINS = (process.env.BOT_EVENT_ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);

app.options('/api/bot-event', (req, res) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Access-Control-Max-Age', '86400');
  }
  res.status(204).end();
});

app.post('/api/bot-event', botEventRateLimit, (req, res) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin || '*');
  }

  const body = req.body || {};

  // Server-authoritative IP — never trust client-supplied IP
  const ip = (req.ip || req.socket.remoteAddress || 'unknown').slice(0, 45);
  const userAgent = typeof body.user_agent === 'string' ? body.user_agent.slice(0, 512) : (req.headers['user-agent'] || '').slice(0, 512);
  const isBot = body.is_bot === true;
  const signals = Array.isArray(body.signals) ? body.signals.slice(0, 20).map(s => String(s).slice(0, 64)) : [];
  const page = typeof body.page === 'string' ? body.page.slice(0, 256) : '/';
  const referrer = typeof body.referrer === 'string' ? body.referrer.slice(0, 256) : '';
  const email = typeof body.email === 'string' ? body.email.slice(0, 128) : '';
  const isDisposableEmail = body.disposable_email === true;
  const channel = typeof body.channel === 'string' ? body.channel.slice(0, 32) : 'web';
  const score = typeof body.score === 'number' && Number.isFinite(body.score) ? Math.max(0, Math.min(100, body.score)) : null;

  const event = {
    id: crypto.randomUUID(),
    timestamp: new Date().toISOString(),
    ip,
    user_agent: userAgent,
    is_bot: isBot,
    signals,
    page,
    referrer,
    email: email ? `${email[0]}***@${email.split('@')[1] || '***'}` : '',
    disposable_email: isDisposableEmail,
    channel,
    score,
  };

  pushEvent(event);

  counters.total_visits++;
  if (isBot) {
    counters.bot_visits++;
    counters.bot_blocked++;
    const hour = new Date().getUTCHours();
    counters.hourly_bot[hour] = (counters.hourly_bot[hour] || 0) + 1;
  }
  if (isDisposableEmail) counters.disposable_email++;

  incrementCounter(counters.referrer_counts, 'referrer', referrer, 200);
  incrementCounter(counters.landing_counts, 'landing', page, 200);
  const agentBucket = userAgent.split('/')[0].slice(0, 40) || 'unknown';
  incrementCounter(counters.agent_counts, 'agent', agentBucket, 200);

  log('debug', 'bot-event ingested', { id: event.id, is_bot: isBot, ip });

  res.status(204).end();
});

// ===========================================================================
// AUTHENTICATED ROUTES — admin rate limit + bearer token required
// ===========================================================================
app.use('/api', adminRateLimit);
app.use('/api', requireAuth);

app.use((req, _res, next) => {
  log('debug', `${req.method} ${req.url}`);
  next();
});

// ---------------------------------------------------------------------------
// Shopify Admin API helpers
// ---------------------------------------------------------------------------
const SHOPIFY_API_VERSION = '2025-10';

function shopifyGqlUrl() {
  const domain = process.env.SHOPIFY_STORE_DOMAIN;
  if (!domain) throw new Error('SHOPIFY_STORE_DOMAIN not set');
  return `https://${domain}/admin/api/${SHOPIFY_API_VERSION}/graphql.json`;
}

function apiBase() {
  const domain = process.env.SHOPIFY_STORE_DOMAIN;
  if (!domain) throw new Error('SHOPIFY_STORE_DOMAIN not set');
  return `https://${domain}/admin/api/${SHOPIFY_API_VERSION}`;
}

function authHeader() {
  const token = process.env.SHOPIFY_ADMIN_API_ACCESS_TOKEN;
  if (!token) throw new Error('SHOPIFY_ADMIN_API_ACCESS_TOKEN not set');
  return { 'X-Shopify-Access-Token': token, 'Content-Type': 'application/json' };
}

const METAFIELD_NAMESPACE = 'gcw';
const METAFIELD_KEY_DISCOUNT = 'discount_config';
const METAFIELD_KEY_MRI = 'mri_config';

// ---------------------------------------------------------------------------
// GraphQL metafieldsSet — single mutation for create-or-update (no GET first)
// ---------------------------------------------------------------------------
async function setMetafield(key, value) {
  const mutation = `
    mutation MetafieldsSet($metafields: [MetafieldsSetInput!]!) {
      metafieldsSet(metafields: $metafields) {
        metafields { id namespace key value type }
        userErrors  { field message }
      }
    }
  `;

  const variables = {
    metafields: [
      {
        namespace: METAFIELD_NAMESPACE,
        key,
        type: 'json',
        value: JSON.stringify(value),
        ownerId: `gid://shopify/Shop/${process.env.SHOPIFY_SHOP_ID || '0'}`,
      },
    ],
  };

  const res = await fetch(shopifyGqlUrl(), {
    method: 'POST',
    headers: authHeader(),
    body: JSON.stringify({ query: mutation, variables }),
  });

  if (!res.ok) {
    const text = await res.text();
    log('error', 'metafieldsSet HTTP error', { status: res.status, body: text });
    throw new Error(`metafieldsSet failed: ${res.status}`);
  }

  const body = await res.json();
  if (!body?.data?.metafieldsSet) {
    log('error', 'metafieldsSet unexpected response', { body });
    throw new Error('metafieldsSet returned unexpected response structure');
  }
  const errors = body.data.metafieldsSet.userErrors;
  if (errors && errors.length > 0) {
    log('error', 'metafieldsSet user errors', { errors });
    throw new Error(`metafieldsSet user error: ${errors[0].message}`);
  }
  return body.data.metafieldsSet.metafields[0];
}

async function getMetafieldValue(key) {
  const url = `${apiBase()}/metafields.json?namespace=${METAFIELD_NAMESPACE}&key=${encodeURIComponent(key)}`;
  const res = await fetch(url, { headers: authHeader() });
  if (!res.ok) {
    const text = await res.text();
    log('error', 'GET metafield failed', { key, status: res.status, body: text });
    throw new Error(`GET metafield (${key}) failed: ${res.status}`);
  }
  const body = await res.json();
  if (body.metafields && body.metafields.length > 0) {
    return JSON.parse(body.metafields[0].value);
  }
  return null;
}

// ---------------------------------------------------------------------------
// Routes — Discount Config (Shopify metafield-backed via GraphQL)
// ---------------------------------------------------------------------------
app.get('/api/config', async (req, res, next) => {
  try {
    const config = await getMetafieldValue(METAFIELD_KEY_DISCOUNT);
    return res.json({ config });
  } catch (err) {
    next(err);
  }
});

app.post('/api/config', async (req, res, next) => {
  try {
    const { percent, active, notes } = req.body || {};
    if (percent == null && active == null && notes == null) {
      return res.status(400).json({ error: 'At least one field (percent, active, notes) is required' });
    }
    if (percent != null && (typeof percent !== 'number' || !Number.isFinite(percent) || percent < 0 || percent > 100)) {
      return res.status(400).json({ error: 'percent must be a finite number between 0 and 100' });
    }
    if (active != null && typeof active !== 'boolean') {
      return res.status(400).json({ error: 'active must be a boolean' });
    }
    if (notes != null && typeof notes !== 'string') {
      return res.status(400).json({ error: 'notes must be a string' });
    }
    if (notes != null && notes.length > 500) {
      return res.status(400).json({ error: 'notes must be 500 characters or fewer' });
    }
    // Only include fields that were explicitly provided
    const config = {};
    if (percent != null) config.percent = percent;
    if (active != null) config.active = active;
    if (notes != null) config.notes = notes;
    const saved = await setMetafield(METAFIELD_KEY_DISCOUNT, config);
    log('info', 'Discount config saved', { percent, active });
    return res.json({ metafield: saved });
  } catch (err) {
    next(err);
  }
});

// ---------------------------------------------------------------------------
// Routes — Conversion MRI Engine (metafield-backed, persists across restarts)
// ---------------------------------------------------------------------------
const MRI_DEFAULTS = {
  enabled: false,
  ui_mode: 'bloomreach',
  discount_optimization: false,
  coupon_abuse_prevention: false,
  bot_protection: false,
  profit_maximization: false,
};

app.get('/api/mri-config', async (req, res, next) => {
  try {
    const config = await getMetafieldValue(METAFIELD_KEY_MRI);
    res.json(config || MRI_DEFAULTS);
  } catch (err) {
    next(err);
  }
});

app.post('/api/mri-config', async (req, res, next) => {
  try {
    const body = req.body || {};
    const mriConfig = {
      enabled: !!body.enabled,
      ui_mode: ['bloomreach', 'custom', 'both'].includes(body.ui_mode) ? body.ui_mode : 'bloomreach',
      discount_optimization: !!body.discount_optimization,
      coupon_abuse_prevention: !!body.coupon_abuse_prevention,
      bot_protection: !!body.bot_protection,
      profit_maximization: !!body.profit_maximization,
    };
    await setMetafield(METAFIELD_KEY_MRI, mriConfig);
    log('info', 'MRI config saved to metafield', mriConfig);
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

app.get('/api/mri-overview', async (req, res, next) => {
  try {
    const config = await getMetafieldValue(METAFIELD_KEY_MRI);
    if (!config || !config.enabled) {
      return res.json({ show: false });
    }
    res.json({ show: true, issues: [] });
  } catch (err) {
    next(err);
  }
});

app.get('/api/metrics', (_req, res) => {
  res.json({
    revenue_saved: 0,
    conversion_lift: 0,
    coupon_abuse_prevented: counters.disposable_email,
    bot_traffic_blocked: counters.bot_blocked,
    channel_breakdown: [],
  });
});

// ---------------------------------------------------------------------------
// Routes — Recent Visits (backed by the bot-event ring buffer)
// ---------------------------------------------------------------------------
app.get('/api/recent-visits', (req, res) => {
  const botsOnly = req.query.bots === '1';
  const limit = Math.min(parseInt(req.query.limit || '100', 10) || 100, 500);
  const recent = getRecentEvents(limit);
  const filtered = botsOnly ? recent.filter((e) => e.is_bot) : recent;

  const sevenDaysAgo = Date.now() - 7 * 86400_000;
  const last7 = recent.filter((e) => new Date(e.timestamp).getTime() >= sevenDaysAgo);
  const botCount7 = last7.filter((e) => e.is_bot).length;

  res.json({
    summary: botsOnly
      ? `${botCount7} bot visits in last 7 days`
      : `${last7.length} total visits in last 7 days (${botCount7} bots)`,
    visits: filtered,
    analytics: {
      top_referrers: topN(counters.referrer_counts, 10),
      top_landings: topN(counters.landing_counts, 10),
      top_agents: topN(counters.agent_counts, 10),
      peak_bot_times: Object.entries(counters.hourly_bot)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 5)
        .map(([hour, count]) => ({ hour: parseInt(hour, 10), count })),
    },
  });
});

// ---------------------------------------------------------------------------
// Routes — App Health Check
// ---------------------------------------------------------------------------
app.get('/api/app-health', (_req, res) => {
  res.json({ apps: [] });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------
app.use((err, _req, res, _next) => {
  log('error', err.message, { stack: err.stack });
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start server
// ---------------------------------------------------------------------------
const port = process.env.PORT || 4000;
const server = app.listen(port, () => log('info', `Commerce Shield listening on http://localhost:${port}`));

// Graceful shutdown — drain active connections before exiting
function shutdown(signal) {
  log('info', `${signal} received — shutting down gracefully`);
  server.close(() => {
    log('info', 'All connections drained — exiting');
    process.exit(0);
  });
  // Force exit after 10s if connections won't drain
  setTimeout(() => {
    log('warn', 'Forcing exit after timeout');
    process.exit(1);
  }, 10_000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
