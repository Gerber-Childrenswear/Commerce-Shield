import { scoreIntentProfile } from "../../shared/intent-scoring.js";
import { createHmacSignature, parseAllowedOrigins, timingSafeEqualHex } from "../../shared/worker-security.js";

/**
 * Commerce Shield — Cloudflare Worker
 * Stats collection + Dashboard UI + intent scoring edge API
 */

const OPEN_CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-CS-Signature, X-CS-Timestamp, X-CS-Nonce",
};

const SENSITIVE_CORS_HEADERS = {
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-CS-Signature, X-CS-Timestamp, X-CS-Nonce",
};

const MAX_JSON_BODY_BYTES = 16 * 1024;
const INTENT_EVENT_LIMIT = 120;
const BLOOMREACH_LOOKUP_LIMIT = 30;
const PIXEL_GUARD_EVENT_LIMIT = 240;
const DASHBOARD_READ_LIMIT = 60;
const RECENT_READ_LIMIT = 60;
const NONCE_WINDOW_SECONDS = 300;
const SHOPIFY_ADMIN_API_VERSION_FALLBACK = "2026-01";
const SHOPIFY_INTENT_NAMESPACE = "$app";
const SHOPIFY_INTENT_MODEL_VERSION = "intent-v1";
const SHOPIFY_AUDIT_REQUIRED_SCOPES = ["read_themes", "read_script_tags"];
const SHOPIFY_THEME_INSTALL_REQUIRED_SCOPES = ["read_themes", "write_themes"];
const PIXEL_GUARD_MARKER = "Commerce Shield Pixel Guard";
const INTENT_HIGH_TIERS = new Set(["high_intent", "purchase_ready", "customer"]);
const INTENT_MEDIUM_TIERS = new Set(["considering", "interested"]);
const DEFAULT_HUMAN_VISIT_SAMPLE_RATE = 0.05;
const DEFAULT_SUSPICIOUS_VISIT_THRESHOLD = 0.35;
const DATACENTER_ASNS = new Set([
  // Major cloud/datacenter providers frequently used by scraping traffic.
  14618, 16509, 8075, 15169, 19527, 20473, 396982, 45102,
  134238, 132203, 38365, 55967, 24940, 34119, 48693, 49815,
  51167, 53667, 55286, 60781, 62567, 63949, 9009, 35913,
  40021, 197695, 206728,
]);
const DATACENTER_ORG_HINTS = [
  "amazon", "aws", "google", "gcp", "azure", "microsoft", "oracle",
  "alibaba", "tencent", "digitalocean", "linode", "vultr", "choopa",
  "hetzner", "ovh", "racknerd", "frantech", "contabo", "scaleway",
  "leaseweb", "hostwinds", "m247",
];
const KNOWN_BAD_JA3 = new Set([
  // Add observed bot TLS fingerprints here as they are identified.
]);
const DEFAULT_ADMIN_SETTINGS = Object.freeze({
  intent: {
    sensitivity: 62,
    includePaths: ["/products/*", "/collections/*", "/cart", "/checkout"],
    rewardProductViews: true,
    rewardCartSignals: true,
    rewardReturningSessions: true,
    suppressBotsAndCrawlers: true,
    conservativeMode: true,
  },
  appHealth: {
    detectLegacyScriptTags: true,
    requireThemeAppExtensions: true,
    detectDuplicatePixels: true,
    reviewInlineScripts: true,
    conservativeFlagging: true,
  },
  conversionMri: {
    conservativeMode: true,
    runAppChecks: true,
    runContentChecks: true,
    runAdaChecks: true,
    runSeoChecks: true,
    runSpeedChecks: true,
  },
});

const ALLOWED_INTENT_EVENTS = new Set([
  "page_view",
  "collection_view",
  "search",
  "search_click",
  "filter_use",
  "sort_use",
  "product_view",
  "variant_select",
  "media_interaction",
  "size_guide_open",
  "review_open",
  "scroll_depth_50",
  "scroll_depth_80",
  "engaged_30s",
  "engaged_120s",
  "add_to_cart",
  "cart_view",
  "cart_update",
  "checkout_start",
  "email_capture",
  "login",
  "purchase",
  "session_summary",
  "discount_view",
]);

class HttpError extends Error {
  constructor(message, status = 400) {
    super(message);
    this.status = status;
  }
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const sensitiveRoute = isSensitiveRoute(url.pathname);
    const corsHeaders = buildCorsHeaders(request, env, sensitiveRoute);

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      if (url.pathname === "/api/stats" && request.method === "POST") {
        return handleStats(request, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/pixel-guard/event" && request.method === "POST") {
        return handlePixelGuardEvent(request, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/dashboard" && request.method === "GET") {
        return handleDashboardData(request, url, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/recent" && request.method === "GET") {
        return handleRecentVisits(request, url, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/admin/settings") {
        return handleAdminSettings(request, url, env, corsHeaders);
      }
      if (url.pathname === "/api/admin/install-pixel-guard" && request.method === "POST") {
        return handleAdminInstallPixelGuard(request, url, env, corsHeaders);
      }
      if (url.pathname === "/api/admin/intent-summary" && request.method === "GET") {
        return handleAdminIntentSummary(url, env, corsHeaders);
      }
      if (url.pathname === "/api/admin/store-audit" && request.method === "GET") {
        return handleAdminStoreAudit(url, env, corsHeaders);
      }
      if (url.pathname === "/api/admin/conversion-mri" && request.method === "GET") {
        return handleAdminConversionMri(url, env, corsHeaders);
      }
      if (url.pathname === "/api/intent/event" && request.method === "POST") {
        return handleIntentEvent(request, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/integrations/bloomreach/intent-profile" && request.method === "POST") {
        return handleBloomreachIntentProfile(request, env, corsHeaders, ctx);
      }
      if (url.pathname === "/api/turnstile-verify" && request.method === "POST") {
        return handleTurnstileVerify(request, env, corsHeaders);
      }
      if (url.pathname === "/cs-pixel-guard.js" && request.method === "GET") {
        return servePixelGuard(url);
      }
      if (url.pathname === "/" || url.pathname === "/app" || url.pathname.startsWith("/app/")) {
        return serveEmbeddedAdmin(url, request, ctx);
      }
      if (url.pathname === "/dashboard") {
        return serveDashboard(url, request, ctx);
      }
      return new Response("Not found", { status: 404 });
    } catch (error) {
      if (error instanceof HttpError) {
        return jsonResponse({ error: error.message }, error.status, corsHeaders);
      }
      return jsonResponse({ error: error.message || "Unexpected error" }, 500, corsHeaders);
    }
  },
};

function isSensitiveRoute(pathname) {
  return pathname === "/api/integrations/bloomreach/intent-profile" || pathname.startsWith("/api/admin/");
}

function buildCorsHeaders(request, env, sensitiveRoute) {
  if (!sensitiveRoute) return OPEN_CORS_HEADERS;
  const origin = request.headers.get("origin");
  const allowedOrigins = parseAllowedOrigins(env.BLOOMREACH_ALLOWED_ORIGINS);
  if (!origin || !allowedOrigins.includes(origin)) return SENSITIVE_CORS_HEADERS;
  return { ...SENSITIVE_CORS_HEADERS, "Access-Control-Allow-Origin": origin, Vary: "Origin" };
}

function jsonResponse(body, status, corsHeaders) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders },
  });
}

function jsonResponseWithHeaders(body, status, corsHeaders, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders, ...extraHeaders },
  });
}

function buildReadCacheKey(route, shop, params = {}) {
  const keyUrl = new URL(`https://cache.local${route}`);
  keyUrl.searchParams.set("shop", shop);
  for (const [key, value] of Object.entries(params)) {
    keyUrl.searchParams.set(key, String(value));
  }
  return new Request(keyUrl.toString(), { method: "GET" });
}

async function respondWithEdgeCache(cacheKey, ttlSeconds, corsHeaders, ctx, producer) {
  const cache = caches.default;
  const cached = await cache.match(cacheKey);
  if (cached) {
    const hitHeaders = new Headers(cached.headers);
    for (const [name, value] of Object.entries(corsHeaders)) {
      hitHeaders.set(name, value);
    }
    hitHeaders.set("X-CS-Cache", "HIT");
    return new Response(cached.body, { status: cached.status, headers: hitHeaders });
  }

  const fresh = await producer();
  const freshHeaders = new Headers(fresh.headers);
  for (const [name, value] of Object.entries(corsHeaders)) {
    freshHeaders.set(name, value);
  }
  freshHeaders.set("Cache-Control", `public, max-age=0, s-maxage=${ttlSeconds}, stale-while-revalidate=${Math.min(ttlSeconds * 4, 300)}`);
  freshHeaders.set("X-CS-Cache", "MISS");
  const cacheable = new Response(fresh.body, { status: fresh.status, headers: freshHeaders });

  if (cacheable.status >= 200 && cacheable.status < 300) {
    const toStore = cacheable.clone();
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(cache.put(cacheKey, toStore));
    } else {
      await cache.put(cacheKey, toStore);
    }
  }

  return cacheable;
}

function shouldBlockNoisyReadRequest(request) {
  const userAgent = sanitizeString(request.headers.get("user-agent") || "", 400).toLowerCase();
  const hardBotUa = /(adsbot|baiduspider|bingbot|bot|crawler|curl|duckduckbot|googlebot|headless|httpclient|lighthouse|playwright|prerender|puppeteer|python-requests|selenium|spider|wget|yandexbot)/i.test(userAgent);
  const cfRisk = applyCloudflareRiskSignals(request, 0, false, "low");
  if (cfRisk.cfThreatScore >= 40) return true;
  if (hardBotUa && cfRisk.isBot && cfRisk.confidence === "high") return true;
  return false;
}

function extractIp(request) {
  return (
    request.headers.get("cf-connecting-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    request.headers.get("x-real-ip") ||
    "unknown"
  );
}

async function parseJsonRequest(request, maxBytes = MAX_JSON_BODY_BYTES) {
  const lengthHeader = request.headers.get("content-length");
  if (lengthHeader && Number(lengthHeader) > maxBytes) {
    throw new HttpError("Payload too large", 413);
  }

  const text = await request.text();
  if (!text) throw new HttpError("Missing request body", 400);
  if (text.length > maxBytes) throw new HttpError("Payload too large", 413);

  try {
    return { rawText: text, body: JSON.parse(text) };
  } catch {
    throw new HttpError("Invalid JSON body", 400);
  }
}

function sanitizeString(value, maxLength = 255) {
  if (typeof value !== "string") return "";
  return value.trim().slice(0, maxLength);
}

function timingSafeEqualString(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) {
    result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return result === 0;
}

function requireWorkerAdmin(request, env) {
  const configuredToken = sanitizeString(env.COMMERCE_SHIELD_ADMIN_TOKEN, 500);
  if (!configuredToken) {
    throw new HttpError("Commerce Shield admin token is not configured for theme installation", 503);
  }

  const header = request.headers.get("authorization") || "";
  if (!header.startsWith("Bearer ")) {
    throw new HttpError("Authorization header required", 401);
  }

  const token = header.slice(7);
  if (!timingSafeEqualString(token, configuredToken)) {
    throw new HttpError("Invalid Commerce Shield admin token", 403);
  }
}

function normalizeShopDomain(value) {
  const candidate = sanitizeString(value, 120).toLowerCase();
  return /^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(candidate) ? candidate : "";
}

function sanitizeEmailHash(value) {
  const candidate = sanitizeString(value, 80).toLowerCase();
  return /^sha256:[a-f0-9]{64}$/.test(candidate) ? candidate : "";
}

function normalizeCustomerId(value) {
  const candidate = sanitizeString(value, 180);
  if (!candidate) return "";
  if (candidate.indexOf("gid://shopify/Customer/") === 0) return candidate;
  if (/^\d+$/.test(candidate)) return `gid://shopify/Customer/${candidate}`;
  return "";
}

function normalizeAdminApiVersion(value) {
  const candidate = sanitizeString(value, 20);
  return /^\d{4}-\d{2}$/.test(candidate) ? candidate : SHOPIFY_ADMIN_API_VERSION_FALLBACK;
}

function parseShopifyAdminTokenMap(env) {
  const tokens = {};
  const directShop = normalizeShopDomain(env.SHOPIFY_ADMIN_SHOP);
  const directToken = sanitizeString(env.SHOPIFY_ADMIN_ACCESS_TOKEN, 400);
  if (directShop && directToken) {
    tokens[directShop] = directToken;
  }

  const rawTokenMap = typeof env.SHOPIFY_ADMIN_ACCESS_TOKENS_JSON === "string"
    ? env.SHOPIFY_ADMIN_ACCESS_TOKENS_JSON.trim()
    : "";

  if (!rawTokenMap) return tokens;

  try {
    const parsed = JSON.parse(rawTokenMap);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return tokens;
    for (const [shop, token] of Object.entries(parsed)) {
      const normalizedShop = normalizeShopDomain(shop);
      const normalizedToken = sanitizeString(token, 400);
      if (normalizedShop && normalizedToken) {
        tokens[normalizedShop] = normalizedToken;
      }
    }
  } catch {
    return tokens;
  }

  return tokens;
}

function buildIntentSyncPayload(payload, scoredProfile) {
  return {
    shop: payload.shop,
    customerId: payload.customerId,
    visitorKey: payload.visitorKey,
    emailHash: payload.emailHash || null,
    intentScore: scoredProfile.intentScore,
    intentTier: scoredProfile.intentTier,
    intentConfidence: scoredProfile.intentConfidence,
    intentUpdatedAt: scoredProfile.lastSeenAt || payload.createdAt,
    intentModelVersion: SHOPIFY_INTENT_MODEL_VERSION,
    sourceEventType: payload.eventType,
  };
}

function cloneDefaultAdminSettings() {
  return JSON.parse(JSON.stringify(DEFAULT_ADMIN_SETTINGS));
}

function clampNumber(value, fallback, min, max) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, Math.round(parsed)));
}

function coerceBoolean(value, fallback) {
  if (typeof value === "boolean") return value;
  if (typeof value === "string") {
    if (value === "true" || value === "1" || value === "on") return true;
    if (value === "false" || value === "0" || value === "off") return false;
  }
  return fallback;
}

function normalizePathPatterns(value) {
  const rawValues = Array.isArray(value)
    ? value
    : typeof value === "string"
      ? value.split(/\r?\n|,/g)
      : [];

  const deduped = [];
  const seen = new Set();
  for (const rawValue of rawValues) {
    const candidate = sanitizeString(rawValue, 160);
    if (!candidate) continue;
    const normalized = candidate.startsWith("/") ? candidate : `/${candidate.replace(/^\/+/, "")}`;
    if (seen.has(normalized)) continue;
    seen.add(normalized);
    deduped.push(normalized);
    if (deduped.length >= 20) break;
  }

  return deduped.length > 0 ? deduped : cloneDefaultAdminSettings().intent.includePaths;
}

function normalizeAdminSettings(input) {
  const defaults = cloneDefaultAdminSettings();
  const source = input && typeof input === "object" ? input : {};
  const intent = source.intent && typeof source.intent === "object" ? source.intent : {};
  const appHealth = source.appHealth && typeof source.appHealth === "object" ? source.appHealth : {};
  const conversionMri = source.conversionMri && typeof source.conversionMri === "object" ? source.conversionMri : {};

  return {
    intent: {
      sensitivity: clampNumber(intent.sensitivity, defaults.intent.sensitivity, 10, 95),
      includePaths: normalizePathPatterns(intent.includePaths ?? defaults.intent.includePaths),
      rewardProductViews: coerceBoolean(intent.rewardProductViews, defaults.intent.rewardProductViews),
      rewardCartSignals: coerceBoolean(intent.rewardCartSignals, defaults.intent.rewardCartSignals),
      rewardReturningSessions: coerceBoolean(intent.rewardReturningSessions, defaults.intent.rewardReturningSessions),
      suppressBotsAndCrawlers: coerceBoolean(intent.suppressBotsAndCrawlers, defaults.intent.suppressBotsAndCrawlers),
      conservativeMode: coerceBoolean(intent.conservativeMode, defaults.intent.conservativeMode),
    },
    appHealth: {
      detectLegacyScriptTags: coerceBoolean(appHealth.detectLegacyScriptTags, defaults.appHealth.detectLegacyScriptTags),
      requireThemeAppExtensions: coerceBoolean(appHealth.requireThemeAppExtensions, defaults.appHealth.requireThemeAppExtensions),
      detectDuplicatePixels: coerceBoolean(appHealth.detectDuplicatePixels, defaults.appHealth.detectDuplicatePixels),
      reviewInlineScripts: coerceBoolean(appHealth.reviewInlineScripts, defaults.appHealth.reviewInlineScripts),
      conservativeFlagging: coerceBoolean(appHealth.conservativeFlagging, defaults.appHealth.conservativeFlagging),
    },
    conversionMri: {
      conservativeMode: coerceBoolean(conversionMri.conservativeMode, defaults.conversionMri.conservativeMode),
      runAppChecks: coerceBoolean(conversionMri.runAppChecks, defaults.conversionMri.runAppChecks),
      runContentChecks: coerceBoolean(conversionMri.runContentChecks, defaults.conversionMri.runContentChecks),
      runAdaChecks: coerceBoolean(conversionMri.runAdaChecks, defaults.conversionMri.runAdaChecks),
      runSeoChecks: coerceBoolean(conversionMri.runSeoChecks, defaults.conversionMri.runSeoChecks),
      runSpeedChecks: coerceBoolean(conversionMri.runSpeedChecks, defaults.conversionMri.runSpeedChecks),
    },
  };
}

async function getAdminSettings(env, shop) {
  const row = await env.DB.prepare(
    `SELECT intent_settings, app_health_settings, conversion_mri_settings
     FROM admin_shop_settings
     WHERE shop = ?
     LIMIT 1`
  ).bind(shop).first();

  if (!row) return cloneDefaultAdminSettings();

  return normalizeAdminSettings({
    intent: safeJsonParse(row.intent_settings, {}),
    appHealth: safeJsonParse(row.app_health_settings, {}),
    conversionMri: safeJsonParse(row.conversion_mri_settings, {}),
  });
}

async function saveAdminSettings(env, shop, partialSettings) {
  const current = await getAdminSettings(env, shop);
  const next = normalizeAdminSettings({
    intent: { ...current.intent, ...(partialSettings.intent || {}) },
    appHealth: { ...current.appHealth, ...(partialSettings.appHealth || {}) },
    conversionMri: { ...current.conversionMri, ...(partialSettings.conversionMri || {}) },
  });

  await env.DB.prepare(
    `INSERT INTO admin_shop_settings (
      shop, intent_settings, app_health_settings, conversion_mri_settings, updated_at
    ) VALUES (?, ?, ?, ?, datetime('now'))
    ON CONFLICT(shop) DO UPDATE SET
      intent_settings = excluded.intent_settings,
      app_health_settings = excluded.app_health_settings,
      conversion_mri_settings = excluded.conversion_mri_settings,
      updated_at = datetime('now')`
  ).bind(
    shop,
    JSON.stringify(next.intent),
    JSON.stringify(next.appHealth),
    JSON.stringify(next.conversionMri),
  ).run();

  return next;
}

function getRequiredShop(url) {
  const shop = normalizeShopDomain(url.searchParams.get("shop"));
  if (!shop) throw new HttpError("Missing or invalid shop parameter", 400);
  return shop;
}

function summarizeIntentSensitivity(sensitivity) {
  if (sensitivity >= 80) return "Very selective";
  if (sensitivity >= 65) return "Balanced";
  if (sensitivity >= 45) return "Broad";
  return "Exploratory";
}

async function handleAdminSettings(request, url, env, corsHeaders) {
  if (request.method === "GET") {
    const shop = getRequiredShop(url);
    const settings = await getAdminSettings(env, shop);
    return jsonResponse({ shop, settings }, 200, corsHeaders);
  }

  if (request.method === "POST") {
    const { body } = await parseJsonRequest(request);
    const shop = normalizeShopDomain(body.shop);
    if (!shop) throw new HttpError("Missing or invalid shop", 400);
    const settings = await saveAdminSettings(env, shop, body);
    return jsonResponse({ ok: true, shop, settings }, 200, corsHeaders);
  }

  throw new HttpError("Method not allowed", 405);
}

async function handleAdminInstallPixelGuard(request, url, env, corsHeaders) {
  requireWorkerAdmin(request, env);
  const { body } = await parseJsonRequest(request, 4 * 1024);
  const shop = normalizeShopDomain(body.shop || url.searchParams.get("shop"));
  if (!shop) throw new HttpError("Missing or invalid shop", 400);

  const result = await installPixelGuardInTheme(env, shop, url.origin);
  return jsonResponse({ shop, ...result }, 200, corsHeaders);
}

async function fetchIntentSummary(env, shop) {
  const settings = await getAdminSettings(env, shop);
  const profileStats = await env.DB.prepare(
    `SELECT
       COUNT(*) as total_profiles,
       SUM(CASE WHEN bot_excluded = 1 THEN 1 ELSE 0 END) as bots_and_crawlers,
       SUM(CASE WHEN bot_excluded = 0 AND intent_tier IN ('high_intent', 'purchase_ready', 'customer') THEN 1 ELSE 0 END) as high_intent,
       SUM(CASE WHEN bot_excluded = 0 AND intent_tier IN ('considering', 'interested') THEN 1 ELSE 0 END) as medium_intent,
       SUM(CASE WHEN bot_excluded = 0 AND intent_tier NOT IN ('high_intent', 'purchase_ready', 'customer', 'considering', 'interested') THEN 1 ELSE 0 END) as low_intent,
       AVG(intent_score) as avg_intent_score
     FROM intent_profiles
     WHERE shop = ? AND updated_at >= datetime('now', '-30 days')`
  ).bind(shop).first();

  const pathRows = await env.DB.prepare(
    `SELECT page, COUNT(*) as hits
     FROM intent_events
     WHERE shop = ? AND page IS NOT NULL AND created_at >= datetime('now', '-30 days')
     GROUP BY page
     ORDER BY hits DESC
     LIMIT 8`
  ).bind(shop).all();

  const eventRows = await env.DB.prepare(
    `SELECT event_type, COUNT(*) as hits
     FROM intent_events
     WHERE shop = ? AND created_at >= datetime('now', '-30 days')
     GROUP BY event_type
     ORDER BY hits DESC
     LIMIT 8`
  ).bind(shop).all();

  const signalRows = await env.DB.prepare(
    `SELECT signal_summary
     FROM intent_profiles
     WHERE shop = ? AND signal_summary IS NOT NULL AND updated_at >= datetime('now', '-30 days')
     ORDER BY updated_at DESC
     LIMIT 200`
  ).bind(shop).all();

  const signalCounts = new Map();
  for (const row of signalRows.results || []) {
    for (const signal of safeJsonParse(row.signal_summary, [])) {
      const type = sanitizeString(signal?.type, 80);
      if (!type) continue;
      signalCounts.set(type, (signalCounts.get(type) || 0) + 1);
    }
  }

  const topSignals = Array.from(signalCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([type, count]) => ({ type, count }));

  return {
    settings,
    cohorts: {
      totalProfiles: Number(profileStats?.total_profiles) || 0,
      highIntent: Number(profileStats?.high_intent) || 0,
      mediumIntent: Number(profileStats?.medium_intent) || 0,
      lowIntent: Number(profileStats?.low_intent) || 0,
      botsAndCrawlers: Number(profileStats?.bots_and_crawlers) || 0,
      averageScore: Math.round(Number(profileStats?.avg_intent_score) || 0),
    },
    topPaths: (pathRows.results || []).map((row) => ({ path: row.page, hits: Number(row.hits) || 0 })),
    topEvents: (eventRows.results || []).map((row) => ({ eventType: row.event_type, hits: Number(row.hits) || 0 })),
    topSignals,
    sensitivityLabel: summarizeIntentSensitivity(settings.intent.sensitivity),
  };
}

async function handleAdminIntentSummary(url, env, corsHeaders) {
  const shop = getRequiredShop(url);
  return jsonResponse(await fetchIntentSummary(env, shop), 200, corsHeaders);
}

function getShopifyAccessToken(env, shop) {
  return parseShopifyAdminTokenMap(env)[shop] || "";
}

async function shopifyAdminRestGet(env, shop, path) {
  const accessToken = getShopifyAccessToken(env, shop);
  if (!accessToken) throw new HttpError("Shopify Admin token is not configured for this shop", 503);
  const apiVersion = normalizeAdminApiVersion(env.SHOPIFY_ADMIN_API_VERSION);
  const response = await fetch(`https://${shop}/admin/api/${apiVersion}${path}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
  });

  if (!response.ok) {
    throw new Error(`Shopify REST request failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function shopifyAdminRestPut(env, shop, path, body) {
  const accessToken = getShopifyAccessToken(env, shop);
  if (!accessToken) throw new HttpError("Shopify Admin token is not configured for this shop", 503);
  const apiVersion = normalizeAdminApiVersion(env.SHOPIFY_ADMIN_API_VERSION);
  const response = await fetch(`https://${shop}/admin/api/${apiVersion}${path}`, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify(body),
  });

  if (!response.ok) {
    throw new Error(`Shopify REST request failed: ${response.status} ${await response.text()}`);
  }

  return response.json();
}

async function shopifyAdminGraphql(env, shop, query, variables = {}) {
  const accessToken = getShopifyAccessToken(env, shop);
  if (!accessToken) throw new HttpError("Shopify Admin token is not configured for this shop", 503);
  const apiVersion = normalizeAdminApiVersion(env.SHOPIFY_ADMIN_API_VERSION);
  const response = await fetch(`https://${shop}/admin/api/${apiVersion}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({ query, variables }),
  });

  if (!response.ok) {
    throw new Error(`Shopify GraphQL request failed: ${response.status} ${await response.text()}`);
  }

  const result = await response.json();
  if (Array.isArray(result?.errors) && result.errors.length > 0) {
    throw new Error(result.errors.map((entry) => entry.message).join("; "));
  }

  return result.data || {};
}

async function fetchGrantedShopifyScopes(env, shop) {
  const accessScopesResponse = await shopifyAdminRestGet(env, shop, "/oauth/access_scopes.json");
  return (accessScopesResponse?.access_scopes || []).map((scope) => scope.handle);
}

async function fetchMainTheme(env, shop) {
  const themesData = await shopifyAdminGraphql(
    env,
    shop,
    `query CommerceShieldThemes {
      themes(first: 10) {
        nodes {
          id
          name
          role
          updatedAt
        }
      }
    }`,
  );

  const themeNodes = themesData?.themes?.nodes || [];
  return themeNodes.find((theme) => theme.role === "MAIN") || themeNodes[0] || null;
}

async function fetchThemeTextFile(env, shop, themeId, filename) {
  const themeData = await shopifyAdminGraphql(
    env,
    shop,
    `query CommerceShieldThemeFile($themeId: ID!, $filenames: [String!]!) {
      theme(id: $themeId) {
        files(filenames: $filenames) {
          nodes {
            filename
            body {
              ... on OnlineStoreThemeFileBodyText {
                content
              }
            }
          }
          userErrors {
            code
            filename
          }
        }
      }
    }`,
    {
      themeId,
      filenames: [filename],
    },
  );

  const file = (themeData?.theme?.files?.nodes || []).find((entry) => entry.filename === filename);
  return normalizeThemeText(file?.body?.content);
}

async function upsertThemeTextFile(env, shop, themeId, filename, content) {
  try {
    const result = await shopifyAdminGraphql(
      env,
      shop,
      `mutation CommerceShieldThemeFilesUpsert($themeId: ID!, $files: [OnlineStoreThemeFilesUpsertFileInput!]!) {
        themeFilesUpsert(themeId: $themeId, files: $files) {
          upsertedThemeFiles {
            filename
          }
          userErrors {
            code
            field
            filename
            message
          }
        }
      }`,
      {
        themeId,
        files: [
          {
            filename,
            body: {
              type: "TEXT",
              value: content,
            },
          },
        ],
      },
    );

    const errors = result?.themeFilesUpsert?.userErrors || [];
    if (errors.length > 0) {
      throw new Error(errors.map((error) => error.message).join("; "));
    }

    return result?.themeFilesUpsert?.upsertedThemeFiles || [];
  } catch (error) {
    const numericThemeId = String(themeId).split("/").pop();
    if (!/^\d+$/.test(numericThemeId)) throw error;
    await shopifyAdminRestPut(env, shop, `/themes/${numericThemeId}/assets.json`, {
      asset: {
        key: filename,
        value: content,
      },
    });
    return [{ filename }];
  }
}

function normalizeThemeText(content) {
  if (typeof content === "string") return content;
  return "";
}

function extractAbsoluteHosts(content) {
  const hosts = [];
  const regex = /<script\b[^>]*\bsrc=["']((?:https?:)?\/\/[^"']+)["']/gi;
  let match;
  while ((match = regex.exec(content))) {
    try {
      const parsed = new URL(match[1].startsWith("//") ? `https:${match[1]}` : match[1]);
      hosts.push(parsed.hostname.toLowerCase());
    } catch {
      continue;
    }
  }
  return hosts;
}

function countInlineScripts(content) {
  const matches = content.match(/<script\b(?![^>]*\bsrc=)[^>]*>/gi);
  return matches ? matches.length : 0;
}

function countOccurrences(content, pattern) {
  return (content.match(pattern) || []).length;
}

function buildAuditFinding(severity, category, title, location, evidence, fix, missedConversionPct) {
  return { severity, category, title, location, evidence, fix, missedConversionPct };
}

function detectDuplicatePixelLibraries(themeLiquid, scriptTags) {
  const haystack = `${themeLiquid}\n${scriptTags.map((entry) => entry.src || "").join("\n")}`;
  const libraries = [
    { key: "Google tracking", pattern: /(googletagmanager\.com|gtag\()/gi },
    { key: "Meta pixel", pattern: /(connect\.facebook\.net|fbq\()/gi },
    { key: "TikTok pixel", pattern: /(analytics\.tiktok\.com|ttq\()/gi },
    { key: "Pinterest pixel", pattern: /(ct\.pinterest\.com|pintrk\()/gi },
  ];

  return libraries
    .map((library) => ({ key: library.key, count: countOccurrences(haystack, library.pattern) }))
    .filter((library) => library.count > 1);
}

function deriveAppHealthStatus(findings) {
  if (findings.some((finding) => finding.severity === "high")) return "critical";
  if (findings.some((finding) => finding.severity === "medium")) return "warning";
  return "healthy";
}

function buildPixelGuardThemeSnippet(shop, workerOrigin) {
  // Serve via Render proxy to avoid blowing the workers.dev free request quota.
  // Render caches the script in-memory and downstream browsers cache for 24h,
  // so the worker is only hit once per ~24h per (shop, mode) variant.
  // Bot event POSTs (rare) still go straight to the worker via the script's
  // baked-in `apiBase`.
  const PIXEL_GUARD_PROXY_HOST = "https://commerce-shield.onrender.com";
  const scriptUrl = `${PIXEL_GUARD_PROXY_HOST}/cs-pixel-guard.js?shop=${encodeURIComponent(shop)}`;
  return `  <!-- ${PIXEL_GUARD_MARKER} -->\n  <script src="${scriptUrl}"></script>\n`;
}

function insertPixelGuardIntoTheme(themeLiquid, shop, workerOrigin) {
  const source = normalizeThemeText(themeLiquid);
  const headMatch = source.match(/<head\b[^>]*>/i);
  if (!headMatch || headMatch.index == null) {
    throw new HttpError("layout/theme.liquid does not contain an opening <head> tag", 422);
  }

  const markerPattern = new RegExp(`\\s*<!--\\s*${PIXEL_GUARD_MARKER.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\\s*-->\\s*<script\\b[^>]*\\bsrc=["'][^"']*/cs-pixel-guard\\.js[^"']*["'][^>]*>\\s*</script>\\s*`, "gi");
  const loosePattern = /\s*<script\b[^>]*\bsrc=["'][^"']*\/cs-pixel-guard\.js[^"']*["'][^>]*>\s*<\/script>\s*/gi;
  const cleaned = source.replace(markerPattern, "\n").replace(loosePattern, "\n");
  const nextHeadMatch = cleaned.match(/<head\b[^>]*>/i);
  const insertAt = nextHeadMatch.index + nextHeadMatch[0].length;
  const snippet = buildPixelGuardThemeSnippet(shop, workerOrigin);
  const updated = `${cleaned.slice(0, insertAt)}\n${snippet}${cleaned.slice(insertAt).replace(/^\s*/, "")}`;

  return {
    content: updated,
    changed: updated !== source,
  };
}

async function installPixelGuardInTheme(env, shop, workerOrigin) {
  const grantedScopes = await fetchGrantedShopifyScopes(env, shop);
  const missingScopes = SHOPIFY_THEME_INSTALL_REQUIRED_SCOPES.filter((scope) => !grantedScopes.includes(scope));
  if (missingScopes.length > 0) {
    throw new HttpError(`Missing Shopify scope(s): ${missingScopes.join(", ")}`, 403);
  }

  const mainTheme = await fetchMainTheme(env, shop);
  if (!mainTheme?.id) {
    throw new HttpError("No main Shopify theme found", 404);
  }

  const filename = "layout/theme.liquid";
  const themeLiquid = await fetchThemeTextFile(env, shop, mainTheme.id, filename);
  if (!themeLiquid) {
    throw new HttpError("layout/theme.liquid could not be read", 422);
  }

  const currentHeadMatch = themeLiquid.match(/<head\b[^>]*>/i);
  const currentAfterHead = currentHeadMatch?.index == null
    ? ""
    : themeLiquid.slice(currentHeadMatch.index + currentHeadMatch[0].length).trimStart();
  const desiredSnippet = buildPixelGuardThemeSnippet(shop, workerOrigin).trim();
  const alreadyInstalledAtHead = currentAfterHead.startsWith(desiredSnippet);

  if (alreadyInstalledAtHead) {
    return {
      ok: true,
      installed: false,
      alreadyInstalled: true,
      message: "Pixel guard is already first in layout/theme.liquid <head>.",
      theme: { id: mainTheme.id, name: mainTheme.name, role: mainTheme.role },
      filename,
    };
  }

  const nextTheme = insertPixelGuardIntoTheme(themeLiquid, shop, workerOrigin);
  await upsertThemeTextFile(env, shop, mainTheme.id, filename, nextTheme.content);

  return {
    ok: true,
    installed: true,
    alreadyInstalled: false,
    message: "Pixel guard installed at the beginning of layout/theme.liquid <head>.",
    theme: { id: mainTheme.id, name: mainTheme.name, role: mainTheme.role },
    filename,
  };
}

async function buildStoreAudit(env, shop) {
  const settings = await getAdminSettings(env, shop);
  const accessToken = getShopifyAccessToken(env, shop);
  if (!accessToken) {
    return {
      connected: false,
      status: "disconnected",
      settings,
      findings: [],
      upgradeCandidates: [],
      summary: {
        legacyScriptTags: 0,
        externalScriptHosts: 0,
        duplicatePixels: 0,
        riskyPatterns: 0,
        embedDetected: false,
      },
      missingScopes: SHOPIFY_AUDIT_REQUIRED_SCOPES,
      guidance: "Add a Worker-side Shopify Admin access token for this shop to enable conservative app health and Conversion MRI scans.",
    };
  }

  try {
    const accessScopesResponse = await shopifyAdminRestGet(env, shop, "/oauth/access_scopes.json");
    const grantedScopes = (accessScopesResponse?.access_scopes || []).map((scope) => scope.handle);
    const missingScopes = SHOPIFY_AUDIT_REQUIRED_SCOPES.filter((scope) => !grantedScopes.includes(scope));
    if (missingScopes.length > 0) {
      return {
        connected: true,
        status: "limited",
        settings,
        findings: [],
        upgradeCandidates: [],
        summary: {
          legacyScriptTags: 0,
          externalScriptHosts: 0,
          duplicatePixels: 0,
          riskyPatterns: 0,
          embedDetected: false,
        },
        grantedScopes,
        missingScopes,
        guidance: `Grant ${missingScopes.join(", ")} to unlock theme and script-tag audits.`,
      };
    }

    const themesData = await shopifyAdminGraphql(
      env,
      shop,
      `query CommerceShieldThemes {
        themes(first: 10) {
          nodes {
            id
            name
            role
            updatedAt
          }
        }
      }`,
    );

    const themeNodes = themesData?.themes?.nodes || [];
    const mainTheme = themeNodes.find((theme) => theme.role === "MAIN") || themeNodes[0] || null;

    const scriptTagsData = await shopifyAdminGraphql(
      env,
      shop,
      `query CommerceShieldScriptTags {
        scriptTags(first: 50) {
          nodes {
            id
            src
            displayScope
            createdAt
            updatedAt
          }
        }
      }`,
    );

    const scriptTags = scriptTagsData?.scriptTags?.nodes || [];
    let themeLiquid = "";
    let settingsData = "";

    if (mainTheme?.id) {
      const themeData = await shopifyAdminGraphql(
        env,
        shop,
        `query CommerceShieldThemeFiles($themeId: ID!, $filenames: [String!]!) {
          theme(id: $themeId) {
            id
            name
            role
            files(filenames: $filenames) {
              nodes {
                filename
                body {
                  ... on OnlineStoreThemeFileBodyText {
                    content
                  }
                }
              }
              userErrors {
                code
                filename
              }
            }
          }
        }`,
        {
          themeId: mainTheme.id,
          filenames: ["layout/theme.liquid", "config/settings_data.json"],
        },
      );

      for (const file of themeData?.theme?.files?.nodes || []) {
        const content = normalizeThemeText(file?.body?.content);
        if (file.filename === "layout/theme.liquid") themeLiquid = content;
        if (file.filename === "config/settings_data.json") settingsData = content;
      }
    }

    const externalHosts = extractAbsoluteHosts(themeLiquid);
    const uniqueHosts = Array.from(new Set(externalHosts));
    const inlineScriptCount = countInlineScripts(themeLiquid);
    const duplicatePixels = detectDuplicatePixelLibraries(themeLiquid, scriptTags);
    const riskyPatternCount =
      countOccurrences(themeLiquid, /\bdocument\.write\s*\(/gi) +
      countOccurrences(themeLiquid, /\beval\s*\(/gi) +
      countOccurrences(themeLiquid, /\bnew Function\s*\(/gi);
    const contentForHeaderCount = countOccurrences(themeLiquid, /\{\{\s*content_for_header\s*\}\}/gi);
    const hasPageTitle = /\{\{\s*page_title\s*\}\}/i.test(themeLiquid) || /<title\b/i.test(themeLiquid);
    const hasCanonical = /\{\{\s*canonical_url\s*\}\}/i.test(themeLiquid);
    const hasHtmlLang = /<html[^>]*\slang=/i.test(themeLiquid);
    const commerceShieldEmbedDetected = /commerce-shield/i.test(settingsData);

    const findings = [];
    if (settings.appHealth.detectLegacyScriptTags && scriptTags.length > 0) {
      findings.push(
        buildAuditFinding(
          "medium",
          "apps",
          "Legacy ScriptTag injections detected",
          "Shopify ScriptTag API",
          `${scriptTags.length} script tag injection(s) are still active. Shopify recommends theme app extensions instead of ScriptTags for theme integrations.`,
          "Audit each listed source and migrate any theme-facing app to app blocks or app embeds before adding more storefront scripts.",
          Math.min(1.6, 0.35 * scriptTags.length),
        ),
      );
    }

    if (settings.appHealth.detectDuplicatePixels && duplicatePixels.length > 0) {
      findings.push(
        buildAuditFinding(
          "medium",
          "apps",
          "Duplicate tracking libraries found",
          "layout/theme.liquid and injected scripts",
          `Repeated tracking libraries were detected for ${duplicatePixels.map((entry) => entry.key).join(", ")}.`,
          "Remove duplicate pixel loaders so each analytics vendor initializes once per page.",
          Math.min(1.4, 0.4 * duplicatePixels.length),
        ),
      );
    }

    if (settings.appHealth.reviewInlineScripts && riskyPatternCount > 0) {
      findings.push(
        buildAuditFinding(
          "high",
          "apps",
          "Risky inline JavaScript pattern detected",
          "layout/theme.liquid",
          "The live theme contains direct inline patterns such as document.write, eval, or new Function. These patterns are high-risk for conflicts and hard-to-debug failures.",
          "Vendor-review the inline script immediately and replace it with a static or deferred integration path.",
          2.3,
        ),
      );
    }

    if (contentForHeaderCount !== 1) {
      findings.push(
        buildAuditFinding(
          "high",
          "theme",
          "Theme header injection point is not in a safe state",
          "layout/theme.liquid",
          `Expected exactly one {{ content_for_header }} reference, but found ${contentForHeaderCount}. This can break app embeds and storefront integrations.`,
          "Restore a single {{ content_for_header }} token in the head of the main theme layout.",
          2.8,
        ),
      );
    }

    if (uniqueHosts.length >= 8) {
      findings.push(
        buildAuditFinding(
          settings.appHealth.conservativeFlagging ? "low" : "medium",
          "speed",
          "High third-party script density on the storefront",
          "layout/theme.liquid",
          `${uniqueHosts.length} external script host(s) are loaded directly in the main theme layout.`,
          "Consolidate non-critical storefront vendors, defer late-loading scripts, and move legacy app code to app embeds where possible.",
          Math.min(1.5, uniqueHosts.length * 0.12),
        ),
      );
    }

    if (settings.appHealth.requireThemeAppExtensions && !commerceShieldEmbedDetected) {
      findings.push(
        buildAuditFinding(
          "low",
          "theme",
          "Commerce Shield embed was not confirmed in theme settings",
          "config/settings_data.json",
          "The theme settings payload does not clearly reference Commerce Shield. The app embed may be disabled on the live theme.",
          "Open Theme customizer > App embeds and confirm Commerce Shield is enabled on the main theme.",
          0.6,
        ),
      );
    }

    const upgradeCandidates = scriptTags.map((tag) => ({
      src: tag.src,
      displayScope: tag.displayScope,
      updatedAt: tag.updatedAt,
    }));

    return {
      connected: true,
      status: deriveAppHealthStatus(findings),
      settings,
      grantedScopes,
      missingScopes,
      mainTheme: mainTheme ? { name: mainTheme.name, role: mainTheme.role, updatedAt: mainTheme.updatedAt } : null,
      summary: {
        legacyScriptTags: scriptTags.length,
        externalScriptHosts: uniqueHosts.length,
        duplicatePixels: duplicatePixels.length,
        riskyPatterns: riskyPatternCount,
        inlineScripts: inlineScriptCount,
        embedDetected: commerceShieldEmbedDetected,
      },
      signals: {
        hasPageTitle,
        hasCanonical,
        hasHtmlLang,
        externalScriptHosts: uniqueHosts,
        inlineScriptCount,
      },
      findings,
      upgradeCandidates,
    };
  } catch (error) {
    return {
      connected: true,
      status: "limited",
      settings,
      findings: [],
      upgradeCandidates: [],
      summary: {
        legacyScriptTags: 0,
        externalScriptHosts: 0,
        duplicatePixels: 0,
        riskyPatterns: 0,
        embedDetected: false,
      },
      missingScopes: [],
      guidance: `Audit scan could not complete cleanly: ${error.message || error}`,
    };
  }
}

async function handleAdminStoreAudit(url, env, corsHeaders) {
  const shop = getRequiredShop(url);
  return jsonResponse(await buildStoreAudit(env, shop), 200, corsHeaders);
}

async function fetchIntentFunnel(env, shop) {
  const funnelRows = await env.DB.prepare(
    `SELECT event_type, COUNT(DISTINCT visitor_key) as visitors
     FROM intent_events
     WHERE shop = ?
       AND event_type IN ('product_view', 'add_to_cart', 'checkout_start', 'purchase')
       AND created_at >= datetime('now', '-30 days')
     GROUP BY event_type`
  ).bind(shop).all();

  const counts = { product_view: 0, add_to_cart: 0, checkout_start: 0, purchase: 0 };
  for (const row of funnelRows.results || []) {
    counts[row.event_type] = Number(row.visitors) || 0;
  }
  return counts;
}

function ratio(numerator, denominator) {
  if (!denominator) return 0;
  return numerator / denominator;
}

async function handleAdminConversionMri(url, env, corsHeaders) {
  const shop = getRequiredShop(url);
  const settings = await getAdminSettings(env, shop);
  const funnel = await fetchIntentFunnel(env, shop);
  const audit = await buildStoreAudit(env, shop);
  const diagnostics = [];

  if (settings.conversionMri.runAppChecks) {
    diagnostics.push(
      ...audit.findings.map((finding) => ({
        category: finding.category,
        title: finding.title,
        location: finding.location,
        fix: finding.fix,
        missedConversionPct: finding.missedConversionPct,
        severity: finding.severity,
      })),
    );
  }

  const addToCartRate = ratio(funnel.add_to_cart, funnel.product_view);
  const checkoutRate = ratio(funnel.checkout_start, funnel.add_to_cart);
  const purchaseRate = ratio(funnel.purchase, funnel.checkout_start);

  if (funnel.product_view >= 80 && addToCartRate > 0 && addToCartRate < 0.018) {
    diagnostics.push({
      category: "content",
      title: "Product-page interest is not converting into cart intent",
      location: "Product detail page",
      fix: "Audit merchandising clarity above the fold, variant defaults, and purchase friction on high-traffic PDPs before changing pricing or discount strategy.",
      missedConversionPct: 1.2,
      severity: "medium",
    });
  }

  if (funnel.add_to_cart >= 25 && checkoutRate > 0 && checkoutRate < 0.33) {
    diagnostics.push({
      category: "checkout",
      title: "Cart-to-checkout handoff looks soft",
      location: "Cart and mini-cart flows",
      fix: "Review cart drawer blockers, shipping threshold messaging, and app scripts that re-render the cart before checkout begins.",
      missedConversionPct: 1.6,
      severity: "medium",
    });
  }

  if (funnel.checkout_start >= 12 && purchaseRate > 0 && purchaseRate < 0.28) {
    diagnostics.push({
      category: "checkout",
      title: "Checkout completion is underperforming",
      location: "Checkout and post-cart apps",
      fix: "Audit validation rules, accelerated-checkout conflicts, and any app injecting checkout-adjacent scripts or redirects.",
      missedConversionPct: 1.9,
      severity: "high",
    });
  }

  if (settings.conversionMri.runSeoChecks && audit.connected && audit.status !== "disconnected") {
    if (!audit.signals.hasPageTitle) {
      diagnostics.push({
        category: "seo",
        title: "Theme layout does not clearly expose the page title",
        location: "layout/theme.liquid",
        fix: "Restore a clear <title> or {{ page_title }} output in the main layout before changing any content templates.",
        missedConversionPct: 0.7,
        severity: "medium",
      });
    }
    if (!audit.signals.hasCanonical) {
      diagnostics.push({
        category: "seo",
        title: "Canonical URL output is missing",
        location: "layout/theme.liquid",
        fix: "Add {{ canonical_url }} to the head so search engines do not split ranking signals across duplicate URLs.",
        missedConversionPct: 0.5,
        severity: "low",
      });
    }
  }

  if (settings.conversionMri.runAdaChecks && audit.connected && audit.status !== "disconnected" && !audit.signals.hasHtmlLang) {
    diagnostics.push({
      category: "ada",
      title: "Primary HTML language attribute is missing",
      location: "layout/theme.liquid",
      fix: "Set a valid lang attribute on the root html tag so screen readers and accessibility tooling can interpret the page correctly.",
      missedConversionPct: 0.4,
      severity: "low",
    });
  }

  const sortedDiagnostics = diagnostics
    .sort((a, b) => Number(b.missedConversionPct) - Number(a.missedConversionPct))
    .slice(0, settings.conversionMri.conservativeMode ? 8 : 12);

  const totalMissedConversionPct = sortedDiagnostics
    .reduce((sum, finding) => sum + Number(finding.missedConversionPct || 0), 0)
    .toFixed(1);

  return jsonResponse({
    settings,
    funnel,
    auditStatus: audit.status,
    diagnostics: sortedDiagnostics,
    totalMissedConversionPct: Number(totalMissedConversionPct),
  }, 200, corsHeaders);
}

function normalizeIntentEventPayload(body) {
  const shop = normalizeShopDomain(body.shop);
  const eventType = sanitizeString(body.eventType, 60);
  const visitorKey = sanitizeString(body.visitorKey, 120);
  const sessionId = sanitizeString(body.sessionId, 120);
  const page = sanitizeString(body.page, 500);
  const pageType = sanitizeString(body.pageType, 60);
  const productId = sanitizeString(body.productId, 120);
  const customerId = normalizeCustomerId(body.customerId);
  const emailHash = sanitizeEmailHash(body.emailHash);
  const metadata = typeof body.metadata === "object" && body.metadata ? body.metadata : {};
  const createdAt = new Date().toISOString();
  const botContext = {
    isBot: Boolean(body.botContext?.isBot),
    isLegitimate: Boolean(body.botContext?.isLegitimate),
    botScore: Number(body.botContext?.botScore) || 0,
    confidence: sanitizeString(body.botContext?.confidence || "low", 20).toLowerCase() || "low",
  };

  if (!shop) throw new HttpError("Missing shop", 400);
  if (!visitorKey) throw new HttpError("Missing visitorKey", 400);
  if (!ALLOWED_INTENT_EVENTS.has(eventType)) throw new HttpError("Unsupported event type", 400);

  const sanitizedMetadata = {
    durationMs: Number(metadata.durationMs) || 0,
    pageViewCount: Number(metadata.pageViewCount) || 0,
    commerceSignalCount: Number(metadata.commerceSignalCount) || 0,
    queryLength: Number(metadata.queryLength) || 0,
  };

  return {
    shop,
    visitorKey,
    sessionId,
    eventType,
    page,
    pageType,
    productId,
    customerId,
    emailHash,
    metadata: sanitizedMetadata,
    botContext,
    createdAt,
  };
}

async function applyRateLimit(env, scope, key, limit, windowSeconds) {
  const bucket = Math.floor(Date.now() / (windowSeconds * 1000));
  const bucketKey = `${scope}:${key}:${bucket}`;
  const expiresAt = new Date((bucket + 1) * windowSeconds * 1000).toISOString();

  // Single round-trip: upsert and return the new count in one query.
  // Halves D1 operations per rate-limit check on every request.
  const row = await env.DB.prepare(
    `INSERT INTO rate_limits (bucket_key, count, expires_at)
     VALUES (?, 1, ?)
     ON CONFLICT(bucket_key) DO UPDATE SET count = count + 1
     RETURNING count`
  ).bind(bucketKey, expiresAt).first();

  if ((row?.count || 0) > limit) {
    throw new HttpError("Rate limit exceeded", 429);
  }
}

async function registerNonce(env, endpoint, nonce, timestamp) {
  const expiresAt = new Date((timestamp + NONCE_WINDOW_SECONDS * 1000)).toISOString();
  const nonceKey = `${endpoint}:${nonce}`;
  const result = await env.DB.prepare(
    `INSERT INTO endpoint_nonces (nonce_key, endpoint, expires_at)
     VALUES (?, ?, ?)
     ON CONFLICT(nonce_key) DO NOTHING`
  ).bind(nonceKey, endpoint, expiresAt).run();

  if (!result.meta || result.meta.changes === 0) {
    throw new HttpError("Replay detected", 409);
  }
}

async function pruneSecurityTables(env, ctx) {
  // Probabilistic cleanup — runs on ~1% of requests instead of every write.
  // Both tables are tiny and self-expiring, so frequent pruning adds no value.
  // waitUntil lets the cleanup happen after the response is sent.
  if (Math.random() >= 0.01) return;

  const cleanup = env.DB.batch([
    env.DB.prepare(`DELETE FROM endpoint_nonces WHERE expires_at < datetime('now')`),
    env.DB.prepare(`DELETE FROM rate_limits WHERE expires_at < datetime('now')`),
  ]);

  if (ctx && typeof ctx.waitUntil === "function") {
    ctx.waitUntil(cleanup);
  } else {
    await cleanup;
  }
}

async function verifySignedRequest(request, env, rawText, endpoint) {
  const secret = env.BLOOMREACH_SHARED_SECRET;
  if (!secret) throw new HttpError("Bloomreach secret is not configured", 503);

  const timestampHeader = request.headers.get("x-cs-timestamp");
  const nonce = sanitizeString(request.headers.get("x-cs-nonce"), 120);
  const signature = sanitizeString(request.headers.get("x-cs-signature"), 128).toLowerCase();

  if (!timestampHeader || !nonce || !signature) {
    throw new HttpError("Missing signature headers", 401);
  }

  const timestamp = Number(timestampHeader);
  if (!Number.isFinite(timestamp)) throw new HttpError("Invalid timestamp", 401);

  const now = Date.now();
  if (Math.abs(now - timestamp) > NONCE_WINDOW_SECONDS * 1000) {
    throw new HttpError("Expired request", 401);
  }

  const expected = await createHmacSignature(secret, timestampHeader, nonce, rawText);
  if (!timingSafeEqualHex(expected, signature.replace(/^sha256=/, ""))) {
    throw new HttpError("Invalid signature", 401);
  }

  await registerNonce(env, endpoint, nonce, timestamp);
}

async function fetchIntentEvents(env, shop, visitorKey) {
  const result = await env.DB.prepare(
    `SELECT visitor_key, session_id, event_type, page_type, page, product_id, customer_id, email_hash, metadata, created_at
     FROM intent_events
     WHERE shop = ? AND visitor_key = ? AND created_at >= datetime('now', '-30 days')
     ORDER BY created_at ASC`
  ).bind(shop, visitorKey).all();

  return (result.results || []).map((row) => ({
    visitorKey: row.visitor_key,
    sessionId: row.session_id,
    eventType: row.event_type,
    pageType: row.page_type,
    page: row.page,
    productId: row.product_id,
    customerId: row.customer_id,
    emailHash: row.email_hash,
    metadata: safeJsonParse(row.metadata, {}),
    createdAt: row.created_at,
  }));
}

async function fetchIntentProfile(env, shop, visitorKey) {
  return env.DB.prepare(
    `SELECT visitor_key, customer_id, intent_score, intent_tier, intent_confidence, bot_excluded, bot_confidence, bot_score, updated_at
     FROM intent_profiles
     WHERE shop = ? AND visitor_key = ?
     LIMIT 1`
  ).bind(shop, visitorKey).first();
}

function safeJsonParse(value, fallback) {
  if (!value) return fallback;
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}

async function upsertIntentProfile(env, payload, scoredProfile) {
  await env.DB.prepare(
    `INSERT INTO intent_profiles (
      shop, visitor_key, customer_id, email_hash, intent_score, intent_tier, intent_confidence,
      bot_excluded, bot_confidence, bot_score, session_count, signal_summary,
      first_seen_at, last_seen_at, purchased_at, updated_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(shop, visitor_key) DO UPDATE SET
      customer_id = COALESCE(excluded.customer_id, intent_profiles.customer_id),
      email_hash = COALESCE(excluded.email_hash, intent_profiles.email_hash),
      intent_score = excluded.intent_score,
      intent_tier = excluded.intent_tier,
      intent_confidence = excluded.intent_confidence,
      bot_excluded = excluded.bot_excluded,
      bot_confidence = excluded.bot_confidence,
      bot_score = excluded.bot_score,
      session_count = excluded.session_count,
      signal_summary = excluded.signal_summary,
      last_seen_at = excluded.last_seen_at,
      purchased_at = COALESCE(excluded.purchased_at, intent_profiles.purchased_at),
      updated_at = datetime('now')`
  ).bind(
    payload.shop,
    payload.visitorKey,
    payload.customerId || null,
    payload.emailHash || null,
    scoredProfile.intentScore,
    scoredProfile.intentTier,
    scoredProfile.intentConfidence,
    scoredProfile.botContext.excluded ? 1 : 0,
    scoredProfile.botContext.confidence,
    scoredProfile.botContext.botScore,
    scoredProfile.sessionCount,
    JSON.stringify(scoredProfile.intentSignals),
    scoredProfile.firstSeenAt || payload.createdAt,
    scoredProfile.lastSeenAt || payload.createdAt,
    scoredProfile.purchasedAt || null,
  ).run();
}

function shouldSyncCustomerProfile(previousProfile, scoredProfile, payload) {
  if (!payload.customerId) return false;
  if (scoredProfile.botContext.excluded) return false;

  const previousScore = Number(previousProfile?.intent_score) || 0;
  const previousTier = previousProfile?.intent_tier || "";
  const materialScoreChange = Math.abs(scoredProfile.intentScore - previousScore) >= 10;
  const tierChanged = previousTier !== scoredProfile.intentTier;
  const importantEvent = payload.eventType === "login" || payload.eventType === "email_capture" || payload.eventType === "purchase";

  return !previousProfile || materialScoreChange || tierChanged || importantEvent;
}

async function syncIntentProfileToShopify(env, payload, scoredProfile, requestOrigin) {
  let lastError = null;

  try {
    const syncedViaApp = await syncIntentProfileToShopifyApp(env, payload, scoredProfile, requestOrigin);
    if (syncedViaApp) return;
  } catch (error) {
    lastError = error;
  }

  try {
    const syncedDirectly = await syncIntentProfileToShopifyAdmin(env, payload, scoredProfile);
    if (syncedDirectly) return;
  } catch (error) {
    lastError = lastError
      ? new Error(`${lastError.message}; direct-sync fallback failed: ${error.message || error}`)
      : error;
  }

  if (lastError) throw lastError;
}

async function syncIntentProfileToShopifyApp(env, payload, scoredProfile, requestOrigin) {
  const configuredEndpoint = sanitizeString(env.SHOPIFY_INTENT_SYNC_URL, 500);
  const appBaseUrl = sanitizeString(env.SHOPIFY_APP_URL, 500);
  const secret = env.INTERNAL_SYNC_SHARED_SECRET;
  if (!secret) return false;
  const endpoint = configuredEndpoint || (appBaseUrl ? `${appBaseUrl.replace(/\/$/, "")}/api/intent/sync-customer` : "") || (requestOrigin ? `${requestOrigin.replace(/\/$/, "")}/api/intent/sync-customer` : "");
  if (!endpoint) return false;

  const syncPayload = buildIntentSyncPayload(payload, scoredProfile);

  const bodyText = JSON.stringify(syncPayload);
  const timestamp = String(Date.now());
  const nonce = crypto.randomUUID();
  const signature = await createHmacSignature(secret, timestamp, nonce, bodyText);

  const response = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CS-Timestamp": timestamp,
      "X-CS-Nonce": nonce,
      "X-CS-Signature": signature,
    },
    body: bodyText,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Shopify intent sync failed: ${response.status} ${errorText}`);
  }

  return true;
}

async function syncIntentProfileToShopifyAdmin(env, payload, scoredProfile) {
  const tokenMap = parseShopifyAdminTokenMap(env);
  const accessToken = tokenMap[payload.shop];
  const ownerId = normalizeCustomerId(payload.customerId);
  if (!accessToken || !ownerId) return false;

  const apiVersion = normalizeAdminApiVersion(env.SHOPIFY_ADMIN_API_VERSION);
  const syncPayload = buildIntentSyncPayload(payload, scoredProfile);
  const metafields = [
    {
      ownerId,
      namespace: SHOPIFY_INTENT_NAMESPACE,
      key: "intent_score",
      type: "number_integer",
      value: String(syncPayload.intentScore),
    },
    {
      ownerId,
      namespace: SHOPIFY_INTENT_NAMESPACE,
      key: "intent_tier",
      type: "single_line_text_field",
      value: syncPayload.intentTier,
    },
    {
      ownerId,
      namespace: SHOPIFY_INTENT_NAMESPACE,
      key: "intent_updated_at",
      type: "date_time",
      value: syncPayload.intentUpdatedAt,
    },
    {
      ownerId,
      namespace: SHOPIFY_INTENT_NAMESPACE,
      key: "intent_model_version",
      type: "single_line_text_field",
      value: syncPayload.intentModelVersion,
    },
  ];

  const response = await fetch(`https://${payload.shop}/admin/api/${apiVersion}/graphql.json`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Shopify-Access-Token": accessToken,
    },
    body: JSON.stringify({
      query: `mutation MetafieldsSet($metafields: [MetafieldsSetInput!]!) {
        metafieldsSet(metafields: $metafields) {
          metafields {
            namespace
            key
            value
            updatedAt
          }
          userErrors {
            field
            message
            code
          }
        }
      }`,
      variables: { metafields },
    }),
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`Shopify direct intent sync failed: ${response.status} ${errorText}`);
  }

  const result = await response.json();
  const userErrors = result?.data?.metafieldsSet?.userErrors || [];
  if (userErrors.length > 0) {
    const formattedErrors = userErrors.map((error) => error.message).join("; ");
    throw new Error(`Shopify direct intent sync rejected metafields: ${formattedErrors}`);
  }

  return true;
}

function applyCloudflareRiskSignals(request, baseScore, baseIsBot, baseConfidence) {
  const cf = request && request.cf ? request.cf : {};
  let score = Number(baseScore) || 0;
  let isBot = baseIsBot === true;
  let confidence = baseConfidence === "high" ? "high" : "low";
  const reasons = [];

  // Free-plan signal available on all Cloudflare plans.
  const threatScore = Number(cf.threatScore) || 0;
  if (threatScore > 30) {
    score = Math.max(score, 0.9);
    isBot = true;
    confidence = "high";
    reasons.push(`cf_threat_${threatScore}`);
  } else if (threatScore > 10) {
    score = Math.max(score, Math.min(1, score + 0.25));
    reasons.push(`cf_threat_${threatScore}`);
  }

  // Enterprise Bot Management signal (safe no-op when absent).
  const bm = cf && typeof cf.botManagement === "object" ? cf.botManagement : null;
  if (bm) {
    const bmScore = Number(bm.score);
    if (Number.isFinite(bmScore)) {
      if (bmScore <= 10) {
        score = Math.max(score, 0.95);
        isBot = true;
        confidence = "high";
        reasons.push(`cf_bm_score_${bmScore}`);
      } else if (bmScore <= 30) {
        score = Math.max(score, Math.min(1, score + 0.4));
        reasons.push(`cf_bm_score_${bmScore}`);
      }
    }
    if (bm.verifiedBot === true) reasons.push("cf_verified_bot");
    if (typeof bm.ja3Hash === "string" && KNOWN_BAD_JA3.has(bm.ja3Hash)) {
      score = Math.max(score, 0.95);
      isBot = true;
      confidence = "high";
      reasons.push("cf_bad_ja3");
    }
    if (typeof bm.ja4 === "string" && bm.ja4.length > 0) {
      reasons.push("cf_ja4_present");
    }
  }

  // Datacenter reputation by ASN and ASN organization.
  const asn = Number(cf.asn) || 0;
  if (asn && DATACENTER_ASNS.has(asn)) {
    score = Math.max(score, Math.min(1, score + 0.45));
    reasons.push(`datacenter_asn_${asn}`);
  }

  const asOrg = sanitizeString(cf.asOrganization, 140).toLowerCase();
  if (asOrg && DATACENTER_ORG_HINTS.some((hint) => asOrg.includes(hint))) {
    score = Math.max(score, Math.min(1, score + 0.25));
    reasons.push("datacenter_as_org");
  }

  if (score >= 0.9) {
    isBot = true;
    confidence = "high";
  }

  return {
    score: Number(Math.min(1, score).toFixed(2)),
    isBot,
    confidence,
    reasons,
    cfThreatScore: threatScore,
    cfAsn: asn || null,
    cfAsOrganization: asOrg || null,
  };
}

async function handleStats(request, env, corsHeaders, ctx) {
  const { body } = await parseJsonRequest(request);
  const { shop, isBot, botScore, confidence, isMobile, isLegitimate, isCouponBot, source, page, ua } = body;
  if (!shop) throw new HttpError("Missing shop", 400);
  const normalizedShop = normalizeShopDomain(shop);
  if (!normalizedShop) throw new HttpError("Invalid shop", 400);

  const today = new Date().toISOString().split("T")[0];

  // Cloudflare-native edge enrichment (threat score, botManagement, ASN/org hints, JA3/JA4).
  const cfRisk = applyCloudflareRiskSignals(request, botScore, isBot, confidence);
  const finalIsBot = cfRisk.isBot;
  const finalBotScore = cfRisk.score;
  const finalConfidence = cfRisk.confidence;
  const pixelProtected = finalIsBot && finalConfidence === "high" && !isLegitimate ? 1 : 0;

  const envSampleRate = Number(env.HUMAN_VISIT_SAMPLE_RATE);
  const humanVisitSampleRate = Number.isFinite(envSampleRate)
    ? Math.min(1, Math.max(0, envSampleRate))
    : DEFAULT_HUMAN_VISIT_SAMPLE_RATE;
  const envSuspiciousThreshold = Number(env.SUSPICIOUS_VISIT_THRESHOLD);
  const suspiciousThreshold = Number.isFinite(envSuspiciousThreshold)
    ? Math.min(1, Math.max(0, envSuspiciousThreshold))
    : DEFAULT_SUSPICIOUS_VISIT_THRESHOLD;

  // Free-plan D1 optimization: keep detailed visit rows for bots/suspicious traffic,
  // sample low-risk humans, while keeping daily totals exact.
  const shouldPersistVisitRow =
    finalIsBot ||
    isCouponBot === true ||
    isLegitimate === true ||
    finalBotScore >= suspiciousThreshold ||
    Math.random() < humanVisitSampleRate;

  // Batch writes into one round-trip. `daily_stats` is always exact.
  const statements = [
    env.DB.prepare(
      `INSERT INTO daily_stats (shop, date, total_visits, human_visits, bot_visits, coupon_bots, pixels_protected)
       VALUES (?, ?, 1, ?, ?, ?, ?)
       ON CONFLICT(shop, date) DO UPDATE SET
         total_visits = total_visits + 1,
         human_visits = human_visits + ?,
         bot_visits = bot_visits + ?,
         coupon_bots = coupon_bots + ?,
         pixels_protected = pixels_protected + ?`
    ).bind(
      normalizedShop,
      today,
      finalIsBot ? 0 : 1,
      finalIsBot ? 1 : 0,
      isCouponBot ? 1 : 0,
      pixelProtected,
      finalIsBot ? 0 : 1,
      finalIsBot ? 1 : 0,
      isCouponBot ? 1 : 0,
      pixelProtected,
    ),
  ];

  if (shouldPersistVisitRow) {
    statements.push(
      env.DB.prepare(
        `INSERT INTO visits (shop, is_bot, bot_score, confidence, is_mobile, is_legitimate, is_coupon_bot, source, page, ua)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(
        normalizedShop,
        finalIsBot ? 1 : 0,
        Number(finalBotScore) || 0,
        sanitizeString(finalConfidence, 20) || "low",
        isMobile ? 1 : 0,
        isLegitimate ? 1 : 0,
        isCouponBot ? 1 : 0,
        sanitizeString(source, 80) || "direct",
        sanitizeString(page, 500),
        sanitizeString(ua, 200),
      )
    );
  }

  await env.DB.batch(statements);

  // Probabilistic cleanup — runs on ~0.5% of requests instead of every write.
  // At 500k writes/day this still prunes ~2,500 times per day, far more than needed.
  // Uses waitUntil so the cleanup doesn't block the response to the client.
  if (Math.random() < 0.005) {
    const cleanup = env.DB.prepare(
      `DELETE FROM visits WHERE shop = ? AND created_at < datetime('now', '-30 days')`
    ).bind(normalizedShop).run();
    if (ctx && typeof ctx.waitUntil === "function") {
      ctx.waitUntil(cleanup);
    } else {
      await cleanup;
    }
  }

  return jsonResponse({ ok: true }, 200, corsHeaders);
}

async function handlePixelGuardEvent(request, env, corsHeaders, ctx) {
  pruneSecurityTables(env, ctx);
  const { body } = await parseJsonRequest(request, 8 * 1024);
  const shop = normalizeShopDomain(body.shop);
  if (!shop) throw new HttpError("Missing shop", 400);

  const ip = extractIp(request);
  await applyRateLimit(env, "pixel_guard", `${shop}:${ip}`, PIXEL_GUARD_EVENT_LIMIT, 60);

  const confidence = sanitizeString(body.confidence, 20).toLowerCase();
  const isBot = body.isBot === true;
  const pixelCount = clampNumber(body.count, 1, 1, 50);

  if (!isBot || confidence !== "high") {
    return jsonResponse({ ok: true, accepted: false }, 200, corsHeaders);
  }

  const today = new Date().toISOString().split("T")[0];
  await env.DB.prepare(
    `INSERT INTO daily_stats (shop, date, total_visits, human_visits, bot_visits, coupon_bots, pixels_protected)
     VALUES (?, ?, 0, 0, 0, 0, ?)
     ON CONFLICT(shop, date) DO UPDATE SET
       pixels_protected = pixels_protected + ?`
  ).bind(shop, today, pixelCount, pixelCount).run();

  return jsonResponse({ ok: true, accepted: true, pixelsProtected: pixelCount }, 200, corsHeaders);
}

async function handleIntentEvent(request, env, corsHeaders, ctx) {
  // Fire-and-forget probabilistic cleanup (no await — doesn't block the hot path).
  pruneSecurityTables(env, ctx);
  const { body } = await parseJsonRequest(request);
  const payload = normalizeIntentEventPayload(body);
  const ip = extractIp(request);
  const previousProfile = await fetchIntentProfile(env, payload.shop, payload.visitorKey);

  await applyRateLimit(env, "intent_event", `${payload.shop}:${ip}`, INTENT_EVENT_LIMIT, 60);

  await env.DB.prepare(
    `INSERT INTO intent_events (
      shop, visitor_key, session_id, event_type, page_type, page, product_id,
      customer_id, email_hash, bot_score, bot_confidence, is_bot, is_legitimate, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).bind(
    payload.shop,
    payload.visitorKey,
    payload.sessionId || null,
    payload.eventType,
    payload.pageType || null,
    payload.page || null,
    payload.productId || null,
    payload.customerId || null,
    payload.emailHash || null,
    payload.botContext.botScore,
    payload.botContext.confidence,
    payload.botContext.isBot ? 1 : 0,
    payload.botContext.isLegitimate ? 1 : 0,
    JSON.stringify(payload.metadata),
  ).run();

  const events = await fetchIntentEvents(env, payload.shop, payload.visitorKey);
  const scoredProfile = scoreIntentProfile(events, payload.botContext);
  await upsertIntentProfile(env, payload, scoredProfile);

  if (shouldSyncCustomerProfile(previousProfile, scoredProfile, payload) && ctx?.waitUntil) {
    ctx.waitUntil(
      syncIntentProfileToShopify(env, payload, scoredProfile, new URL(request.url).origin).catch((error) => {
        console.error("intent-sync-customer-failed", error?.message || error);
      }),
    );
  }

  await env.DB.prepare(
    `DELETE FROM intent_events WHERE shop = ? AND visitor_key = ? AND created_at < datetime('now', '-45 days')`
  ).bind(payload.shop, payload.visitorKey).run();

  return jsonResponse({
    ok: true,
    visitorKey: payload.visitorKey,
    intentScore: scoredProfile.intentScore,
    intentTier: scoredProfile.intentTier,
    intentConfidence: scoredProfile.intentConfidence,
    intentSignals: scoredProfile.intentSignals,
    botContext: {
      excluded: scoredProfile.botContext.excluded,
      capped: scoredProfile.botContext.capped,
      confidence: scoredProfile.botContext.confidence,
      botScore: scoredProfile.botContext.botScore,
    },
  }, 200, corsHeaders);
}

async function handleBloomreachIntentProfile(request, env, corsHeaders, ctx) {
  // Fire-and-forget probabilistic cleanup (no await — doesn't block the hot path).
  pruneSecurityTables(env, ctx);
  const ip = extractIp(request);
  await applyRateLimit(env, "bloomreach_lookup", ip, BLOOMREACH_LOOKUP_LIMIT, 60);

  const { rawText, body } = await parseJsonRequest(request);
  await verifySignedRequest(request, env, rawText, "bloomreach_intent_profile");

  const shop = normalizeShopDomain(body.shop);
  const visitorKey = sanitizeString(body.visitorKey, 120);
  const customerId = normalizeCustomerId(body.customerId);
  const emailHash = sanitizeEmailHash(body.emailHash);

  if (!shop) throw new HttpError("Missing shop", 400);
  if (!visitorKey && !customerId && !emailHash) {
    throw new HttpError("Provide visitorKey, customerId, or emailHash", 400);
  }

  const query = visitorKey
    ? {
        sql: `SELECT * FROM intent_profiles WHERE shop = ? AND visitor_key = ? LIMIT 1`,
        params: [shop, visitorKey],
      }
    : customerId
      ? {
          sql: `SELECT * FROM intent_profiles WHERE shop = ? AND customer_id = ? ORDER BY updated_at DESC LIMIT 1`,
          params: [shop, customerId],
        }
      : {
          sql: `SELECT * FROM intent_profiles WHERE shop = ? AND email_hash = ? ORDER BY updated_at DESC LIMIT 1`,
          params: [shop, emailHash],
        };

  const profile = await env.DB.prepare(query.sql).bind(...query.params).first();
  if (!profile) {
    return jsonResponse({ found: false, shop }, 200, corsHeaders);
  }

  return jsonResponse({
    found: true,
    shop,
    visitorKey: profile.visitor_key,
    customerId: profile.customer_id || null,
    emailHash: profile.email_hash || null,
    intentScore: profile.intent_score || 0,
    intentTier: profile.intent_tier || "unknown",
    intentConfidence: profile.intent_confidence || "low",
    lastSeenAt: profile.last_seen_at || null,
    firstSeenAt: profile.first_seen_at || null,
    purchasedAt: profile.purchased_at || null,
    signals: safeJsonParse(profile.signal_summary, []),
    botContext: {
      isExcluded: Boolean(profile.bot_excluded),
      confidence: profile.bot_confidence || "low",
      botScore: Number(profile.bot_score) || 0,
    },
  }, 200, corsHeaders);
}

async function handleDashboardData(request, url, env, corsHeaders, ctx) {
  const shop = normalizeShopDomain(url.searchParams.get("shop"));
  const days = Math.min(90, Math.max(1, parseInt(url.searchParams.get("days") || "30", 10) || 30));
  if (!shop) throw new HttpError("Missing or invalid shop param", 400);
  if (shouldBlockNoisyReadRequest(request)) {
    throw new HttpError("Blocked by noisy endpoint filter", 403);
  }

  const ip = extractIp(request);
  await applyRateLimit(env, "dashboard_read", `${shop}:${ip}`, DASHBOARD_READ_LIMIT, 60);

  const cacheKey = buildReadCacheKey("/api/dashboard", shop, { days });
  return respondWithEdgeCache(cacheKey, 45, corsHeaders, ctx, async () => {

  const since = new Date();
  since.setDate(since.getDate() - days);
  const sinceStr = since.toISOString().split("T")[0];

  const stats = await env.DB.prepare(
    `SELECT date, total_visits, human_visits, bot_visits, coupon_bots, pixels_protected, disposable_emails_blocked
     FROM daily_stats WHERE shop = ? AND date >= ? ORDER BY date ASC`
  ).bind(shop, sinceStr).all();

  const totals = await env.DB.prepare(
    `SELECT
       COALESCE(SUM(total_visits), 0) as totalVisits,
       COALESCE(SUM(human_visits), 0) as humanVisits,
       COALESCE(SUM(bot_visits), 0) as botVisits,
       COALESCE(SUM(coupon_bots), 0) as couponBots,
       COALESCE(SUM(pixels_protected), 0) as pixelsProtected,
       COALESCE(SUM(disposable_emails_blocked), 0) as disposableEmailsBlocked
     FROM daily_stats WHERE shop = ? AND date >= ?`
  ).bind(shop, sinceStr).first();

  const sources = await env.DB.prepare(
    `SELECT source, COUNT(*) as count, SUM(is_bot) as bots
     FROM visits WHERE shop = ? AND created_at >= datetime(?)
     GROUP BY source ORDER BY count DESC LIMIT 10`
  ).bind(shop, sinceStr + "T00:00:00").all();

  const botTypes = await env.DB.prepare(
    `SELECT
       SUM(CASE WHEN is_coupon_bot = 1 THEN 1 ELSE 0 END) as couponBots,
       SUM(CASE WHEN is_legitimate = 1 THEN 1 ELSE 0 END) as legitimateBots,
       SUM(CASE WHEN is_bot = 1 AND is_coupon_bot = 0 AND is_legitimate = 0 THEN 1 ELSE 0 END) as badBots,
       SUM(CASE WHEN is_bot = 0 THEN 1 ELSE 0 END) as humans
     FROM visits WHERE shop = ? AND created_at >= datetime(?)`
  ).bind(shop, sinceStr + "T00:00:00").first();

    return jsonResponseWithHeaders({
      dailyStats: stats.results || [],
      totals: totals || {},
      sources: sources.results || [],
      botTypes: botTypes || {},
    }, 200, corsHeaders, {
      "Cache-Control": "public, max-age=0, s-maxage=45, stale-while-revalidate=180",
    });
  });
}

async function handleRecentVisits(request, url, env, corsHeaders, ctx) {
  const shop = normalizeShopDomain(url.searchParams.get("shop"));
  const limit = Math.min(parseInt(url.searchParams.get("limit") || "50", 10), 200);
  if (!shop) throw new HttpError("Missing or invalid shop param", 400);
  if (shouldBlockNoisyReadRequest(request)) {
    throw new HttpError("Blocked by noisy endpoint filter", 403);
  }

  const ip = extractIp(request);
  await applyRateLimit(env, "recent_read", `${shop}:${ip}`, RECENT_READ_LIMIT, 60);

  const botsOnly = url.searchParams.get("bots") !== "0";

  const cacheKey = buildReadCacheKey("/api/recent", shop, { limit, bots: botsOnly ? 1 : 0 });
  return respondWithEdgeCache(cacheKey, 20, corsHeaders, ctx, async () => {
    const recent = await env.DB.prepare(
      botsOnly
        ? `SELECT is_bot, bot_score, confidence, is_mobile, is_legitimate, is_coupon_bot, source, page, ua, created_at
           FROM visits WHERE shop = ? AND is_bot = 1 ORDER BY id DESC LIMIT ?`
        : `SELECT is_bot, bot_score, confidence, is_mobile, is_legitimate, is_coupon_bot, source, page, ua, created_at
           FROM visits WHERE shop = ? ORDER BY id DESC LIMIT ?`
    ).bind(shop, limit).all();

    return jsonResponseWithHeaders({ visits: recent.results || [] }, 200, corsHeaders, {
      "Cache-Control": "public, max-age=0, s-maxage=20, stale-while-revalidate=120",
    });
  });
}

function serveEmbeddedAdmin(url, request, ctx) {
  const shop = url.searchParams.get("shop") || "";
  const cacheKey = new Request(`https://cache.local${url.pathname}?shop=${encodeURIComponent(shop)}`, { method: "GET" });
  return respondWithEdgeCache(cacheKey, 120, OPEN_CORS_HEADERS, ctx, async () => {
    return new Response(buildEmbeddedAdminHTML(shop, url.origin), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Content-Security-Policy": "frame-ancestors https://admin.shopify.com https://*.myshopify.com",
        "Cache-Control": "public, max-age=0, s-maxage=120, stale-while-revalidate=300",
      },
    });
  });
}

function serveDashboard(url, request, ctx) {
  const shop = url.searchParams.get("shop") || "";
  const cacheKey = new Request(`https://cache.local/dashboard?shop=${encodeURIComponent(shop)}`, { method: "GET" });
  return respondWithEdgeCache(cacheKey, 120, OPEN_CORS_HEADERS, ctx, async () => {
    return new Response(getDashboardHTML(shop), {
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "public, max-age=0, s-maxage=120, stale-while-revalidate=300",
      },
    });
  });
}

async function handleTurnstileVerify(request, env, corsHeaders) {
  let body;
  try {
    body = await request.json();
  } catch {
    return jsonResponse({ ok: false, error: "invalid_json" }, 400, corsHeaders);
  }

  const token = typeof body?.token === "string" ? body.token.slice(0, 2048) : "";
  const action = typeof body?.action === "string" ? body.action.slice(0, 50) : "";

  if (!token) {
    return jsonResponse({ ok: false, error: "missing_token" }, 400, corsHeaders);
  }

  const secret = env.TURNSTILE_SECRET_KEY;
  if (!secret) {
    // Not configured — fail open so real users aren't blocked
    return jsonResponse({ ok: true, note: "not_configured" }, 200, corsHeaders);
  }

  const form = new URLSearchParams();
  form.set("secret", secret);
  form.set("response", token);
  if (action) form.set("action", action);
  const ip = request.headers.get("CF-Connecting-IP");
  if (ip) form.set("remoteip", ip);

  let result;
  try {
    const resp = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      body: form,
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
    result = await resp.json();
  } catch {
    // Upstream error — fail open
    return jsonResponse({ ok: true, note: "upstream_error" }, 200, corsHeaders);
  }

  const ok = result.success === true;
  return jsonResponse({ ok }, ok ? 200 : 403, corsHeaders);
}

function servePixelGuard(url) {
  const shop = normalizeShopDomain(url.searchParams.get("shop"));
  const reportOnly = url.searchParams.get("mode") === "report";
  const enabled = url.searchParams.get("enabled") !== "0";

  return new Response(buildPixelGuardScript(shop, url.origin, reportOnly, enabled), {
    headers: {
      "Content-Type": "application/javascript; charset=utf-8",
      "Cache-Control": "public, max-age=86400, s-maxage=86400, stale-while-revalidate=3600",
      "X-Content-Type-Options": "nosniff",
    },
  });
}

function buildPixelGuardScript(shop, origin, reportOnly, enabled) {
  return `(() => {
  "use strict";

  const config = {
    shop: ${JSON.stringify(shop)},
    apiBase: ${JSON.stringify(origin)},
    enabled: ${enabled ? "true" : "false"},
    reportOnly: ${reportOnly ? "true" : "false"},
    version: "pixel-guard-v1"
  };

  if (!config.enabled || !config.shop || window.__CommerceShieldPixelGuard?.active) return;

  const ua = navigator.userAgent || "";
  const native = {
    fetch: window.fetch,
    sendBeacon: navigator.sendBeacon,
    appendChild: Element.prototype.appendChild,
    insertBefore: Element.prototype.insertBefore,
    image: window.Image,
    xhr: window.XMLHttpRequest
  };

  function classifyVisitor() {
    const reasons = [];
    let score = 0;
    const lowerUa = ua.toLowerCase();
    const hardUa = /(adsbot|applebot|baiduspider|bingbot|bot|crawler|curl|duckduckbot|facebookexternalhit|googlebot|headlesschrome|httpclient|lighthouse|micromessenger|mmwebsdk|phantomjs|playwright|prerender|puppeteer|python-requests|semrushbot|selenium|spider|wget|weixin|xweb\/|yandexbot)/i.test(ua);
    const automationUa = /(headlesschrome|phantomjs|playwright|puppeteer|selenium|webdriver|jsdom)/i.test(ua);

    if (hardUa) {
      score = Math.max(score, 0.92);
      reasons.push("bot_user_agent");
    }
    if (automationUa) {
      score = Math.max(score, 0.94);
      reasons.push("automation_user_agent");
    }
    if (navigator.webdriver === true) {
      score = Math.max(score, 0.96);
      reasons.push("webdriver");
    }
    if (!/chrome|crios|safari|firefox|edg|opr|mobile/i.test(lowerUa)) {
      score += 0.1;
      reasons.push("non_browser_user_agent");
    }
    if (Array.isArray(navigator.languages) && navigator.languages.length === 0) {
      score += 0.08;
      reasons.push("empty_languages");
    }

    // Frozen/stale Chrome version — real Chrome auto-updates.
    // Chrome < 130 = 18+ months out of date (shipped Sep 2024).
    const chromeVerMatch = ua.match(/Chrome\/(\d+)\./);
    if (chromeVerMatch) {
      const chromeVer = parseInt(chromeVerMatch[1], 10);
      if (chromeVer < 100) {
        score = Math.max(score, 0.92);
        reasons.push("stale_chrome_version");
      } else if (chromeVer < 130) {
        score += 0.35;
        reasons.push("stale_chrome_version");
      }
    }

    // --- Browser environment fingerprinting ---
    // Real Chrome always exposes window.chrome. Headless/Playwright/Puppeteer
    // often omit it or have an incomplete stub.
    if (/Chrome\//i.test(ua) && !lowerUa.includes('chromium')) {
      if (typeof window.chrome === 'undefined' || window.chrome === null) {
        score += 0.35;
        reasons.push("chrome_ua_no_chrome_obj");
      }
    }

    // Headless Chrome has zero plugins. Real Chrome always has at least one
    // (PDF viewer). Only applies to desktop UA strings, not mobile.
    try {
      if (navigator.plugins && navigator.plugins.length === 0 &&
          /Chrome|Safari/i.test(ua) && !/Mobile|Android|iPhone|iPad/i.test(ua)) {
        score += 0.3;
        reasons.push("no_plugins");
      }
    } catch {}

    // outerWidth/outerHeight are 0 in headless Chrome unless explicitly set.
    try {
      if (typeof window.outerWidth !== 'undefined' &&
          window.outerWidth === 0 && window.outerHeight === 0) {
        score += 0.35;
        reasons.push("zero_outer_dimensions");
      }
    } catch {}

    // Unrealistically small screen.
    try {
      if (typeof screen !== 'undefined' &&
          (screen.width < 100 || screen.height < 100)) {
        score += 0.4;
        reasons.push("tiny_screen");
      }
    } catch {}

    // WebGL software renderer — headless Chrome uses SwiftShader.
    // Real GPUs never identify as software renderers.
    try {
      const canvas = document.createElement('canvas');
      const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
      if (gl) {
        const dbg = gl.getExtension('WEBGL_debug_renderer_info');
        if (dbg) {
          const renderer = (gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL) || '').toLowerCase();
          if (/swiftshader|llvmpipe|virtualbox|vmware|mesa|softpipe/i.test(renderer)) {
            score = Math.max(score, 0.88);
            reasons.push("software_webgl_renderer");
          }
        }
      }
    } catch {}

    // Platform/UA mismatch — scrapers hardcode "Macintosh" UA on non-Mac machines.
    try {
      const claimedMac = /Macintosh/i.test(ua);
      const platformMac = /Mac/i.test(navigator.platform || '');
      if (claimedMac && !platformMac && navigator.platform) {
        score += 0.3;
        reasons.push("platform_ua_mismatch");
      }
    } catch {}

    score = Math.min(1, score);
    const highConfidence = score >= 0.9;
    return {
      isBot: highConfidence,
      confidence: highConfidence ? "high" : "low",
      botScore: Number(score.toFixed(2)),
      reasons
    };
  }

  const decision = classifyVisitor();
  const state = {
    active: true,
    version: config.version,
    reportOnly: config.reportOnly,
    suppressing: decision.isBot && decision.confidence === "high" && !config.reportOnly,
    decision,
    suppressedPixels: 0
  };
  window.__CommerceShieldPixelGuard = state;

  // External signals (e.g. Turnstile) can call markBot() to escalate classification.
  // Never blocks user actions — only installs analytics pixel suppression.
  state.markBot = function(reason) {
    if (state.suppressing || config.reportOnly) return;
    state.suppressing = true;
    if (reason && !decision.reasons.includes(reason)) decision.reasons.push(reason);
    decision.isBot = true;
    decision.confidence = 'high';
    decision.botScore = Math.max(decision.botScore, 0.95);
    state.decision = decision;
    installFunctionStubs();
    installNetworkGuards();
    installDomGuards();
  };

  // Allow borderline scores (0.25–0.89) through for behavioral check.
  // Exit only if clearly human: no fingerprinting signals at all (score 0).
  // All visitors with any signal go through the behavioral check below.
  if (!state.suppressing && decision.botScore === 0) return;

  const blockedHostSuffixes = [
    "facebook.com",
    "facebook.net",
    "google-analytics.com",
    "googletagmanager.com",
    "googleadservices.com",
    "doubleclick.net",
    "googlesyndication.com",
    "tiktok.com",
    "pinimg.com",
    "pinterest.com",
    "snapchat.com",
    "sc-static.net",
    "bing.com",
    "clarity.ms",
    "reddit.com",
    "redditstatic.com",
    "ads-twitter.com",
    "analytics.twitter.com",
    "cloudflareinsights.com",
    "shopifysvc.com"
  ];
  const blockedPathMarkers = [
    "/tr/",
    "/collect",
    "/g/collect",
    "/pagead/",
    "/conversion",
    "/events",
    "/adsct",
    "/cdn-cgi/rum",
    "/web-pixels"
  ];

  let pendingReports = 0;
  let reportTimer = 0;

  function getUrl(value) {
    if (!value) return "";
    if (typeof value === "string") return value;
    if (value.url) return value.url;
    return String(value);
  }

  function hostMatches(host, suffix) {
    return host === suffix || host.endsWith("." + suffix);
  }

  function isPixelUrl(value) {
    const raw = getUrl(value);
    if (!raw) return false;
    let target;
    try {
      target = new URL(raw, document.baseURI);
    } catch {
      return false;
    }
    const host = target.hostname.toLowerCase();
    const path = target.pathname.toLowerCase();

    for (const suffix of blockedHostSuffixes) {
      if (hostMatches(host, suffix)) return true;
    }
    if (host === "cdn.shopify.com" && path.includes("/web-pixels")) return true;
    if (host === "www.google.com" && (path.includes("/pagead/") || path.includes("/conversion"))) return true;
    if (host === "www.googleadservices.com") return true;

    for (const marker of blockedPathMarkers) {
      if (path.includes(marker) && /(facebook|google|doubleclick|tiktok|pinterest|snap|bing|clarity|reddit|twitter|cloudflare|shopify)/i.test(host)) {
        return true;
      }
    }
    return false;
  }

  function reportSuppressedPixel(kind, url) {
    state.suppressedPixels += 1;
    state.lastSuppressed = {
      kind,
      url: String(url || "").slice(0, 180),
      at: new Date().toISOString()
    };
    pendingReports += 1;
    if (!reportTimer) {
      reportTimer = setTimeout(flushReports, 800);
    }
  }

  function flushReports() {
    reportTimer = 0;
    const count = Math.min(50, pendingReports);
    pendingReports = Math.max(0, pendingReports - count);
    if (!count) return;

    const body = JSON.stringify({
      shop: config.shop,
      count,
      isBot: true,
      confidence: decision.confidence,
      botScore: decision.botScore,
      reason: decision.reasons.join(","),
      page: location.pathname.slice(0, 500),
      source: document.referrer.slice(0, 200),
      ua: ua.slice(0, 200)
    });
    const endpoint = config.apiBase + "/api/pixel-guard/event";

    try {
      if (native.sendBeacon) {
        const blob = new Blob([body], { type: "application/json" });
        if (native.sendBeacon.call(navigator, endpoint, blob)) return;
      }
    } catch {}

    try {
      if (native.fetch) {
        native.fetch(endpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body,
          keepalive: true
        }).catch(() => {});
      }
    } catch {}
  }

  function blockScriptNode(node) {
    if (!node || String(node.tagName || "").toUpperCase() !== "SCRIPT") return false;
    const src = node.src || node.getAttribute?.("src") || "";
    if (!isPixelUrl(src)) return false;
    reportSuppressedPixel("script", src);
    try {
      node.type = "text/plain";
      node.removeAttribute("src");
      node.setAttribute("data-commerce-shield-suppressed", "true");
    } catch {}
    return true;
  }

  function installFunctionStubs() {
    const stubNames = ["fbq", "_fbq", "gtag", "pintrk", "snaptr", "twq", "rdt", "lintrk", "qp", "clarity"];
    for (const name of stubNames) {
      window[name] = function commerceShieldPixelStub() {
        reportSuppressedPixel("function:" + name, name);
        return undefined;
      };
      window[name].commerceShieldSuppressed = true;
    }

    window.dataLayer = window.dataLayer || [];
    window.dataLayer.push = function commerceShieldDataLayerPush() {
      reportSuppressedPixel("dataLayer", "dataLayer");
      return window.dataLayer.length;
    };

    window.uetq = window.uetq || [];
    window.uetq.push = function commerceShieldUetqPush() {
      reportSuppressedPixel("uetq", "uetq");
      return window.uetq.length;
    };

    window.ttq = window.ttq || {};
    for (const method of ["page", "track", "identify", "load", "instance", "ready"]) {
      window.ttq[method] = function commerceShieldTtqStub() {
        reportSuppressedPixel("ttq:" + method, "ttq");
        return window.ttq;
      };
    }
  }

  function installNetworkGuards() {
    if (native.fetch) {
      window.fetch = function commerceShieldFetch(input, init) {
        const target = getUrl(input);
        if (isPixelUrl(target)) {
          reportSuppressedPixel("fetch", target);
          return Promise.resolve(new Response("", { status: 204, statusText: "Commerce Shield Pixel Suppressed" }));
        }
        return native.fetch.apply(this, arguments);
      };
    }

    if (native.sendBeacon) {
      navigator.sendBeacon = function commerceShieldBeacon(url, data) {
        if (isPixelUrl(url)) {
          reportSuppressedPixel("beacon", url);
          return true;
        }
        return native.sendBeacon.call(this, url, data);
      };
    }

    if (native.xhr) {
      window.XMLHttpRequest = function CommerceShieldXMLHttpRequest() {
        const xhr = new native.xhr();
        const open = xhr.open;
        const send = xhr.send;
        let blocked = false;
        xhr.open = function commerceShieldXhrOpen(method, url) {
          if (isPixelUrl(url)) {
            blocked = true;
            reportSuppressedPixel("xhr", url);
            return undefined;
          }
          return open.apply(xhr, arguments);
        };
        xhr.send = function commerceShieldXhrSend() {
          if (blocked) return undefined;
          return send.apply(xhr, arguments);
        };
        return xhr;
      };
      window.XMLHttpRequest.prototype = native.xhr.prototype;
    }
  }

  function installDomGuards() {
    Element.prototype.appendChild = function commerceShieldAppendChild(node) {
      if (blockScriptNode(node)) return node;
      return native.appendChild.call(this, node);
    };
    Element.prototype.insertBefore = function commerceShieldInsertBefore(node, referenceNode) {
      if (blockScriptNode(node)) return node;
      return native.insertBefore.call(this, node, referenceNode);
    };

    if (native.image && window.HTMLImageElement) {
      const srcDescriptor = Object.getOwnPropertyDescriptor(HTMLImageElement.prototype, "src");
      if (srcDescriptor?.set && srcDescriptor?.get) {
        window.Image = function CommerceShieldImage(width, height) {
          const img = arguments.length ? new native.image(width, height) : new native.image();
          try {
            Object.defineProperty(img, "src", {
              configurable: true,
              enumerable: true,
              get() {
                return srcDescriptor.get.call(img);
              },
              set(value) {
                if (isPixelUrl(value)) {
                  reportSuppressedPixel("image", value);
                  return;
                }
                srcDescriptor.set.call(img, value);
              }
            });
          } catch {}
          return img;
        };
        window.Image.prototype = native.image.prototype;
      }
    }
  }

  // Install suppression hooks immediately for confirmed bots (score >= 0.9).
  if (state.suppressing) {
    installFunctionStubs();
    installNetworkGuards();
    installDomGuards();
  }

  // Behavioral check: listen for human interaction signals.
  // For borderline scores (0.25–0.89): if no interaction in 2.5 s → boost score,
  // install suppression, report as bot. If interaction detected and we were
  // provisionally suppressing → restore native network functions.
  (function setupBehavioralCheck() {
    let interacted = false;
    const evts = ['mousemove', 'scroll', 'click', 'keydown', 'touchstart', 'pointerdown'];
    function onInteract() {
      interacted = true;
      for (const e of evts) window.removeEventListener(e, onInteract, { passive: true });
    }
    for (const e of evts) window.addEventListener(e, onInteract, { passive: true });

    setTimeout(function() {
      for (const e of evts) window.removeEventListener(e, onInteract, { passive: true });
      state.behavioralCheck = { completed: true, hadInteraction: interacted };

      if (!interacted) {
        // No mouse/scroll/key/touch in 2.5 s — elevate score.
        const boosted = Math.min(1, decision.botScore + 0.6);
        decision.botScore = Number(boosted.toFixed(2));
        decision.isBot = boosted >= 0.9;
        decision.confidence = decision.isBot ? 'high' : 'low';
        if (!decision.reasons.includes('no_interaction')) decision.reasons.push('no_interaction');
        state.decision = decision;

        if (decision.isBot && !state.suppressing && !config.reportOnly) {
          state.suppressing = true;
          installFunctionStubs();
          installNetworkGuards();
          installDomGuards();
        }
      } else if (interacted && state.suppressing && decision.botScore < 0.9) {
        // Was borderline-suppressed but user proved human — restore native network fns.
        // (Already-blocked pixels cannot be un-blocked, but future ones are allowed.)
        if (native.fetch) window.fetch = native.fetch;
        if (native.sendBeacon) navigator.sendBeacon = native.sendBeacon;
        if (native.xhr) window.XMLHttpRequest = native.xhr;
        state.suppressing = false;
        decision.isBot = false;
        decision.confidence = 'low';
        decision.reasons.push('interaction_cleared');
        state.decision = decision;
      }
    }, 2500);
  })();
})();`;
}

function getDashboardHTML(defaultShop) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Commerce Shield Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh}
.header{background:linear-gradient(135deg,#1e293b,#334155);padding:20px 32px;border-bottom:1px solid #475569;display:flex;align-items:center;justify-content:space-between}
.header h1{font-size:24px;font-weight:700;display:flex;align-items:center;gap:10px}
.header h1 .shield{font-size:28px}
.controls{display:flex;gap:12px;align-items:center}
.controls input,.controls select{background:#1e293b;border:1px solid #475569;color:#e2e8f0;padding:8px 12px;border-radius:8px;font-size:14px}
.controls button{background:#3b82f6;color:white;border:none;padding:8px 20px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}
.controls button:hover{background:#2563eb}
.dashboard{padding:24px 32px;max-width:1400px;margin:0 auto}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;text-align:center}
.stat-card .value{font-size:32px;font-weight:700;margin:4px 0}
.stat-card .label{font-size:13px;color:#94a3b8;text-transform:uppercase;letter-spacing:0.5px}
.stat-card.sessions .value{color:#3b82f6}
.stat-card.humans .value{color:#22c55e}
.stat-card.bots .value{color:#ef4444}
.stat-card.rate .value{color:#f59e0b}
.stat-card.coupon .value{color:#a855f7}
.stat-card.pixels .value{color:#06b6d4}
.stat-card.emails .value{color:#ec4899}
.charts-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:24px}
.chart-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px}
.chart-card h3{font-size:16px;margin-bottom:16px;color:#cbd5e1}
.table-card{background:#1e293b;border:1px solid #334155;border-radius:12px;padding:20px;overflow-x:auto}
.table-card h3{font-size:16px;margin-bottom:16px;color:#cbd5e1}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:10px 12px;border-bottom:1px solid #334155;color:#94a3b8;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:0.5px}
td{padding:10px 12px;border-bottom:1px solid #1e293b}
tr:hover td{background:#334155}
.badge{padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600}
.badge.bot{background:#991b1b;color:#fca5a5}
.badge.human{background:#14532d;color:#86efac}
.badge.coupon{background:#581c87;color:#d8b4fe}
.badge.legit{background:#1e3a5f;color:#93c5fd}
.badge.high{background:#991b1b;color:#fca5a5}
.badge.medium{background:#78350f;color:#fde68a}
.badge.low{background:#14532d;color:#86efac}
.empty{text-align:center;padding:60px 20px;color:#64748b}
.empty .icon{font-size:48px;margin-bottom:12px}
@media(max-width:768px){.charts-grid{grid-template-columns:1fr}.dashboard{padding:16px}.header{padding:16px}.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="header">
  <h1><span class="shield">&#x1f6e1;</span> Commerce Shield</h1>
  <div class="controls">
    <input type="text" id="shopInput" placeholder="your-store.myshopify.com" value="${defaultShop}">
    <select id="daysSelect"><option value="7">7 days</option><option value="14">14 days</option><option value="30" selected>30 days</option></select>
    <button onclick="loadDashboard()">Load</button>
  </div>
</div>
<div class="dashboard" id="content">
  <div class="empty"><div class="icon">&#x1f6e1;</div><p>Enter your shop domain above and click Load</p></div>
</div>
<script>
let lineChart, donutChart;
let lastDashboardFetchAt = 0;
const DASHBOARD_REFRESH_MS = 60000;

async function loadDashboard() {
  const shop = document.getElementById('shopInput').value.trim();
  const days = document.getElementById('daysSelect').value;
  if (!shop) return;
  if (Date.now() - lastDashboardFetchAt < DASHBOARD_REFRESH_MS) return;
  lastDashboardFetchAt = Date.now();

  const base = window.location.origin;
  const [dashRes, recentRes] = await Promise.all([
    fetch(base + '/api/dashboard?shop=' + encodeURIComponent(shop) + '&days=' + days, { cache: 'force-cache' }),
    fetch(base + '/api/recent?shop=' + encodeURIComponent(shop) + '&limit=25&bots=1', { cache: 'force-cache' })
  ]);

  const dash = await dashRes.json();
  const recent = await recentRes.json();
  renderDashboard(dash, recent);
}

function renderDashboard(dash, recent) {
  const t = dash.totals || {};
  const totalVisits = t.totalVisits || 0;
  const botRate = totalVisits > 0 ? ((t.botVisits || 0) / totalVisits * 100).toFixed(1) : '0.0';

  let html = '<div class="stats-grid">';
  html += statCard('sessions', 'Sessions', fmt(totalVisits));
  html += statCard('humans', 'Humans', fmt(t.humanVisits || 0));
  html += statCard('bots', 'Bots Detected', fmt(t.botVisits || 0));
  html += statCard('rate', 'Bot Rate', botRate + '%');
  html += statCard('coupon', 'Coupon Bots', fmt(t.couponBots || 0));
  html += statCard('pixels', 'Pixels Protected', fmt(t.pixelsProtected || 0));
  html += statCard('emails', 'Emails Blocked', fmt(t.disposableEmailsBlocked || 0));
  html += '</div>';

  html += '<div class="charts-grid">';
  html += '<div class="chart-card"><h3>Traffic Over Time</h3><canvas id="lineChart" height="200"></canvas></div>';
  html += '<div class="chart-card"><h3>Visitor Breakdown</h3><canvas id="donutChart" height="200"></canvas></div>';
  html += '</div>';

  // Sources table
  html += '<div class="charts-grid"><div class="chart-card"><h3>Traffic Sources</h3><table><thead><tr><th>Source</th><th>Visits</th><th>Bots</th><th>Bot %</th></tr></thead><tbody>';
  for (const s of (dash.sources || [])) {
    const pct = s.count > 0 ? (s.bots / s.count * 100).toFixed(1) : '0.0';
    html += '<tr><td>' + esc(s.source) + '</td><td>' + fmt(s.count) + '</td><td>' + fmt(s.bots) + '</td><td>' + pct + '%</td></tr>';
  }
  html += '</tbody></table></div>';

  // Recent visits
  html += '<div class="table-card"><h3>Recent Bot Visits</h3><table><thead><tr><th>Time</th><th>Type</th><th>Score</th><th>Confidence</th><th>Source</th><th>Page</th></tr></thead><tbody>';
  for (const v of (recent.visits || []).slice(0, 25)) {
    const type = v.is_coupon_bot ? 'coupon' : v.is_legitimate ? 'legit' : v.is_bot ? 'bot' : 'human';
    const typeLabel = v.is_coupon_bot ? 'Coupon Bot' : v.is_legitimate ? 'Crawler' : v.is_bot ? 'Bot' : 'Human';
    const confClass = v.confidence || 'low';
    const time = v.created_at ? new Date(v.created_at + 'Z').toLocaleTimeString() : '';
    html += '<tr><td>' + time + '</td><td><span class="badge ' + type + '">' + typeLabel + '</span></td>';
    html += '<td>' + (v.bot_score || 0).toFixed(2) + '</td>';
    html += '<td><span class="badge ' + confClass + '">' + (v.confidence || 'low') + '</span></td>';
    html += '<td>' + esc(v.source || '') + '</td><td>' + esc((v.page || '').slice(0, 40)) + '</td></tr>';
  }
  html += '</tbody></table></div></div>';

  document.getElementById('content').innerHTML = html;

  // Render charts
  renderLineChart(dash.dailyStats || []);
  renderDonutChart(dash.botTypes || {});
}

function renderLineChart(data) {
  const ctx = document.getElementById('lineChart');
  if (!ctx) return;
  if (lineChart) lineChart.destroy();
  lineChart = new Chart(ctx, {
    type: 'line',
    data: {
      labels: data.map(d => d.date),
      datasets: [
        { label: 'Humans', data: data.map(d => d.human_visits), borderColor: '#22c55e', backgroundColor: 'rgba(34,197,94,0.1)', fill: true, tension: 0.3 },
        { label: 'Bots', data: data.map(d => d.bot_visits), borderColor: '#ef4444', backgroundColor: 'rgba(239,68,68,0.1)', fill: true, tension: 0.3 },
      ]
    },
    options: { responsive: true, plugins: { legend: { labels: { color: '#94a3b8' } } }, scales: { x: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } }, y: { ticks: { color: '#64748b' }, grid: { color: '#1e293b' } } } }
  });
}

function renderDonutChart(bt) {
  const ctx = document.getElementById('donutChart');
  if (!ctx) return;
  if (donutChart) donutChart.destroy();
  donutChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['Humans', 'Bad Bots', 'Coupon Bots', 'Legitimate Crawlers'],
      datasets: [{ data: [bt.humans || 0, bt.badBots || 0, bt.couponBots || 0, bt.legitimateBots || 0], backgroundColor: ['#22c55e', '#ef4444', '#a855f7', '#3b82f6'] }]
    },
    options: { responsive: true, plugins: { legend: { position: 'bottom', labels: { color: '#94a3b8', padding: 12 } } } }
  });
}

function statCard(cls, label, value) {
  return '<div class="stat-card ' + cls + '"><div class="label">' + label + '</div><div class="value">' + value + '</div></div>';
}
function fmt(n) { return (n || 0).toLocaleString(); }
function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

// Auto-load if shop param is present
if (document.getElementById('shopInput').value) { setTimeout(loadDashboard, 100); }
</script>
</body>
</html>`;
}

function getEmbeddedAdminHTML(shop, origin) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Commerce Shield</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4"><\/script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f6f6f7;color:#1a1a1a;min-height:100vh;padding:16px}
.page-header{margin-bottom:20px}
.page-header h1{font-size:20px;font-weight:700;display:flex;align-items:center;gap:8px;color:#1a1a1a}
.page-header p{font-size:14px;color:#616161;margin-top:4px}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
.stat-card{background:white;border:1px solid #e3e3e3;border-radius:12px;padding:16px;text-align:center;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.stat-card .value{font-size:28px;font-weight:700;margin:2px 0}
.stat-card .label{font-size:12px;color:#616161;text-transform:uppercase;letter-spacing:0.3px;font-weight:600}
.stat-card.sessions .value{color:#005bd3}
.stat-card.humans .value{color:#1a8245}
.stat-card.bots .value{color:#d72c0d}
.stat-card.rate .value{color:#b98900}
.stat-card.coupon .value{color:#8c6daa}
.stat-card.pixels .value{color:#0e7090}
.stat-card.emails .value{color:#c44e8a}
.card{background:white;border:1px solid #e3e3e3;border-radius:12px;padding:20px;margin-bottom:16px;box-shadow:0 1px 3px rgba(0,0,0,0.04)}
.card h3{font-size:14px;font-weight:600;margin-bottom:12px;color:#303030}
.charts-grid{display:grid;grid-template-columns:2fr 1fr;gap:16px;margin-bottom:16px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;padding:8px 10px;border-bottom:2px solid #e3e3e3;color:#616161;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:0.3px}
td{padding:8px 10px;border-bottom:1px solid #f1f1f1}
tr:hover td{background:#f9fafb}
.badge{padding:2px 8px;border-radius:9999px;font-size:11px;font-weight:600}
.badge.bot{background:#fce4e4;color:#d72c0d}
.badge.human{background:#e0f5e9;color:#1a8245}
.badge.coupon{background:#f0e8f5;color:#8c6daa}
.badge.legit{background:#e0efff;color:#005bd3}
.badge.high{background:#fce4e4;color:#d72c0d}
.badge.medium{background:#fff5d6;color:#b98900}
.badge.low{background:#e0f5e9;color:#1a8245}
.controls{display:flex;gap:10px;align-items:center;margin-bottom:20px;flex-wrap:wrap}
.controls select,.controls input{border:1px solid #c9cccf;padding:8px 12px;border-radius:8px;font-size:14px;background:white;color:#303030}
.controls button{background:#005bd3;color:white;border:none;padding:8px 20px;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}
.controls button:hover{background:#004ab2}
.empty{text-align:center;padding:60px 20px;color:#8c9196}
.empty .icon{font-size:48px;margin-bottom:12px}
.status-banner{background:#e0f5e9;border:1px solid #95d6b0;border-radius:12px;padding:12px 16px;margin-bottom:16px;display:flex;align-items:center;gap:8px;font-size:14px;color:#1a8245}
.status-banner .dot{width:8px;height:8px;background:#1a8245;border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}
@media(max-width:768px){.charts-grid{grid-template-columns:1fr}.stats-grid{grid-template-columns:repeat(2,1fr)}}
</style>
</head>
<body>
<div class="page-header">
  <h1>&#x1f6e1;&#xfe0f; Commerce Shield</h1>
  <p>Bot detection, pixel protection &amp; email security — running 24/7 on your storefront</p>
</div>

<div class="status-banner">
  <span class="dot"></span>
  <strong>Active</strong> — Client-side bot detection is running on all pages
</div>

<div class="controls">
  <input type="text" id="shopInput" placeholder="your-store.myshopify.com" value="${shop}">
  <select id="daysSelect"><option value="7">Last 7 days</option><option value="14">Last 14 days</option><option value="30" selected>Last 30 days</option><option value="90">Last 90 days</option></select>
  <button onclick="loadData()">Refresh</button>
</div>

<div id="content">
  <div class="empty"><div class="icon">&#x1f6e1;&#xfe0f;</div><p>Enter your shop domain and click Refresh to load analytics</p></div>
</div>

<script>
let lineChart, donutChart;
const API = '${origin}';
let lastLoadAt = 0;
const MIN_LOAD_MS = 60000;

async function loadData() {
  const shop = document.getElementById('shopInput').value.trim();
  const days = document.getElementById('daysSelect').value;
  if (!shop) return;
  if (Date.now() - lastLoadAt < MIN_LOAD_MS) return;
  lastLoadAt = Date.now();
  try {
    const [dashRes, recentRes] = await Promise.all([
      fetch(API + '/api/dashboard?shop=' + encodeURIComponent(shop) + '&days=' + days, { cache: 'force-cache' }),
      fetch(API + '/api/recent?shop=' + encodeURIComponent(shop) + '&limit=25&bots=1', { cache: 'force-cache' })
    ]);
    const dash = await dashRes.json();
    const recent = await recentRes.json();
    render(dash, recent);
  } catch(e) {
    document.getElementById('content').innerHTML = '<div class="card"><p>Error loading data: ' + e.message + '</p></div>';
  }
}

function render(dash, recent) {
  const t = dash.totals || {};
  const total = t.totalVisits || 0;
  const botRate = total > 0 ? ((t.botVisits || 0) / total * 100).toFixed(1) : '0.0';

  let h = '<div class="stats-grid">';
  h += sc('sessions','Sessions',fmt(total));
  h += sc('humans','Humans',fmt(t.humanVisits||0));
  h += sc('bots','Bots Detected',fmt(t.botVisits||0));
  h += sc('rate','Bot Rate',botRate+'%');
  h += sc('coupon','Coupon Bots',fmt(t.couponBots||0));
  h += sc('pixels','Pixels Protected',fmt(t.pixelsProtected||0));
  h += sc('emails','Emails Blocked',fmt(t.disposableEmailsBlocked||0));
  h += '</div>';

  h += '<div class="charts-grid">';
  h += '<div class="card"><h3>Traffic Over Time</h3><canvas id="lineChart" height="180"></canvas></div>';
  h += '<div class="card"><h3>Visitor Breakdown</h3><canvas id="donutChart" height="180"></canvas></div>';
  h += '</div>';

  h += '<div class="charts-grid">';
  h += '<div class="card"><h3>Traffic Sources</h3><table><thead><tr><th>Source</th><th>Visits</th><th>Bots</th><th>Bot %</th></tr></thead><tbody>';
  for (const s of (dash.sources||[])) {
    const p = s.count > 0 ? (s.bots/s.count*100).toFixed(1) : '0.0';
    h += '<tr><td>'+esc(s.source)+'</td><td>'+fmt(s.count)+'</td><td>'+fmt(s.bots)+'</td><td>'+p+'%</td></tr>';
  }
  if (!dash.sources?.length) h += '<tr><td colspan="4" style="text-align:center;color:#8c9196">No data yet</td></tr>';
  h += '</tbody></table></div>';

  h += '<div class="card"><h3>Recent Bot Visits</h3><table><thead><tr><th>Time</th><th>Type</th><th>Score</th><th>Confidence</th><th>Source</th></tr></thead><tbody>';
  for (const v of (recent.visits||[]).slice(0,20)) {
    const type = v.is_coupon_bot?'coupon':v.is_legitimate?'legit':v.is_bot?'bot':'human';
    const lbl = v.is_coupon_bot?'Coupon Bot':v.is_legitimate?'Crawler':v.is_bot?'Bot':'Human';
    const conf = v.confidence||'low';
    const tm = v.created_at ? new Date(v.created_at+'Z').toLocaleTimeString() : '';
    h += '<tr><td>'+tm+'</td><td><span class="badge '+type+'">'+lbl+'</span></td>';
    h += '<td>'+(v.bot_score||0).toFixed(2)+'</td>';
    h += '<td><span class="badge '+conf+'">'+(v.confidence||'low')+'</span></td>';
    h += '<td>'+esc(v.source||'')+'</td></tr>';
  }
  if (!recent.visits?.length) h += '<tr><td colspan="5" style="text-align:center;color:#8c9196">No bot visits recorded yet</td></tr>';
  h += '</tbody></table></div></div>';

  document.getElementById('content').innerHTML = h;
  renderLine(dash.dailyStats||[]);
  renderDonut(dash.botTypes||{});
}

function renderLine(data){
  const c=document.getElementById('lineChart'); if(!c)return;
  if(lineChart)lineChart.destroy();
  lineChart=new Chart(c,{type:'line',data:{labels:data.map(d=>d.date),datasets:[
    {label:'Humans',data:data.map(d=>d.human_visits),borderColor:'#1a8245',backgroundColor:'rgba(26,130,69,0.08)',fill:true,tension:0.3},
    {label:'Bots',data:data.map(d=>d.bot_visits),borderColor:'#d72c0d',backgroundColor:'rgba(215,44,13,0.08)',fill:true,tension:0.3}
  ]},options:{responsive:true,plugins:{legend:{labels:{color:'#616161'}}},scales:{x:{ticks:{color:'#8c9196'},grid:{color:'#f1f1f1'}},y:{ticks:{color:'#8c9196'},grid:{color:'#f1f1f1'}}}}});
}

function renderDonut(bt){
  const c=document.getElementById('donutChart'); if(!c)return;
  if(donutChart)donutChart.destroy();
  donutChart=new Chart(c,{type:'doughnut',data:{labels:['Humans','Bad Bots','Coupon Bots','Crawlers'],datasets:[{data:[bt.humans||0,bt.badBots||0,bt.couponBots||0,bt.legitimateBots||0],backgroundColor:['#1a8245','#d72c0d','#8c6daa','#005bd3']}]},options:{responsive:true,plugins:{legend:{position:'bottom',labels:{color:'#616161',padding:12}}}}});
}

function sc(c,l,v){return '<div class="stat-card '+c+'"><div class="label">'+l+'</div><div class="value">'+v+'</div></div>';}
function fmt(n){return(n||0).toLocaleString();}
function esc(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML;}

// Auto-load if shop param present
if(document.getElementById('shopInput').value){setTimeout(loadData,200);}
<\/script>
</body>
</html>`;
}

function buildEmbeddedAdminHTML(shop, origin) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Commerce Shield</title>
<style>
*{box-sizing:border-box}body{margin:0;padding:18px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;background:#f6f6f7;color:#111827}.wrap{max-width:1440px;margin:0 auto}.hero{margin-bottom:16px}.hero h1{margin:0;font-size:24px}.hero p{margin:6px 0 0;color:#6b7280;font-size:14px;line-height:1.5}.strip{background:#eef6ff;border:1px solid #bfdbfe;color:#1d4ed8;border-radius:14px;padding:12px 14px;margin:0 0 16px;font-size:13px;font-weight:700}.controls,.tabs{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}.controls input,.controls select,textarea{background:#fff;border:1px solid #d1d5db;border-radius:10px;padding:10px 12px;font-size:14px;color:#111827}textarea{width:100%;min-height:120px;resize:vertical}button{border:none;border-radius:10px;padding:10px 14px;background:#111827;color:#fff;font-size:13px;font-weight:700;cursor:pointer}.tabs button{background:#fff;color:#374151;border:1px solid #d1d5db}.tabs button.active{background:#111827;color:#fff;border-color:#111827}.panel{display:none}.panel.active{display:block}.grid{display:grid;gap:12px}.cards{grid-template-columns:repeat(auto-fit,minmax(180px,1fr));margin-bottom:16px}.two{grid-template-columns:repeat(2,minmax(0,1fr));margin-bottom:16px}.card,.metric{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:18px;box-shadow:0 8px 24px rgba(15,23,42,.04)}.metric .k{font-size:12px;text-transform:uppercase;letter-spacing:.4px;color:#6b7280;font-weight:700}.metric .v{font-size:28px;font-weight:800;margin-top:6px}.metric .h{font-size:12px;color:#6b7280;line-height:1.45;margin-top:8px}.head{display:flex;justify-content:space-between;gap:14px;align-items:flex-start;margin-bottom:12px}.head h2{margin:0;font-size:20px}.head p{margin:6px 0 0;color:#6b7280;font-size:13px;line-height:1.55;max-width:820px}.chip{padding:6px 10px;border-radius:999px;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.4px}.ok{background:#dcfce7;color:#166534}.warn{background:#fef3c7;color:#92400e}.bad{background:#fee2e2;color:#991b1b}.info{background:#dbeafe;color:#1d4ed8}.msg{display:none;margin-bottom:16px;padding:12px 14px;border-radius:12px;font-size:13px;font-weight:700}.msg.show{display:block}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #f3f4f6;vertical-align:top}th{font-size:11px;color:#6b7280;text-transform:uppercase;letter-spacing:.4px;border-bottom:2px solid #e5e7eb}.finding{border:1px solid #e5e7eb;border-radius:14px;padding:14px;margin-bottom:12px}.finding h4{margin:8px 0 6px;font-size:15px}.finding p{margin:0;color:#4b5563;font-size:13px;line-height:1.55}.row{display:flex;gap:8px;flex-wrap:wrap;align-items:center}.sub{font-size:12px;color:#6b7280}.switch{display:flex;gap:10px;padding:12px 0;border-bottom:1px solid #f3f4f6}.switch:last-child{border-bottom:none}.switch input{margin-top:4px}.switch strong{display:block;font-size:14px;margin-bottom:4px}.switch span{display:block;font-size:12px;color:#6b7280;line-height:1.45}.load{padding:54px 18px;text-align:center;color:#6b7280;background:#fff;border:1px dashed #d1d5db;border-radius:16px}@media(max-width:960px){.two{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <div class="hero"><h1>Commerce Shield</h1><p>Bot-blocker stays the default home tab. User-intent is separated from bot scoring. Shopify app health and Conversion MRI both stay conservative so the app misses weak signals before it recommends a bad fix.</p></div>
  <div class="strip">Live Worker control plane. This is the production Shopify app surface configured in this repo.</div>
  <div id="msg" class="msg"></div>
  <div class="controls">
    <input id="shopInput" placeholder="your-store.myshopify.com" value="${shop}">
    <select id="daysSelect"><option value="7">Last 7 days</option><option value="14">Last 14 days</option><option value="30" selected>Last 30 days</option><option value="90">Last 90 days</option></select>
    <button type="button" onclick="refreshActive(true)">Refresh Active Tab</button>
    <button type="button" onclick="installPixelGuard()">Install Pixel Guard</button>
  </div>
  <div class="tabs">
    <button class="active" data-tab="bot-blocker" onclick="activateTab('bot-blocker')">Bot-Blocker</button>
    <button data-tab="user-intent" onclick="activateTab('user-intent')">User-Intent</button>
    <button data-tab="shopify-app-health" onclick="activateTab('shopify-app-health')">Shopify App Health</button>
    <button data-tab="conversion-mri" onclick="activateTab('conversion-mri')">Conversion MRI</button>
  </div>
  <section id="panel-bot-blocker" class="panel active"><div class="load">Load a shop to inspect storefront traffic and bot protection.</div></section>
  <section id="panel-user-intent" class="panel"><div class="load">User-intent loads after a valid shop is entered.</div></section>
  <section id="panel-shopify-app-health" class="panel"><div class="load">App health needs a Worker-side Admin token and the theme/script scopes.</div></section>
  <section id="panel-conversion-mri" class="panel"><div class="load">Conversion MRI waits for enough evidence before surfacing diagnostics.</div></section>
</div>
<script>
const SHOPIFY_API_KEY='dc386b789af148f54d80b54d07e63215';(function bootstrapEmbeddedLaunch(){const params=new URLSearchParams(window.location.search);const qShop=(params.get('shop')||'').trim().toLowerCase();if(qShop&&/^[a-z0-9][a-z0-9-]*\.myshopify\.com$/.test(qShop)){const input=document.getElementById('shopInput');if(input)input.value=qShop;}})();const API='${origin}';const state={tab:'bot-blocker',cache:{},lastFetch:{}};const TAB_REFRESH_MS={'bot-blocker':60000,'user-intent':90000,'shopify-app-health':120000,'conversion-mri':120000};function esc(v){const d=document.createElement('div');d.textContent=v==null?'':String(v);return d.innerHTML}function fmt(v){return (Number(v)||0).toLocaleString()}function pct(v){return (Number(v)||0).toFixed(1)}function shop(){return document.getElementById('shopInput').value.trim()}function days(){return document.getElementById('daysSelect').value}function panel(id){return document.getElementById('panel-'+id)}function msg(text,tone){const el=document.getElementById('msg');if(!text){el.className='msg';el.textContent='';return}el.className='msg show '+(tone==='error'?'bad':'ok');el.textContent=text}function loading(id,text){panel(id).innerHTML='<div class="load">'+esc(text)+'</div>'}async function api(path,opt){const reqOpt=Object.assign({cache:'force-cache'},opt||{});const res=await fetch(path,reqOpt);const data=await res.json().catch(()=>({}));if(!res.ok)throw new Error(data.error||'Request failed');return data}function needShop(){const s=shop();if(!s){msg('Enter a valid .myshopify.com domain first.','error');return''}return s}function getAdminToken(){let token=sessionStorage.getItem('cs_admin_token')||'';if(!token){token=prompt('Enter Commerce Shield admin token to edit theme.liquid:')||'';if(token)sessionStorage.setItem('cs_admin_token',token)}return token}async function installPixelGuard(){const s=needShop();if(!s)return;const token=getAdminToken();if(!token){msg('Admin token required to edit theme.liquid.','error');return}try{msg('Installing pixel guard at the beginning of theme.liquid head...','success');const res=await fetch(API+'/api/admin/install-pixel-guard',{method:'POST',headers:{'Content-Type':'application/json','Authorization':'Bearer '+token},body:JSON.stringify({shop:s})});const data=await res.json().catch(()=>({}));if(res.status===401||res.status===403){sessionStorage.removeItem('cs_admin_token')}if(!res.ok)throw new Error(data.error||'Unable to install pixel guard');state.cache={};msg(data.message||'Pixel guard installed.','success');await refreshActive(true)}catch(error){msg(error.message||'Unable to install pixel guard.','error')}}
function metric(cls,label,value,hint){return '<div class="metric '+cls+'"><div class="k">'+esc(label)+'</div><div class="v">'+esc(value)+'</div><div class="h">'+esc(hint||'')+'</div></div>'}
function switches(name,checked,title,copy){return '<label class="switch"><input type="checkbox" name="'+esc(name)+'"'+(checked?' checked':'')+'><div><strong>'+esc(title)+'</strong><span>'+esc(copy)+'</span></div></label>'}
function findings(items){if(!(items||[]).length)return '<div class="card"><p class="sub">No hard-evidence findings were produced under the current conservative settings.</p></div>';return items.map(function(item){const tone=item.severity==='high'?'bad':item.severity==='medium'?'warn':'info';return '<div class="finding"><div class="row"><span class="chip '+tone+'">'+esc(item.severity)+'</span><span class="chip info">'+esc(item.category)+'</span><span class="sub">'+esc(item.location||'')+'</span><span class="sub">Impact '+pct(item.missedConversionPct||0)+'%</span></div><h4>'+esc(item.title)+'</h4><p>'+esc(item.evidence||item.fix||'')+'</p>'+(item.fix?'<p style="margin-top:8px"><strong>Fix:</strong> '+esc(item.fix)+'</p>':'')+'</div>'}).join('')}
async function loadBot(force){const s=needShop();if(!s)return;const key='bot:'+s+':'+days();if(!force&&state.cache[key])return renderBot(state.cache[key]);loading('bot-blocker','Loading bot-blocker analytics...');const data={dash:await api(API+'/api/dashboard?shop='+encodeURIComponent(s)+'&days='+encodeURIComponent(days())),recent:await api(API+'/api/recent?shop='+encodeURIComponent(s)+'&limit=50')};state.cache[key]=data;renderBot(data)}
function renderBot(data){const t=data.dash.totals||{};const total=Number(t.totalVisits)||0;let h='<div class="head"><div><h2>Bot-Blocker</h2><p>Commerce Shield remains the default home tab. Bot risk and customer intent stay separated so the storefront blocker can stay aggressive without polluting Bloomreach-facing intent tiers.</p></div><span class="chip ok">Live storefront guard</span></div>';h+='<div class="grid cards">'+metric('','Sessions',fmt(total),'All storefront sessions captured in the selected period.')+metric('','Humans',fmt(t.humanVisits||0),'Traffic that stayed on the safe path.')+metric('bad','Bots detected',fmt(t.botVisits||0),'Sessions classified as bots and isolated from clean analytics.')+metric('warn','Bot rate',pct(total?((Number(t.botVisits)||0)/total)*100:0)+'%','Share of selected traffic classified as bot activity.')+metric('','Coupon bots',fmt(t.couponBots||0),'Known coupon extensions and similar crawler traffic.')+metric('','Pixels protected',fmt(t.pixelsProtected||0),'High-confidence bot events blocked from downstream pixels.')+metric('','Emails blocked',fmt(t.disposableEmailsBlocked||0),'Disposable email attempts rejected by Commerce Shield.')+'</div>';h+='<div class="grid two"><div class="card"><h3>Traffic Sources</h3><table><thead><tr><th>Source</th><th>Visits</th><th>Bots</th><th>Bot %</th></tr></thead><tbody>';(data.dash.sources||[]).forEach(function(row){const r=Number(row.count)?((Number(row.bots)||0)/Number(row.count))*100:0;h+='<tr><td>'+esc(row.source||'direct')+'</td><td>'+fmt(row.count)+'</td><td>'+fmt(row.bots)+'</td><td>'+pct(r)+'%</td></tr>'});if(!(data.dash.sources||[]).length)h+='<tr><td colspan="4" class="sub">No source data has been recorded yet.</td></tr>';h+='</tbody></table></div>';h+='<div class="card"><h3>Recent Visits</h3><table><thead><tr><th>Time</th><th>Type</th><th>Score</th><th>Confidence</th><th>Source</th></tr></thead><tbody>';(data.recent.visits||[]).slice(0,20).forEach(function(v){const type=v.is_coupon_bot?'Coupon Bot':v.is_legitimate?'Crawler':v.is_bot?'Bot':'Human';h+='<tr><td>'+esc(v.created_at?new Date(v.created_at+'Z').toLocaleString():'—')+'</td><td>'+esc(type)+'</td><td>'+pct(v.bot_score||0)+'</td><td>'+esc(v.confidence||'low')+'</td><td>'+esc(v.source||'direct')+'</td></tr>'});if(!(data.recent.visits||[]).length)h+='<tr><td colspan="5" class="sub">No visit classifications recorded yet.</td></tr>';h+='</tbody></table></div></div>';panel('bot-blocker').innerHTML=h}
async function loadIntent(force){const s=needShop();if(!s)return;const key='intent:'+s;if(!force&&state.cache[key])return renderIntent(state.cache[key]);loading('user-intent','Loading user-intent cohorts and controls...');const data=await api(API+'/api/admin/intent-summary?shop='+encodeURIComponent(s));state.cache[key]=data;renderIntent(data)}
function renderIntent(data){const c=data.cohorts||{},x=data.settings.intent||{};let h='<div class="head"><div><h2>User-Intent</h2><p>Intent scores are kept separate from bots and crawlers. High-intent, medium-intent, low-intent, and confirmed bots/crawlers are shown as distinct cohorts so downstream personalization stays clean.</p></div><span class="chip ok">'+esc(data.sensitivityLabel||'Balanced')+'</span></div>';h+='<div class="grid cards">'+metric('','High-intent',fmt(c.highIntent||0),'Purchase-ready and high-intent shopper profiles.')+metric('warn','Medium-intent',fmt(c.mediumIntent||0),'Considering or interested visitors.')+metric('ok','Low-intent',fmt(c.lowIntent||0),'Browsing visitors that have not crossed a stronger threshold.')+metric('bad','Confirmed bots / crawlers',fmt(c.botsAndCrawlers||0),'Profiles intentionally suppressed from positive intent promotion.')+'</div>';h+='<div class="grid two"><div class="card"><h3>Top Signals</h3><table><thead><tr><th>Signal</th><th>Profiles</th></tr></thead><tbody>';(data.topSignals||[]).forEach(function(r){h+='<tr><td>'+esc(r.type)+'</td><td>'+fmt(r.count)+'</td></tr>'});if(!(data.topSignals||[]).length)h+='<tr><td colspan="2" class="sub">No signal summaries yet.</td></tr>';h+='</tbody></table></div><div class="card"><h3>Tracked Paths</h3><table><thead><tr><th>Path</th><th>Hits</th></tr></thead><tbody>';(data.topPaths||[]).forEach(function(r){h+='<tr><td>'+esc(r.path)+'</td><td>'+fmt(r.hits)+'</td></tr>'});if(!(data.topPaths||[]).length)h+='<tr><td colspan="2" class="sub">No path activity yet.</td></tr>';h+='</tbody></table></div></div>';h+='<div class="card"><h3>Intent Controls</h3><form onsubmit="return saveSettings(event,\\'intent\\')"><div class="sub" style="margin-bottom:10px">Average score '+fmt(c.averageScore||0)+' • Sensitivity '+fmt(x.sensitivity||62)+'%</div><p><input type="range" name="sensitivity" min="10" max="95" value="'+esc(x.sensitivity||62)+'" style="width:100%"></p><p class="sub" style="margin:10px 0 6px">Scored path URLs</p><textarea name="includePaths">'+esc((x.includePaths||[]).join('\\n'))+'</textarea>'+switches('rewardProductViews',x.rewardProductViews,'Reward product views','Keep PDP exploration as a positive signal.')+switches('rewardCartSignals',x.rewardCartSignals,'Reward cart signals','Let cart and checkout-start events move shoppers up tiers.')+switches('rewardReturningSessions',x.rewardReturningSessions,'Reward returning sessions','Give repeat visitors a measured uplift.')+switches('suppressBotsAndCrawlers',x.suppressBotsAndCrawlers,'Suppress bots and crawlers','Prevent known bots and legitimate crawlers from getting promoted.')+switches('conservativeMode',x.conservativeMode,'Conservative mode','Prefer silence over a false high-intent label.')+'<p style="margin-top:14px"><button type="submit">Save User-Intent Settings</button></p></form></div>';panel('user-intent').innerHTML=h}
async function loadHealth(force){const s=needShop();if(!s)return;const key='health:'+s;if(!force&&state.cache[key])return renderHealth(state.cache[key]);loading('shopify-app-health','Running conservative app health checks...');const data=await api(API+'/api/admin/store-audit?shop='+encodeURIComponent(s));state.cache[key]=data;renderHealth(data)}
function renderHealth(data){const x=data.settings.appHealth||{},status=data.status||'healthy';let h='<div class="head"><div><h2>Shopify App Health</h2><p>This dashboard only flags strong evidence: legacy ScriptTag injections, duplicate pixel libraries, risky inline patterns, and missing core theme integration primitives. It avoids calling an app malicious unless there is direct evidence.</p></div><span class="chip '+(status==='critical'?'bad':status==='warning'?'warn':status==='limited'||status==='disconnected'?'info':'ok')+'">'+esc(status)+'</span></div>';if(data.guidance)h+='<div class="card"><p class="sub">'+esc(data.guidance)+'</p></div>';h+='<div class="grid cards">'+metric('','Legacy ScriptTags',fmt(data.summary.legacyScriptTags||0),'Theme-facing integrations still using the ScriptTag API.')+metric('','External script hosts',fmt(data.summary.externalScriptHosts||0),'Unique third-party hosts in the main theme layout.')+metric('bad','Risky patterns',fmt(data.summary.riskyPatterns||0),'document.write / eval style patterns found in live theme code.')+metric('warn','Duplicate pixels',fmt(data.summary.duplicatePixels||0),'Repeated tracking libraries in theme or injected scripts.')+'</div>';if(data.mainTheme)h+='<div class="card"><h3>Main Theme</h3><p class="sub">'+esc(data.mainTheme.name)+' ('+esc(data.mainTheme.role)+') updated '+esc(new Date(data.mainTheme.updatedAt).toLocaleString())+'</p></div>';h+=findings(data.findings||[]);h+='<div class="card"><h3>Upgrade Candidates</h3><table><thead><tr><th>Source</th><th>Scope</th><th>Updated</th></tr></thead><tbody>';(data.upgradeCandidates||[]).forEach(function(r){h+='<tr><td>'+esc(r.src)+'</td><td>'+esc(r.displayScope||'all')+'</td><td>'+esc(r.updatedAt?new Date(r.updatedAt).toLocaleString():'—')+'</td></tr>'});if(!(data.upgradeCandidates||[]).length)h+='<tr><td colspan="3" class="sub">No ScriptTag upgrade candidates were found.</td></tr>';h+='</tbody></table></div>';h+='<div class="card"><h3>App Health Controls</h3><form onsubmit="return saveSettings(event,\\'appHealth\\')">'+switches('detectLegacyScriptTags',x.detectLegacyScriptTags,'Detect legacy ScriptTags','Flag storefront apps that still depend on ScriptTag injection.')+switches('requireThemeAppExtensions',x.requireThemeAppExtensions,'Require theme app extension patterns','Warn when the live theme does not show safe app-embed style integration.')+switches('detectDuplicatePixels',x.detectDuplicatePixels,'Detect duplicate pixels','Only surface duplicate vendors when the same library appears more than once.')+switches('reviewInlineScripts',x.reviewInlineScripts,'Review inline scripts','Inspect the main theme for direct risky JS patterns.')+switches('conservativeFlagging',x.conservativeFlagging,'Conservative flagging','Prefer fewer, higher-confidence findings over noisy alerts.')+'<p style="margin-top:14px"><button type="submit">Save App Health Settings</button></p></form></div>';panel('shopify-app-health').innerHTML=h}
async function loadMri(force){const s=needShop();if(!s)return;const key='mri:'+s;if(!force&&state.cache[key])return renderMri(state.cache[key]);loading('conversion-mri','Building conservative conversion diagnostics...');const data=await api(API+'/api/admin/conversion-mri?shop='+encodeURIComponent(s));state.cache[key]=data;renderMri(data)}
function renderMri(data){const x=data.settings.conversionMri||{},f=data.funnel||{};let h='<div class="head"><div><h2>Conversion MRI</h2><p>Conversion MRI ties funnel drop-off to conservative technical evidence. It would rather miss an issue than recommend a noisy or harmful fix path.</p></div><span class="chip '+(data.auditStatus==='critical'?'bad':data.auditStatus==='warning'?'warn':data.auditStatus==='limited'||data.auditStatus==='disconnected'?'info':'ok')+'">'+esc(data.auditStatus||'healthy')+'</span></div>';h+='<div class="grid cards">'+metric('warn','Missed conversion',pct(data.totalMissedConversionPct||0)+'%','Estimated recoverable conversion from the current evidence-backed findings.')+metric('','Product views',fmt(f.product_view||0),'Distinct profiles reaching product detail pages.')+metric('','Add to cart',fmt(f.add_to_cart||0),'Distinct profiles progressing into the cart.')+metric('','Checkout start',fmt(f.checkout_start||0),'Distinct profiles reaching checkout.')+'</div>';h+=findings(data.diagnostics||[]);h+='<div class="card"><h3>Conversion MRI Controls</h3><form onsubmit="return saveSettings(event,\\'conversionMri\\')">'+switches('conservativeMode',x.conservativeMode,'Conservative mode','Limit the report to the strongest few findings.')+switches('runAppChecks',x.runAppChecks,'App conflict checks','Include store-health findings that plausibly hurt conversion.')+switches('runContentChecks',x.runContentChecks,'Content checks','Allow PDP and cart-content friction diagnostics when ratios are clearly weak.')+switches('runAdaChecks',x.runAdaChecks,'ADA checks','Only surface layout-level accessibility issues with direct evidence.')+switches('runSeoChecks',x.runSeoChecks,'SEO checks','Inspect canonical and title output in the main layout.')+switches('runSpeedChecks',x.runSpeedChecks,'Site speed checks','Use script density and risky inline patterns in the MRI model.')+'<p style="margin-top:14px"><button type="submit">Save Conversion MRI Settings</button></p></form></div><div class="card"><p class="sub">Conversion MRI is intentionally biased toward under-reporting. Weak evidence stays out of the report.</p></div>';panel('conversion-mri').innerHTML=h}
async function saveSettings(event,section){event.preventDefault();const s=needShop();if(!s)return false;try{const fd=new FormData(event.currentTarget);const payload={shop:s};if(section==='intent'){payload.intent={sensitivity:Number(fd.get('sensitivity'))||62,includePaths:String(fd.get('includePaths')||'').split(/\\r?\\n/).filter(Boolean),rewardProductViews:fd.get('rewardProductViews')==='on',rewardCartSignals:fd.get('rewardCartSignals')==='on',rewardReturningSessions:fd.get('rewardReturningSessions')==='on',suppressBotsAndCrawlers:fd.get('suppressBotsAndCrawlers')==='on',conservativeMode:fd.get('conservativeMode')==='on'}}if(section==='appHealth'){payload.appHealth={detectLegacyScriptTags:fd.get('detectLegacyScriptTags')==='on',requireThemeAppExtensions:fd.get('requireThemeAppExtensions')==='on',detectDuplicatePixels:fd.get('detectDuplicatePixels')==='on',reviewInlineScripts:fd.get('reviewInlineScripts')==='on',conservativeFlagging:fd.get('conservativeFlagging')==='on'}}if(section==='conversionMri'){payload.conversionMri={conservativeMode:fd.get('conservativeMode')==='on',runAppChecks:fd.get('runAppChecks')==='on',runContentChecks:fd.get('runContentChecks')==='on',runAdaChecks:fd.get('runAdaChecks')==='on',runSeoChecks:fd.get('runSeoChecks')==='on',runSpeedChecks:fd.get('runSpeedChecks')==='on'}}await api(API+'/api/admin/settings',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});state.cache={};msg('Settings saved. Reloading the active tab.','success');await refreshActive(true)}catch(error){msg(error.message||'Unable to save settings.','error')}return false}
function activateTab(tab){state.tab=tab;document.querySelectorAll('.tabs button').forEach(function(b){b.classList.toggle('active',b.getAttribute('data-tab')===tab)});document.querySelectorAll('.panel').forEach(function(p){p.classList.toggle('active',p.id==='panel-'+tab)});refreshActive(false)}
async function refreshActive(force){msg('','success');const now=Date.now();const minMs=TAB_REFRESH_MS[state.tab]||60000;const last=state.lastFetch[state.tab]||0;if(!force&&now-last<minMs){return}state.lastFetch[state.tab]=now;try{if(state.tab==='bot-blocker')await loadBot(force);if(state.tab==='user-intent')await loadIntent(force);if(state.tab==='shopify-app-health')await loadHealth(force);if(state.tab==='conversion-mri')await loadMri(force)}catch(error){msg(error.message||'Unable to load data.','error')}}
window.activateTab=activateTab;window.refreshActive=refreshActive;window.saveSettings=saveSettings;window.installPixelGuard=installPixelGuard;if(document.getElementById('shopInput').value){setTimeout(function(){refreshActive(true)},180)}
<\/script>
</body>
</html>`;
}
