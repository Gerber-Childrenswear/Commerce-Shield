const DAY_MS = 24 * 60 * 60 * 1000;
const DEFAULT_LOOKBACK_DAYS = 30;

export const INTENT_EVENT_RULES = {
  page_view: { weight: 1, cap: 4, halfLifeDays: 3, signal: "Page View" },
  collection_view: { weight: 2, cap: 6, halfLifeDays: 5, signal: "Collection View" },
  search: { weight: 6, cap: 12, halfLifeDays: 5, signal: "Search" },
  search_click: { weight: 5, cap: 10, halfLifeDays: 5, signal: "Search Click" },
  filter_use: { weight: 3, cap: 6, halfLifeDays: 5, signal: "Filter Use" },
  sort_use: { weight: 2, cap: 4, halfLifeDays: 5, signal: "Sort Use" },
  product_view: { weight: 6, cap: 18, halfLifeDays: 7, signal: "Product View" },
  variant_select: { weight: 6, cap: 12, halfLifeDays: 7, signal: "Variant Select" },
  media_interaction: { weight: 3, cap: 6, halfLifeDays: 7, signal: "Media Interaction" },
  size_guide_open: { weight: 3, cap: 6, halfLifeDays: 7, signal: "Size Guide" },
  review_open: { weight: 3, cap: 6, halfLifeDays: 7, signal: "Review Open" },
  scroll_depth_50: { weight: 3, cap: 3, halfLifeDays: 2, signal: "50% Scroll" },
  scroll_depth_80: { weight: 4, cap: 4, halfLifeDays: 2, signal: "80% Scroll" },
  engaged_30s: { weight: 4, cap: 4, halfLifeDays: 2, signal: "30s Engaged" },
  engaged_120s: { weight: 6, cap: 6, halfLifeDays: 2, signal: "120s Engaged" },
  add_to_cart: { weight: 20, cap: 40, halfLifeDays: 10, signal: "Add To Cart" },
  cart_view: { weight: 10, cap: 20, halfLifeDays: 10, signal: "Cart View" },
  cart_update: { weight: 4, cap: 12, halfLifeDays: 10, signal: "Cart Update" },
  checkout_start: { weight: 30, cap: 60, halfLifeDays: 14, signal: "Checkout Start" },
  email_capture: { weight: 10, cap: 10, halfLifeDays: 21, signal: "Email Capture" },
  login: { weight: 12, cap: 12, halfLifeDays: 21, signal: "Customer Login" },
  purchase: { weight: 40, cap: 40, halfLifeDays: 60, signal: "Purchase" },
};

export function mapIntentTier(score, purchasedAt) {
  if (purchasedAt || score >= 100) return "customer";
  if (score >= 85) return "purchase_ready";
  if (score >= 70) return "high_intent";
  if (score >= 50) return "considering";
  if (score >= 30) return "interested";
  if (score >= 15) return "browsing";
  return "unknown";
}

export function clampIntentScore(value) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function daysSince(now, timestamp) {
  const value = typeof timestamp === "string" ? Date.parse(timestamp) : timestamp;
  if (!Number.isFinite(value)) return DEFAULT_LOOKBACK_DAYS + 1;
  return Math.max(0, (now - value) / DAY_MS);
}

function decayedWeight(rule, now, event) {
  const ageDays = daysSince(now, event.createdAt);
  if (ageDays > DEFAULT_LOOKBACK_DAYS) return 0;
  return rule.weight * Math.pow(0.5, ageDays / rule.halfLifeDays);
}

function normalizeBotContext(botContext = {}) {
  const botScore = Number(botContext.botScore) || 0;
  const confidence = typeof botContext.confidence === "string" ? botContext.confidence : "low";
  const isBot = Boolean(botContext.isBot);
  const isLegitimate = Boolean(botContext.isLegitimate);
  const excluded = isLegitimate || (isBot && confidence === "high" && botScore >= 0.8);
  const capped = !excluded && isBot && confidence === "medium";
  return {
    isBot,
    isLegitimate,
    botScore,
    confidence,
    excluded,
    capped,
  };
}

function computeDerivedAdjustments(events, now) {
  const adjustments = [];
  const sessionIds = new Set();
  const productSessions = new Map();
  let meaningfulPageViews = 0;
  let hasCommerceSignal = false;
  let shortBounce = false;
  let discountOnlyViews = 0;
  let discountPlusCommerce = false;

  for (const event of events) {
    const type = event.eventType;
    if (event.sessionId) sessionIds.add(event.sessionId);
    if (type === "page_view" || type === "product_view" || type === "collection_view" || type === "search_click") {
      meaningfulPageViews += 1;
    }
    if (type === "add_to_cart" || type === "cart_view" || type === "cart_update" || type === "checkout_start" || type === "email_capture" || type === "login" || type === "purchase") {
      hasCommerceSignal = true;
    }
    if (type === "discount_view") {
      discountOnlyViews += 1;
    } else if (hasCommerceLikeType(type)) {
      discountPlusCommerce = true;
    }
    if (type === "product_view" && event.productId) {
      const key = event.productId;
      if (!productSessions.has(key)) productSessions.set(key, new Set());
      if (event.sessionId) productSessions.get(key).add(event.sessionId);
    }
    if (type === "session_summary") {
      const durationMs = Number(event.metadata?.durationMs) || 0;
      const pageViews = Number(event.metadata?.pageViewCount) || 0;
      const commerceSignals = Number(event.metadata?.commerceSignalCount) || 0;
      if (durationMs > 0 && durationMs < 10_000 && pageViews <= 1 && commerceSignals === 0) {
        shortBounce = true;
      }
    }
  }

  if (meaningfulPageViews >= 6) adjustments.push({ type: "deep_session", value: 6 });
  else if (meaningfulPageViews >= 3) adjustments.push({ type: "engaged_session", value: 5 });

  if (sessionIds.size >= 2) adjustments.push({ type: "repeat_session", value: 10 });

  for (const productId of productSessions.keys()) {
    const sessions = productSessions.get(productId);
    if (sessions.size >= 2) {
      adjustments.push({ type: "repeat_product_view", value: 8 });
      break;
    }
  }

  if (shortBounce) adjustments.push({ type: "short_bounce", value: -8 });

  if (discountOnlyViews >= 2 && !discountPlusCommerce) {
    adjustments.push({ type: "discount_only_scraping", value: -12 });
  }

  if (!hasCommerceSignal && meaningfulPageViews <= 1) {
    adjustments.push({ type: "weak_session", value: -5 });
  }

  return adjustments;
}

function hasCommerceLikeType(type) {
  return [
    "product_view",
    "variant_select",
    "media_interaction",
    "size_guide_open",
    "review_open",
    "add_to_cart",
    "cart_view",
    "cart_update",
    "checkout_start",
    "email_capture",
    "login",
    "purchase",
  ].includes(type);
}

function summarizeSignals(signalTotals) {
  return Object.values(signalTotals)
    .sort((left, right) => right.score - left.score)
    .slice(0, 6)
    .map((entry) => ({
      type: entry.type,
      label: entry.label,
      score: Number(entry.score.toFixed(2)),
      count: entry.count,
    }));
}

function mapIntentConfidence(score, signalTotals, botContext, purchasedAt) {
  const strongSignals = Object.values(signalTotals).filter((entry) => entry.type === "add_to_cart" || entry.type === "checkout_start" || entry.type === "purchase" || entry.type === "login" || entry.type === "email_capture");
  if (botContext.excluded || botContext.capped) return "low";
  if (purchasedAt || strongSignals.length > 0 || score >= 70) return "high";
  if (Object.keys(signalTotals).length >= 3 || score >= 30) return "medium";
  return "low";
}

export function scoreIntentProfile(events, botContextInput = {}, nowInput = Date.now()) {
  const now = typeof nowInput === "number" ? nowInput : Date.parse(nowInput);
  const botContext = normalizeBotContext(botContextInput);
  const recentEvents = events
    .filter((event) => daysSince(now, event.createdAt) <= DEFAULT_LOOKBACK_DAYS)
    .sort((left, right) => Date.parse(left.createdAt) - Date.parse(right.createdAt));

  const firstSeenAt = recentEvents[0]?.createdAt || null;
  const lastSeenAt = recentEvents[recentEvents.length - 1]?.createdAt || null;
  const purchasedAt = recentEvents.find((event) => event.eventType === "purchase")?.createdAt || null;
  const sessionCount = new Set(recentEvents.map((event) => event.sessionId).filter(Boolean)).size;

  if (!recentEvents.length || botContext.excluded) {
    return {
      intentScore: 0,
      intentTier: "unknown",
      intentConfidence: "low",
      intentSignals: [],
      sessionCount,
      firstSeenAt,
      lastSeenAt,
      purchasedAt,
      botContext,
    };
  }

  const signalTotals = {};
  let runningScore = 0;

  for (const event of recentEvents) {
    const rule = INTENT_EVENT_RULES[event.eventType];
    if (!rule) continue;

    const weighted = decayedWeight(rule, now, event);
    if (weighted <= 0) continue;

    if (!signalTotals[event.eventType]) {
      signalTotals[event.eventType] = {
        type: event.eventType,
        label: rule.signal,
        score: 0,
        count: 0,
      };
    }

    const available = Math.max(0, rule.cap - signalTotals[event.eventType].score);
    const applied = Math.min(available, weighted);
    if (applied <= 0) continue;

    signalTotals[event.eventType].score += applied;
    signalTotals[event.eventType].count += 1;
    runningScore += applied;
  }

  const derivedAdjustments = computeDerivedAdjustments(recentEvents, now);
  for (const adjustment of derivedAdjustments) {
    runningScore += adjustment.value;
    signalTotals[adjustment.type] = {
      type: adjustment.type,
      label: adjustment.type.replace(/_/g, " "),
      score: adjustment.value,
      count: 1,
    };
  }

  let intentScore = clampIntentScore(runningScore);
  if (botContext.capped) intentScore = Math.min(intentScore, 35);

  const intentTier = mapIntentTier(intentScore, purchasedAt);
  const intentConfidence = mapIntentConfidence(intentScore, signalTotals, botContext, purchasedAt);

  return {
    intentScore,
    intentTier,
    intentConfidence,
    intentSignals: summarizeSignals(signalTotals),
    sessionCount,
    firstSeenAt,
    lastSeenAt,
    purchasedAt,
    botContext,
  };
}
