-- Commerce Shield D1 Schema

CREATE TABLE IF NOT EXISTS visits (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop TEXT NOT NULL,
  is_bot INTEGER NOT NULL DEFAULT 0,
  bot_score REAL NOT NULL DEFAULT 0,
  confidence TEXT NOT NULL DEFAULT 'low',
  is_mobile INTEGER NOT NULL DEFAULT 0,
  is_legitimate INTEGER NOT NULL DEFAULT 0,
  is_coupon_bot INTEGER NOT NULL DEFAULT 0,
  source TEXT NOT NULL DEFAULT 'direct',
  page TEXT,
  ua TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS daily_stats (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop TEXT NOT NULL,
  date TEXT NOT NULL,
  total_visits INTEGER NOT NULL DEFAULT 0,
  human_visits INTEGER NOT NULL DEFAULT 0,
  bot_visits INTEGER NOT NULL DEFAULT 0,
  coupon_bots INTEGER NOT NULL DEFAULT 0,
  pixels_protected INTEGER NOT NULL DEFAULT 0,
  disposable_emails_blocked INTEGER NOT NULL DEFAULT 0,
  UNIQUE(shop, date)
);

CREATE INDEX IF NOT EXISTS idx_visits_shop_created ON visits(shop, created_at);
CREATE INDEX IF NOT EXISTS idx_daily_stats_shop_date ON daily_stats(shop, date);

CREATE TABLE IF NOT EXISTS intent_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop TEXT NOT NULL,
  visitor_key TEXT NOT NULL,
  session_id TEXT,
  event_type TEXT NOT NULL,
  page_type TEXT,
  page TEXT,
  product_id TEXT,
  customer_id TEXT,
  email_hash TEXT,
  bot_score REAL NOT NULL DEFAULT 0,
  bot_confidence TEXT NOT NULL DEFAULT 'low',
  is_bot INTEGER NOT NULL DEFAULT 0,
  is_legitimate INTEGER NOT NULL DEFAULT 0,
  metadata TEXT,
  created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS intent_profiles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  shop TEXT NOT NULL,
  visitor_key TEXT NOT NULL,
  customer_id TEXT,
  email_hash TEXT,
  intent_score INTEGER NOT NULL DEFAULT 0,
  intent_tier TEXT NOT NULL DEFAULT 'unknown',
  intent_confidence TEXT NOT NULL DEFAULT 'low',
  bot_excluded INTEGER NOT NULL DEFAULT 0,
  bot_confidence TEXT NOT NULL DEFAULT 'low',
  bot_score REAL NOT NULL DEFAULT 0,
  session_count INTEGER NOT NULL DEFAULT 0,
  signal_summary TEXT,
  first_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  last_seen_at TEXT NOT NULL DEFAULT (datetime('now')),
  purchased_at TEXT,
  updated_at TEXT NOT NULL DEFAULT (datetime('now')),
  UNIQUE(shop, visitor_key)
);

CREATE TABLE IF NOT EXISTS endpoint_nonces (
  nonce_key TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS rate_limits (
  bucket_key TEXT PRIMARY KEY,
  count INTEGER NOT NULL DEFAULT 0,
  expires_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_shop_settings (
  shop TEXT PRIMARY KEY,
  intent_settings TEXT NOT NULL DEFAULT '{}',
  app_health_settings TEXT NOT NULL DEFAULT '{}',
  conversion_mri_settings TEXT NOT NULL DEFAULT '{}',
  created_at TEXT NOT NULL DEFAULT (datetime('now')),
  updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_intent_events_shop_visitor_created ON intent_events(shop, visitor_key, created_at);
CREATE INDEX IF NOT EXISTS idx_intent_profiles_shop_email ON intent_profiles(shop, email_hash);
CREATE INDEX IF NOT EXISTS idx_intent_profiles_shop_customer ON intent_profiles(shop, customer_id);

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
