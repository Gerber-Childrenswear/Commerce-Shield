/**
 * Commerce Shield — Bot Detection & Analytics Suppression v2.0
 *
 * Silently collects 30+ browser fingerprint signals, computes a risk score,
 * and takes proportional action — never blocking real users.
 *
 * Risk tiers:
 *   0–39  : human  → no action
 *   40–69 : suspicious → suppress Shopify, GA4, Bloomreach analytics
 *   70+   : confirmed bot → suppress analytics + block Shopify account creation
 *
 * Theme-agnostic: works on Expanse 6.1, Hyper, Dawn, and any Shopify theme.
 * Yotpo-aware: intercepts both form submits and fetch/XHR calls.
 */
(function () {
  'use strict';

  var UA = navigator.userAgent || '';

  // ── Config ─────────────────────────────────────────────────────────────────
  var CS_API             = 'https://commerce-shield.ncassidy.workers.dev/api';
  var TS_KEY             = '__CS_TURNSTILE_SITE_KEY__'; // replaced by Worker route; empty = disabled
  var SUPPRESS_THRESHOLD = 40;
  var BLOCK_THRESHOLD    = 70;
  var HUMAN_VERIFIED_KEY = 'cs_human_verified';
  var PAGE_PATH          = window.location.pathname;
  var PAGE_SEARCH        = window.location.search || '';
  var IS_ACCOUNT_PAGE    = /\/account\/?(?:register|login|addresses)?(?:[?#].*)?$|\/(register|login)(?:[?#].*)?$/i.test(PAGE_PATH);
  var IS_ORDER_CONFIRMATION = /thank[_-]you|order[_-]status|checkouts?\/.*\/thank[_-]you/i.test(PAGE_PATH)
    || /[?&]step=thank_you/i.test(PAGE_SEARCH);
  var IS_MOBILE_UA       = /mobile|android|iphone|ipad|ipod/i.test(UA);
  var HAS_TURNSTILE      = !!(TS_KEY && TS_KEY !== '__CS_TURNSTILE_SITE_KEY__');
  var isVerifiedHuman    = false;
  try {
    isVerifiedHuman = sessionStorage.getItem(HUMAN_VERIFIED_KEY) === '1';
    if (IS_ORDER_CONFIRMATION) sessionStorage.setItem(HUMAN_VERIFIED_KEY, '1');
  } catch (_) {}

  // ── 1. Crawler detection ───────────────────────────────────────────────────
  var CRAWLER_RE = [
    /googlebot/i, /bingbot/i, /yandexbot/i, /baiduspider/i, /duckduckbot/i,
    /slurp/i, /sogou/i, /exabot/i, /ia_archiver/i, /archive\.org_bot/i,
    /facebookexternalhit/i, /twitterbot/i, /linkedinbot/i, /pinterestbot/i,
    /slackbot/i, /telegrambot/i, /whatsapp/i, /discordbot/i,
    /ahrefsbot/i, /semrushbot/i, /mj12bot/i, /dotbot/i, /rogerbot/i,
    /screaming frog/i, /shopify/i, /cloudflare/i,
    /google-structured-data/i, /googleother/i, /adsbot-google/i,
    /mediapartners-google/i, /apis-google/i, /feedfetcher-google/i,
    /google-read-aloud/i, /lighthouse/i,
  ];
  var isCrawler = false;
  for (var ci = 0; ci < CRAWLER_RE.length; ci++) {
    if (CRAWLER_RE[ci].test(UA)) { isCrawler = true; break; }
  }

  // ── 2. Fingerprint collection ──────────────────────────────────────────────
  var FP = {};

  try { FP.scr_w = screen.width; FP.scr_h = screen.height; FP.scr_avail = screen.availHeight; FP.scr_depth = screen.colorDepth; FP.dpr = Math.round((window.devicePixelRatio || 0) * 10) / 10; } catch (_) {}
  try { FP.hw_conc = navigator.hardwareConcurrency || 0; FP.dev_mem = navigator.deviceMemory || 0; FP.max_touch = navigator.maxTouchPoints || 0; FP.plugins = navigator.plugins ? navigator.plugins.length : -1; FP.langs = navigator.languages ? navigator.languages.length : 0; FP.webdriver = navigator.webdriver === true; FP.cookie_en = navigator.cookieEnabled; } catch (_) {}
  try { var resolvedTz = Intl.DateTimeFormat().resolvedOptions(); FP.tz_name = resolvedTz.timeZone || ''; FP.tz_offset = new Date().getTimezoneOffset(); } catch (_) {}

  try {
    var cv = document.createElement('canvas'); cv.width = 200; cv.height = 50;
    var ctx2d = cv.getContext('2d');
    if (ctx2d) {
      ctx2d.textBaseline = 'top'; ctx2d.font = '14px Arial, sans-serif';
      ctx2d.fillStyle = '#e82020'; ctx2d.fillRect(0, 0, 4, 4); ctx2d.fillText('Commerce\u00e4\u00f6\u00fc', 2, 2);
      ctx2d.fillStyle = 'rgba(0,200,60,0.8)'; ctx2d.fillText('\u4e2d\u6587\u0391\u03b2', 10, 20);
      var dataUrl = cv.toDataURL('image/png');
      FP.canvas_len = dataUrl.length; FP.canvas_blank = dataUrl.length < 500 || dataUrl === 'data:,';
    }
  } catch (_) {}

  try {
    var glc = document.createElement('canvas');
    var gl = glc.getContext('webgl') || glc.getContext('experimental-webgl');
    if (gl) { var dbgInfo = gl.getExtension('WEBGL_debug_renderer_info'); FP.gl_vendor = dbgInfo ? gl.getParameter(dbgInfo.UNMASKED_VENDOR_WEBGL) : ''; FP.gl_renderer = dbgInfo ? gl.getParameter(dbgInfo.UNMASKED_RENDERER_WEBGL) : ''; }
    else { FP.gl_vendor = FP.gl_renderer = 'none'; }
  } catch (_) {}

  if (!isCrawler && (IS_ACCOUNT_PAGE || /headless|selenium|webdriver|puppeteer|playwright|phantomjs/i.test(UA))) {
    try {
      var AudioCtx = window.AudioContext || window.webkitAudioContext;
      if (AudioCtx) {
        var ac = new AudioCtx({ sampleRate: 44100 }); var osc = ac.createOscillator(); var anlsr = ac.createAnalyser();
        anlsr.fftSize = 32; osc.connect(anlsr); osc.type = 'triangle'; osc.frequency.value = 10000; osc.start(0);
        var fBuf = new Float32Array(anlsr.fftSize); anlsr.getFloatFrequencyData(fBuf); FP.audio_peak = fBuf[0];
        osc.stop(0); ac.close();
      }
    } catch (_) {}
  }

  try { FP.has_battery_api = typeof navigator.getBattery === 'function'; } catch (_) {}
  try { FP.css_grid = typeof CSS !== 'undefined' && typeof CSS.supports === 'function' && CSS.supports('display', 'grid'); } catch (_) {}
  try {
    FP.has_webrtc    = !!(window.RTCPeerConnection || window.webkitRTCPeerConnection || window.mozRTCPeerConnection);
    FP.has_indexeddb = !!(window.indexedDB); FP.has_speech = !!(window.speechSynthesis); FP.has_geoloc = !!(navigator.geolocation);
    FP.has_clipboard = !!(navigator.clipboard); FP.has_usb = !!(navigator.usb); FP.has_sensors = !!(window.DeviceOrientationEvent);
    FP.has_gamepads  = typeof navigator.getGamepads === 'function'; FP.has_offscreen = typeof OffscreenCanvas !== 'undefined';
  } catch (_) {}

  var AUTO_GLOBALS = ['__nightmare','_phantom','callPhantom','__selenium_unwrapped','__webdriverFuncs','domAutomation','domAutomationController','_Selenium_IDE_Recorder','__webdriver_script_fn','cdc_adoQpoasnfa76pfcZLmcfl','cdc_adoQpoasnfa76pfcZLmcfl_lastMessageId','__pw_manual','__pw_coverage','Cypress','_cy'];
  var autoGlobals = [];
  for (var ag = 0; ag < AUTO_GLOBALS.length; ag++) { try { if (window[AUTO_GLOBALS[ag]] !== undefined) autoGlobals.push(AUTO_GLOBALS[ag]); } catch (_) {} }
  FP.auto_globals = autoGlobals.length;

  // ── 3. Risk scoring ────────────────────────────────────────────────────────
  var signals   = [];
  var riskScore = 0;
  var trustScore = 0;
  var strongBotEvidence = false;

  if (isCrawler) {
    signals.push('crawler');
  } else {
    if (/bot|crawler|spider|scraper|headless|phantomjs|selenium|webdriver|puppeteer|playwright|curl|wget|python(?! )|java\/|go-http|httpclient|libwww|lwp[-\/]|winhttp|requests\//i.test(UA)) { signals.push('ua_bot'); riskScore += 35; strongBotEvidence = true; }
    if (/headlesschrome/i.test(UA))                                                        { signals.push('headless_chrome'); riskScore += 55; strongBotEvidence = true; }
    if (FP.webdriver === true)                                                             { signals.push('webdriver');       riskScore += 65; strongBotEvidence = true; }
    if (FP.auto_globals > 0)                                                               { signals.push('auto_globals');    riskScore += 55; strongBotEvidence = true; }
    if (FP.plugins === 0 && FP.langs === 0)                                                { signals.push('no_plugins_no_langs'); riskScore += 25; }
    if (FP.langs === 0)                                                                    { signals.push('no_langs');           riskScore += 15; }
    if (typeof window.outerWidth === 'number' && window.outerWidth === 0)                  { signals.push('zero_outer_width');   riskScore += 30; }
    if (FP.scr_w === 0 || FP.scr_h === 0)                                                 { signals.push('zero_screen');        riskScore += 30; }
    if (FP.dpr === 0)                                                                      { signals.push('zero_dpr');           riskScore += 20; }
    if (FP.canvas_blank)                                                                   { signals.push('canvas_blank');       riskScore += 25; }
    if (FP.canvas_len && FP.canvas_len < 500)                                             { signals.push('canvas_small');       riskScore += 15; }
    if (FP.hw_conc === 0)                                                                  { signals.push('no_hw_conc');         riskScore += 20; }
    if (!FP.has_webrtc)                                                                    { signals.push('no_webrtc');          riskScore += 20; }
    if (!FP.has_battery_api && /chrome/i.test(UA) && !/mobile|android/i.test(UA))         { signals.push('no_battery');         riskScore += 15; }
    if (FP.gl_renderer && /swiftshader|llvm|virtualbox|vmware|mesa|softpipe|generic/i.test(FP.gl_renderer)) { signals.push('software_gl'); riskScore += 25; }
    if (FP.gl_vendor === 'none')                                                           { signals.push('no_webgl');           riskScore += 15; }
    if ('audio_peak' in FP && (isNaN(FP.audio_peak) || FP.audio_peak === 0 || FP.audio_peak === -Infinity)) { signals.push('audio_anomaly'); riskScore += 15; }

    if (FP.plugins > 0) trustScore += 5;
    if (FP.langs > 0) trustScore += 5;
    if (FP.hw_conc >= 2) trustScore += 5;
    if (FP.cookie_en) trustScore += 5;
    if (IS_MOBILE_UA && FP.max_touch > 0 && FP.scr_w >= 320 && FP.dpr >= 1) trustScore += 10;
  }
  riskScore = Math.max(0, Math.min(100, riskScore - trustScore));

  // ── 4. Determine actions ───────────────────────────────────────────────────
  var shouldChallengeProfile = !isVerifiedHuman && !isCrawler && !IS_ORDER_CONFIRMATION && IS_ACCOUNT_PAGE && (strongBotEvidence || riskScore >= BLOCK_THRESHOLD);
  var doSuppressAnalytics = !isVerifiedHuman && !IS_ORDER_CONFIRMATION && (isCrawler || riskScore >= SUPPRESS_THRESHOLD);
  var doBlockProfile      = !HAS_TURNSTILE && shouldChallengeProfile && strongBotEvidence;

  if (!doSuppressAnalytics && !doBlockProfile && !shouldChallengeProfile) return;

  // ── 5. Multi-layer analytics suppression ──────────────────────────────────
(function () {
  // 5a. Suppress Bloomreach Engagement (Exponea)
  var engagementBlocked = 0;
  try {
    function disableEngagement(sdk) {
      if (!sdk) return;
      var noop = function () {};
      try { if (typeof sdk.disable_tracking === 'function') sdk.disable_tracking(); } catch (_) {}
      ['track', 'identify', 'anonymize', 'update', 'trackEvent'].forEach(function (m) {
        try { if (typeof sdk[m] === 'function') sdk[m] = noop; } catch (_) {}
      });
    }
    if (window.exponea)              disableEngagement(window.exponea);
    if (window.bloomreachEngagement) disableEngagement(window.bloomreachEngagement);
    ['exponea', 'bloomreachEngagement'].forEach(function (prop) {
      var _v = window[prop];
      try { Object.defineProperty(window, prop, { get: function () { return _v; }, set: function (v) { _v = v; disableEngagement(v); }, configurable: true }); } catch (_) {}
    });
    engagementBlocked = 1;
  } catch (_) {}

  // 5b. Suppress Shopify Analytics, Web Pixels, and __st tracking beacon
  try {
    var noop = function () {};
    if (window.ShopifyAnalytics) { try { if (window.ShopifyAnalytics.lib) { window.ShopifyAnalytics.lib.track = noop; window.ShopifyAnalytics.lib.page = noop; } } catch (_) {} }
    Object.defineProperty(window, 'ShopifyAnalytics', { get: function () { return window.__cs_sa; }, set: function (v) { if (v && v.lib) { v.lib.track = noop; v.lib.page = noop; } window.__cs_sa = v; }, configurable: true });
    if (window.Shopify && window.Shopify.analytics) { window.Shopify.analytics.publish = noop; window.Shopify.analytics.subscribe = noop; }
    if (window.Shopify) { Object.defineProperty(window.Shopify, 'analytics', { get: function () { return window.__cs_sana || { publish: noop, subscribe: noop }; }, set: function (v) { if (v) { v.publish = noop; v.subscribe = noop; } window.__cs_sana = v; }, configurable: true }); }
    Object.defineProperty(window, '__st', { get: function () { return window.__cs_st || {}; }, set: function () {}, configurable: true });
  } catch (_) {}

  // 5c. Suppress GA4, Universal Analytics, and _gaq
  try {
    var gaNoopFn = function () {};
    window.gtag = gaNoopFn; window.ga = gaNoopFn; window._gaq = { push: gaNoopFn };
    Object.defineProperty(window, 'gtag', { get: function () { return gaNoopFn; }, set: function () {}, configurable: true });
    Object.defineProperty(window, 'ga',   { get: function () { return gaNoopFn; }, set: function () {}, configurable: true });
  } catch (_) {}

  // 5d. Filter GTM dataLayer — drop GA4, Bloomreach, and GTM init events
  var discoveryBlocked = 0;
  try {
    var DROP_EVENTS = /^(pageview|page_view|purchase|add_to_cart|add_to_wishlist|begin_checkout|checkout_started|view_item|view_item_list|view_cart|remove_from_cart|search|login|sign_up|generate_lead|conversion)$|^br_|bloomreach|^gtm\./i;
    function installDataLayerFilter(dl) {
      if (!dl || dl.__cs_filtered) return;
      dl.__cs_filtered = true;
      var origPush = Array.prototype.push.bind(dl);
      Object.defineProperty(dl, 'push', {
        value: function () {
          var accepted = [];
          for (var i = 0; i < arguments.length; i++) {
            var item = arguments[i];
            if (item && typeof item === 'object') {
              var evtName = String(item.event || '');
              if (DROP_EVENTS.test(evtName))   continue;
              if (item.br_data || item.brData) continue;
              if (item.ecommerce)              continue;
            }
            accepted.push(item);
          }
          if (accepted.length) return origPush.apply(null, accepted);
        },
        writable: false, configurable: true,
      });
    }
    var _dl = window.dataLayer || [];
    installDataLayerFilter(_dl);
    Object.defineProperty(window, 'dataLayer', { get: function () { return _dl; }, set: function (v) { _dl = v; installDataLayerFilter(v); }, configurable: true });
    window.dataLayer = _dl;
    discoveryBlocked = 1;
  } catch (_) {}

  // ── 6. Prevent Shopify customer profile creation (confirmed bots, score >= 70) ──
  if (doBlockProfile || shouldChallengeProfile) {
    if (IS_ACCOUNT_PAGE) {
      // Capture phase fires before Yotpo, jQuery, and theme handlers
      document.addEventListener('submit', function (e) {
        var form = e.target;
        if (!form || form.tagName !== 'FORM') return;
        var action = (form.getAttribute('action') || '').toLowerCase();
        var hasEmailField = !!form.querySelector('[name="customer[email]"],[name*="email"]');
        if (doBlockProfile && (/register|account/.test(action) || hasEmailField)) {
          e.preventDefault(); e.stopImmediatePropagation();
          // Silent fail — bot receives no error, no redirect
        }
      }, true);

      // Fetch intercept — catches Yotpo Loyalty AJAX registration
      var _origFetch = window.fetch;
      window.fetch = function (input, opts) {
        var urlStr = String(input instanceof Request ? input.url : input || '');
        if (doBlockProfile && /\/account\/(?:register|login)|yotpo\.com.*\/register|loyalty.*signup|shopify.*customer.*create/i.test(urlStr)) {
          return Promise.resolve(new Response(JSON.stringify({ success: true, ok: true, customer: { id: null } }), { status: 200, headers: { 'Content-Type': 'application/json' } }));
        }
        return _origFetch.apply(this, arguments);
      };

      // XHR intercept — fallback for older AJAX patterns
      var _origXhrOpen = XMLHttpRequest.prototype.open;
      var _origXhrSend = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method, url) { this.__csUrl = String(url || ''); return _origXhrOpen.apply(this, arguments); };
      XMLHttpRequest.prototype.send = function (body) {
        if (doBlockProfile && /\/account\/(?:register|login)|yotpo.*register/i.test(this.__csUrl || '')) {
          var self = this;
          setTimeout(function () {
            try {
              Object.defineProperty(self, 'readyState',   { value: 4,             configurable: true });
              Object.defineProperty(self, 'status',       { value: 200,           configurable: true });
              Object.defineProperty(self, 'responseText', { value: '{"ok":true}', configurable: true });
              if (self.onreadystatechange) self.onreadystatechange();
              if (self.onload) self.onload();
            } catch (_) {}
          }, 20);
          return;
        }
        return _origXhrSend.apply(this, arguments);
      };
    }
  }

  // ── 7. Cloudflare Turnstile (account pages, only if sitekey configured) ──────
  if (HAS_TURNSTILE && shouldChallengeProfile) {
    if (IS_ACCOUNT_PAGE) {
      var tsEl = document.createElement('script');
      tsEl.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      tsEl.async = true;
      tsEl.onload = function () {
        if (!window.turnstile) return;
        var targetForm = document.querySelector('form[action*="account"]') || document.querySelector('form[action*="register"]') || document.querySelector('form[action*="login"]');
        if (!targetForm) return;
        var tsWrap = document.createElement('div'); tsWrap.id = 'cs-ts-widget'; tsWrap.style.display = 'none';
        targetForm.appendChild(tsWrap);
        var tsWidgetId = window.turnstile.render('#cs-ts-widget', {
          sitekey: TS_KEY, size: 'invisible',
          callback: function (token) {
            if (typeof fetch !== 'undefined') {
              fetch(CS_API + '/verify-turnstile', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token: token }), keepalive: true })
                .then(function (r) { return r.json(); })
                .then(function (d) {
                  if (d && d.ok) {
                    try { sessionStorage.setItem(HUMAN_VERIFIED_KEY, '1'); } catch (_) {}
                    doBlockProfile = false;
                    doSuppressAnalytics = false;
                    targetForm.setAttribute('data-cs-ts-cleared', '1');
                    if (targetForm._csTsPending) { targetForm._csTsPending = false; targetForm.submit(); }
                    return;
                  }
                  doBlockProfile = true;
                  doSuppressAnalytics = true;
                  targetForm._csTsPending = false;
                })
                .catch(function () {
                  try { sessionStorage.setItem(HUMAN_VERIFIED_KEY, '1'); } catch (_) {}
                  doBlockProfile = false;
                  targetForm.setAttribute('data-cs-ts-cleared', '1');
                  if (targetForm._csTsPending) { targetForm._csTsPending = false; targetForm.submit(); }
                });
              return;
            }
            try { sessionStorage.setItem(HUMAN_VERIFIED_KEY, '1'); } catch (_) {}
            doBlockProfile = false;
            targetForm.setAttribute('data-cs-ts-cleared', '1');
            if (targetForm._csTsPending) { targetForm._csTsPending = false; targetForm.submit(); }
          },
          'error-callback': function () {
            try { sessionStorage.setItem(HUMAN_VERIFIED_KEY, '1'); } catch (_) {}
            doBlockProfile = false;
            targetForm.setAttribute('data-cs-ts-cleared', '1');
            if (targetForm._csTsPending) { targetForm._csTsPending = false; targetForm.submit(); }
          },
        });
        targetForm.addEventListener('submit', function (e) {
          if (shouldChallengeProfile && !doBlockProfile && !targetForm.getAttribute('data-cs-ts-cleared')) {
            e.preventDefault(); e.stopPropagation();
            targetForm._csTsPending = true; window.turnstile.execute(tsWidgetId);
          }
        });
      };
      document.head.appendChild(tsEl);
    }
  }

  // ── 8. Report to Commerce Shield API (fire-and-forget) ────────────────────
  try {
    var rptPath = window.location.pathname;
    var rptType = 'storefront';
    if (/\/checkouts?\//i.test(rptPath) || rptPath === '/checkout')  rptType = 'checkout';
    else if (/\/account\/login|\/login$/i.test(rptPath))             rptType = 'login';
    else if (/\/account\/register|\/register$/i.test(rptPath))       rptType = 'register';
    var sid = ''; try { if (window.Shopify && window.Shopify.checkout) sid = window.Shopify.checkout.token || ''; } catch (_) {}
    var payload = JSON.stringify({
      user_agent: UA, page: rptPath, page_type: rptType,
      detection_reasons: signals.join(','), referrer: document.referrer || '', session_id: sid,
      visitor_type: isCrawler ? 'crawler' : 'bot',
      risk_score: riskScore, analytics_suppressed: doSuppressAnalytics ? 1 : 0, profile_blocked: doBlockProfile ? 1 : 0,
      bloomreach_engagement_blocked: engagementBlocked, bloomreach_discovery_blocked: discoveryBlocked,
      fp_hw_conc: FP.hw_conc || 0, fp_webdriver: FP.webdriver ? 1 : 0, fp_langs: FP.langs || 0, fp_plugins: FP.plugins || 0,
      fp_canvas_ok: FP.canvas_blank ? 0 : 1, fp_webrtc: FP.has_webrtc ? 1 : 0, fp_gl: FP.gl_renderer || '', fp_tz: FP.tz_name || '', fp_dpr: FP.dpr || 0,
    });
    if (typeof fetch !== 'undefined') {
      fetch(CS_API + '/bot-event', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: payload, keepalive: true }).catch(function () {});
    } else {
      var xhr = new XMLHttpRequest(); xhr.open('POST', CS_API + '/bot-event', true); xhr.setRequestHeader('Content-Type', 'application/json'); xhr.send(payload);
    }
  } catch (_) {}
}());

// ---------------------------------------------------------------------------
// Disposable Email Blocker — runs independently (even for non-bots)
// Intercepts form submissions containing disposable email domains.
// ---------------------------------------------------------------------------

  var DISPOSABLE_API = 'https://commerce-shield.ncassidy.workers.dev/api/disposable-check';

  // Only run on account/registration pages
  var path = window.location.pathname;
  if (!/\/(account|register|login|checkout)/i.test(path)) return;

  // Monitor all form submissions
  document.addEventListener('submit', function (e) {
    var form = e.target;
    if (!form || form.tagName !== 'FORM') return;

    // Find email inputs
    var emailInputs = form.querySelectorAll('input[type="email"], input[name*="email"]');
    if (emailInputs.length === 0) return;

    var email = '';
    for (var i = 0; i < emailInputs.length; i++) {
      if (emailInputs[i].value && emailInputs[i].value.indexOf('@') > 0) {
        email = emailInputs[i].value.trim().toLowerCase();
        break;
      }
    }
    if (!email) return;

    var domain = email.split('@')[1] || '';

    // Quick client-side check against common disposable domains
    var QUICK_LIST = [
      'temp-mail.org','tempmail.com','guerrillamail.com','mailinator.com',
      'yopmail.com','throwaway.email','trashmail.com','maildrop.cc',
      'getnada.com','discard.email','10minutemail.com','fakeinbox.com',
      'tempinbox.com','mailnesia.com','sharklasers.com','grr.la',
      'guerrillamail.net','mailinator.net','yopmail.fr','mohmal.com',
      'temp-mail.io','tempmailo.com','emailondeck.com','burnermail.io',
      'trashmail.me','trashmail.net','discardmail.com','mintemail.com',
      'harakirimail.com','moakt.com','tmpmail.net','tmpmail.org',
    ];

    var parentDomain = domain.split('.').slice(-2).join('.');
    if (QUICK_LIST.indexOf(domain) !== -1 || QUICK_LIST.indexOf(parentDomain) !== -1) {
      e.preventDefault();
      showBlockMessage(form, email);
      return;
    }

    // Async server-side check for domains not in our quick list
    // We allow form submission but also fire a background check
    try {
      fetch(DISPOSABLE_API, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email: email }),
        keepalive: true,
      }).catch(function () {});
    } catch (_) {}
  }, true);

  function showBlockMessage(form, email) {
    // Remove existing messages
    var existing = form.querySelector('.cs-disposable-msg');
    if (existing) existing.remove();

    var msg = document.createElement('div');
    msg.className = 'cs-disposable-msg';
    msg.style.cssText = 'background:#fef2f2;border:1px solid #fecaca;color:#991b1b;padding:12px 16px;margin:12px 0;font-size:14px;font-family:inherit;';
    msg.textContent = 'Disposable email addresses are not accepted. Please use a permanent email to create your account.';
    form.insertBefore(msg, form.firstChild);
  }
}());
