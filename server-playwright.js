#!/usr/bin/env node
/**
 * Enhanced Iframe Bypass Proxy Server with Playwright
 * 
 * Matches WebFuse capabilities by using a real browser engine for:
 * - Authentic TLS/HTTP2 fingerprinting
 * - JavaScript execution (Cloudflare challenges)
 * - Better bot detection evasion
 * 
 * Enables embedding websites in iframes that normally block it via:
 * - X-Frame-Options headers
 * - Content-Security-Policy frame-ancestors
 * - JavaScript frame-busters
 */

// Allow self-signed certificates
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Global error handlers
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught Exception:', err.message);
  console.error(err.stack);
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled Rejection at:', promise);
  console.error('Reason:', reason);
});

const express = require('express');
const cheerio = require('cheerio');
const { chromium } = require('playwright');
const { URL } = require('url');
const cookieModule = require('cookie');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3001;

// Browser pool for better performance
let browserPool = [];
const MAX_BROWSERS = parseInt(process.env.MAX_BROWSERS || '3', 10);
let browserIndex = 0;

// Session state
const cookieJar = new Map();
const sessionOrigins = new Map();
const sessionStartUrls = new Map();
let lastGlobalOrigin = null;

// Proxy context cookies
const PROXY_CTX_SID_COOKIE = '__proxy_sid';
const PROXY_CTX_ORIGIN_COOKIE = '__proxy_origin';

// Base domain for per-session subdomains
const PROXY_BASE_DOMAIN = process.env.PROXY_BASE_DOMAIN || '';

// Simple in-memory cache
const ASSET_CACHE_TTL_MS = parseInt(process.env.ASSET_CACHE_TTL_MS || '600000', 10);
const ASSET_CACHE_MAX_BYTES = parseInt(process.env.ASSET_CACHE_MAX_BYTES || String(50 * 1024 * 1024), 10);
const assetCache = new Map();
let assetCacheBytes = 0;

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.raw({ type: '*/*', limit: '50mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// CORS headers
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Proxy-Session');
  res.header('Access-Control-Expose-Headers', 'X-Proxy-Session');
  if (req.method === 'OPTIONS') {
    return res.sendStatus(200);
  }
  next();
});

/**
 * Initialize browser pool
 */
async function initBrowserPool() {
  console.log(`[IframeProxy] Initializing ${MAX_BROWSERS} browser instances...`);
  for (let i = 0; i < MAX_BROWSERS; i++) {
    try {
      const browser = await chromium.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-blink-features=AutomationControlled',
        ],
      });
      browserPool.push(browser);
      console.log(`[IframeProxy] Browser ${i + 1}/${MAX_BROWSERS} initialized`);
    } catch (e) {
      console.error(`[IframeProxy] Failed to init browser ${i + 1}:`, e.message);
    }
  }
  console.log(`[IframeProxy] Browser pool ready (${browserPool.length} instances)`);
}

/**
 * Get next browser from pool (round-robin)
 */
function getNextBrowser() {
  if (browserPool.length === 0) return null;
  const browser = browserPool[browserIndex];
  browserIndex = (browserIndex + 1) % browserPool.length;
  return browser;
}

/**
 * Cleanup on exit
 */
async function cleanup() {
  console.log('[IframeProxy] Shutting down...');
  for (const browser of browserPool) {
    try {
      await browser.close();
    } catch (e) {
      console.error('[IframeProxy] Error closing browser:', e.message);
    }
  }
  process.exit(0);
}

process.on('SIGINT', cleanup);
process.on('SIGTERM', cleanup);

// ... (Include all the helper functions from the original server.js)
// normalizeSessionId, getSessionId, getProxyBase, etc.

function normalizeSessionId(value) {
  if (!value) return null;
  const cleaned = String(value).toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/-+/g, '-');
  return cleaned.replace(/^-+|-+$/g, '') || null;
}

function getSessionId(req) {
  let sessionId = req.headers['x-proxy-session'];
  if (!sessionId) {
    sessionId = getSessionIdFromHost(req);
  }
  sessionId = normalizeSessionId(sessionId);
  if (!sessionId) {
    sessionId = `session-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
  }
  return sessionId;
}

function getProxyBase(req) {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

function getHostParts(req) {
  const hostHeader = (req.headers['x-forwarded-host'] || req.headers.host || '').toString();
  if (!hostHeader) return { hostname: '', port: '' };
  const [hostname, port] = hostHeader.split(':');
  return { hostname: hostname.toLowerCase(), port: port || '' };
}

function getSessionIdFromHost(req) {
  if (!PROXY_BASE_DOMAIN) return null;
  const { hostname } = getHostParts(req);
  const base = PROXY_BASE_DOMAIN.toLowerCase();
  if (!hostname || hostname === base) return null;
  if (!hostname.endsWith('.' + base)) return null;
  const prefix = hostname.slice(0, -(base.length + 1));
  return normalizeSessionId(prefix) || prefix || null;
}

function setProxyContextCookies(res, req, sessionId, origin) {
  if (!sessionId) return;
  const proto = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const secureFlag = proto === 'https' ? '; Secure' : '';
  const base = `Path=/; SameSite=Lax${secureFlag}`;
  res.append('Set-Cookie', `${PROXY_CTX_SID_COOKIE}=${encodeURIComponent(sessionId)}; ${base}`);
  if (origin) {
    res.append('Set-Cookie', `${PROXY_CTX_ORIGIN_COOKIE}=${encodeURIComponent(origin)}; ${base}`);
  }
}

function safeDecode(value) {
  if (!value) return value;
  try {
    return decodeURIComponent(value);
  } catch (e) {
    return value;
  }
}

// CDN bypass list
const CDN_PASSTHROUGH_DOMAINS = [
  'cdn.shopify.com', 'cdn.shopifycdn.net', 'images.unsplash.com',
  'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com',
  'unpkg.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com',
  '.amazonaws.com', 'storage.googleapis.com', '.cloudfront.net',
];

function shouldBypassProxy(url) {
  if (!url) return false;
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    for (const cdn of CDN_PASSTHROUGH_DOMAINS) {
      if (cdn.startsWith('.')) {
        if (hostname.endsWith(cdn)) return true;
      } else {
        if (hostname === cdn || hostname.endsWith('.' + cdn)) return true;
      }
    }
    if (urlObj.pathname.startsWith('/cdn/')) return true;
    return false;
  } catch (e) {
    return false;
  }
}

function toProxyUrl(targetUrl, proxyBase, sessionId) {
  if (!targetUrl) return targetUrl;
  if (targetUrl.includes('/proxy?') && targetUrl.includes('url=')) return targetUrl;
  if (targetUrl.startsWith('//')) targetUrl = 'https:' + targetUrl;
  if (targetUrl.startsWith('data:') || targetUrl.startsWith('javascript:') ||
      targetUrl.startsWith('mailto:') || targetUrl.startsWith('tel:') ||
      targetUrl.startsWith('blob:') || targetUrl.startsWith('#')) {
    return targetUrl;
  }
  if (shouldBypassProxy(targetUrl)) return targetUrl;
  
  try {
    const encoded = encodeURIComponent(targetUrl);
    let appendSid = true;
    if (PROXY_BASE_DOMAIN) {
      try {
        const host = new URL(proxyBase).hostname.toLowerCase();
        const base = PROXY_BASE_DOMAIN.toLowerCase();
        appendSid = host === base || !host.endsWith('.' + base);
      } catch (e) {}
    }
    return `${proxyBase}/proxy?url=${encoded}${appendSid ? `&sid=${sessionId}` : ''}`;
  } catch (e) {
    return targetUrl;
  }
}

function resolveUrl(relativeUrl, baseUrl) {
  if (!relativeUrl) return relativeUrl;
  if (relativeUrl.startsWith('http://') || relativeUrl.startsWith('https://')) return relativeUrl;
  if (relativeUrl.startsWith('//')) return 'https:' + relativeUrl;
  if (relativeUrl.startsWith('data:') || relativeUrl.startsWith('javascript:') ||
      relativeUrl.startsWith('mailto:') || relativeUrl.startsWith('tel:') ||
      relativeUrl.startsWith('#')) return relativeUrl;
  
  try {
    return new URL(relativeUrl, baseUrl).href;
  } catch (e) {
    return relativeUrl;
  }
}

// TODO: Include rewriteHtml, rewriteCss, rewriteJavaScript functions from original server.js
// For now, let me create simplified versions

function rewriteHtml(html, targetUrl, proxyBase, sessionId) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const baseUrl = targetUrl;
  
  // Remove security headers meta tags
  $('meta[http-equiv="Content-Security-Policy"]').remove();
  $('meta[http-equiv="X-Frame-Options"]').remove();
  
  // Rewrite URLs in attributes
  const urlAttrs = [
    { selector: '[href]', attr: 'href' },
    { selector: '[src]', attr: 'src' },
    { selector: '[action]', attr: 'action' },
    { selector: '[data-src]', attr: 'data-src' },
    { selector: '[poster]', attr: 'poster' },
  ];
  
  for (const { selector, attr } of urlAttrs) {
    $(selector).each((i, el) => {
      const value = $(el).attr(attr);
      if (value && !value.startsWith('data:') && !value.startsWith('javascript:')) {
        const resolved = resolveUrl(value, baseUrl);
        const proxied = toProxyUrl(resolved, proxyBase, sessionId);
        $(el).attr(attr, proxied);
      }
    });
  }
  
  // Inject frame-buster prevention script
  const scriptTag = `
    <script>
      (function() {
        try {
          if (window.top !== window.self) {
            Object.defineProperty(window, 'top', {
              get: function() { return window.self; },
              configurable: true
            });
            Object.defineProperty(window, 'parent', {
              get: function() { return window.self; },
              configurable: true
            });
          }
        } catch(e) {}
      })();
    </script>
  `;
  
  $('head').prepend(scriptTag);
  
  return $.html();
}

function rewriteCssUrls(css, targetUrl, proxyBase, sessionId) {
  const urlRegex = /url\s*\(\s*(['"]?)([^'")]+)\1\s*\)/gi;
  return css.replace(urlRegex, (match, quote, url) => {
    const trimmed = url.trim();
    if (trimmed.startsWith('data:') || trimmed.startsWith('#')) return match;
    const resolved = resolveUrl(trimmed, targetUrl);
    const proxied = toProxyUrl(resolved, proxyBase, sessionId);
    return `url(${quote}${proxied}${quote})`;
  });
}

function rewriteJavaScript(js, targetUrl, proxyBase, sessionId) {
  // Basic rewriting - can be enhanced
  return js;
}

function sanitizeResponseHeaders(headers) {
  const sanitized = {};
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    if (lowerKey === 'x-frame-options') continue;
    if (lowerKey === 'content-security-policy') continue;
    if (lowerKey === 'content-security-policy-report-only') continue;
    if (lowerKey === 'x-content-type-options') continue;
    if (lowerKey === 'cross-origin-embedder-policy') continue;
    if (lowerKey === 'cross-origin-opener-policy') continue;
    if (lowerKey === 'cross-origin-resource-policy') continue;
    sanitized[key] = value;
  }
  return sanitized;
}

/**
 * Fetch using Playwright with real browser
 */
async function fetchWithBrowser(url, options = {}) {
  const browser = getNextBrowser();
  if (!browser) {
    throw new Error('No browser available in pool');
  }
  
  const context = await browser.newContext({
    userAgent: options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
    viewport: { width: 1920, height: 1080 },
    extraHTTPHeaders: options.headers || {},
  });
  
  // Set cookies if provided
  if (options.cookies && options.cookies.length > 0) {
    await context.addCookies(options.cookies);
  }
  
  const page = await context.newPage();
  
  try {
    // Navigate and wait for network idle (handles JS challenges)
    const response = await page.goto(url, {
      waitUntil: 'networkidle',
      timeout: 30000,
    });
    
    if (!response) {
      throw new Error('No response from page.goto');
    }
    
    // Get final URL (after redirects)
    const finalUrl = page.url();
    
    // Get response headers
    const headers = await response.allHeaders();
    
    // Get cookies
    const cookies = await context.cookies();
    
    // Get content based on type
    const contentType = headers['content-type'] || '';
    let body;
    
    if (contentType.includes('text/html')) {
      body = await page.content();
    } else {
      body = await response.body();
    }
    
    await context.close();
    
    return {
      status: response.status(),
      headers,
      cookies,
      body,
      finalUrl,
      contentType,
    };
  } catch (error) {
    await context.close();
    throw error;
  }
}

/**
 * Main proxy handler with Playwright
 */
async function handleProxy(req, res) {
  const targetUrl = req.query.url;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }
  
  let decodedUrl;
  try {
    decodedUrl = decodeURIComponent(targetUrl);
    new URL(decodedUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL', details: e.message });
  }
  
  const sessionId = getSessionId(req);
  const proxyBase = getProxyBase(req);
  
  console.log(`[IframeProxy] Fetching (browser): ${decodedUrl} [session: ${sessionId}]`);
  
  try {
    // Fetch using real browser
    const response = await fetchWithBrowser(decodedUrl, {
      headers: {
        'Accept': req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      },
    });
    
    const { status, headers, cookies, body, finalUrl, contentType } = response;
    
    // Process content based on type
    let processedBody;
    if (contentType.includes('text/html')) {
      const htmlString = Buffer.isBuffer(body) ? body.toString('utf-8') : body;
      processedBody = rewriteHtml(htmlString, finalUrl, proxyBase, sessionId);
    } else if (contentType.includes('text/css')) {
      const cssString = Buffer.isBuffer(body) ? body.toString('utf-8') : body;
      processedBody = rewriteCssUrls(cssString, finalUrl, proxyBase, sessionId);
    } else if (contentType.includes('javascript')) {
      const jsString = Buffer.isBuffer(body) ? body.toString('utf-8') : body;
      processedBody = rewriteJavaScript(jsString, finalUrl, proxyBase, sessionId);
    } else {
      processedBody = body;
    }
    
    // Sanitize headers
    const sanitized = sanitizeResponseHeaders(headers);
    
    // Set response headers
    for (const [key, value] of Object.entries(sanitized)) {
      if (key.toLowerCase() !== 'content-encoding' &&
          key.toLowerCase() !== 'content-length' &&
          key.toLowerCase() !== 'transfer-encoding') {
        res.setHeader(key, value);
      }
    }
    
    res.setHeader('X-Proxy-Session', sessionId);
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    // Track origin for session
    if (contentType.includes('text/html')) {
      try {
        const targetOrigin = new URL(finalUrl).origin;
        sessionOrigins.set(sessionId, targetOrigin);
        lastGlobalOrigin = targetOrigin;
        if (!sessionStartUrls.has(sessionId)) {
          sessionStartUrls.set(sessionId, finalUrl);
        }
        setProxyContextCookies(res, req, sessionId, targetOrigin);
      } catch (e) {}
    }
    
    res.status(status);
    res.send(processedBody);
    
  } catch (error) {
    console.error('[IframeProxy] Error:', error.message);
    if (error.stack) console.error(error.stack);
    res.status(500).json({
      error: 'Proxy error',
      details: error.message || String(error),
      url: decodedUrl,
    });
  }
}

// Routes
app.get('/proxy', handleProxy);
app.post('/proxy', handleProxy);

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    browsers: browserPool.length,
    uptime: process.uptime(),
  });
});

// Start server
(async () => {
  await initBrowserPool();
  
  app.listen(PORT, () => {
    console.log(`[IframeProxy] Server running on port ${PORT}`);
    console.log(`[IframeProxy] Browser pool: ${browserPool.length} instances`);
    console.log(`[IframeProxy] Ready to proxy!`);
  });
})();
