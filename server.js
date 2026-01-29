#!/usr/bin/env node
/**
 * Iframe Bypass Proxy Server
 * 
 * Enables embedding websites in iframes that normally block it via:
 * - X-Frame-Options headers
 * - Content-Security-Policy frame-ancestors
 * - JavaScript frame-busters
 * 
 * API:
 *   GET  /proxy?url=<encoded-url>  - Fetch and proxy a URL
 *   POST /proxy?url=<encoded-url>  - Proxy form submissions
 *   GET  /health                   - Health check
 */

const express = require('express');
const cheerio = require('cheerio');
const fetch = require('node-fetch');
const { URL } = require('url');
const cookieModule = require('cookie');

const app = express();
const PORT = process.env.PORT || 3001;

// Store cookies per session (keyed by a session ID we generate)
const cookieJar = new Map();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.raw({ type: '*/*', limit: '50mb' }));

// Serve static files from public directory
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// CORS headers for the proxy itself
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
 * Get or create a session ID for cookie isolation
 */
function getSessionId(req) {
  let sessionId = req.headers['x-proxy-session'];
  if (!sessionId) {
    sessionId = `session_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  }
  return sessionId;
}

/**
 * Get the proxy base URL (for rewriting)
 */
function getProxyBase(req) {
  const protocol = req.headers['x-forwarded-proto'] || req.protocol || 'http';
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  return `${protocol}://${host}`;
}

/**
 * Convert a target URL to a proxied URL
 */
function toProxyUrl(targetUrl, proxyBase, sessionId) {
  if (!targetUrl) return targetUrl;
  
  // Handle protocol-relative URLs
  if (targetUrl.startsWith('//')) {
    targetUrl = 'https:' + targetUrl;
  }
  
  // Skip data: and javascript: URLs
  if (targetUrl.startsWith('data:') || 
      targetUrl.startsWith('javascript:') ||
      targetUrl.startsWith('mailto:') ||
      targetUrl.startsWith('tel:') ||
      targetUrl.startsWith('#')) {
    return targetUrl;
  }
  
  try {
    const encoded = encodeURIComponent(targetUrl);
    return `${proxyBase}/proxy?url=${encoded}&sid=${sessionId}`;
  } catch (e) {
    return targetUrl;
  }
}

/**
 * Resolve a relative URL against a base URL
 */
function resolveUrl(relativeUrl, baseUrl) {
  if (!relativeUrl) return relativeUrl;
  
  // Already absolute
  if (relativeUrl.startsWith('http://') || relativeUrl.startsWith('https://')) {
    return relativeUrl;
  }
  
  // Protocol-relative
  if (relativeUrl.startsWith('//')) {
    return 'https:' + relativeUrl;
  }
  
  // Skip special URLs
  if (relativeUrl.startsWith('data:') || 
      relativeUrl.startsWith('javascript:') ||
      relativeUrl.startsWith('mailto:') ||
      relativeUrl.startsWith('tel:') ||
      relativeUrl.startsWith('#')) {
    return relativeUrl;
  }
  
  try {
    return new URL(relativeUrl, baseUrl).href;
  } catch (e) {
    return relativeUrl;
  }
}

/**
 * Rewrite URLs in HTML content
 */
function rewriteHtml(html, targetUrl, proxyBase, sessionId) {
  const $ = cheerio.load(html, { decodeEntities: false });
  const baseUrl = targetUrl;
  
  // Get base tag if present
  const baseTag = $('base').attr('href');
  const effectiveBase = baseTag ? resolveUrl(baseTag, targetUrl) : targetUrl;
  
  // Remove existing base tag (we'll handle URLs ourselves)
  $('base').remove();
  
  // Attributes that contain URLs
  const urlAttributes = [
    { selector: '[href]', attr: 'href' },
    { selector: '[src]', attr: 'src' },
    { selector: '[action]', attr: 'action' },
    { selector: '[data-src]', attr: 'data-src' },
    { selector: '[data-href]', attr: 'data-href' },
    { selector: '[poster]', attr: 'poster' },
    { selector: '[srcset]', attr: 'srcset' },
    { selector: '[data-srcset]', attr: 'data-srcset' },
  ];
  
  for (const { selector, attr } of urlAttributes) {
    $(selector).each((i, el) => {
      const value = $(el).attr(attr);
      if (!value) return;
      
      // Handle srcset specially (comma-separated list of URLs with descriptors)
      if (attr === 'srcset' || attr === 'data-srcset') {
        const rewritten = value.split(',').map(part => {
          const [url, ...descriptor] = part.trim().split(/\s+/);
          const resolvedUrl = resolveUrl(url, effectiveBase);
          const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
          return [proxiedUrl, ...descriptor].join(' ');
        }).join(', ');
        $(el).attr(attr, rewritten);
      } else {
        const resolvedUrl = resolveUrl(value, effectiveBase);
        const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
        $(el).attr(attr, proxiedUrl);
      }
    });
  }
  
  // Rewrite inline styles with url()
  $('[style]').each((i, el) => {
    const style = $(el).attr('style');
    if (style && style.includes('url(')) {
      const rewritten = rewriteCssUrls(style, effectiveBase, proxyBase, sessionId);
      $(el).attr(style, rewritten);
    }
  });
  
  // Rewrite <style> tags
  $('style').each((i, el) => {
    const css = $(el).html();
    if (css) {
      $(el).html(rewriteCssUrls(css, effectiveBase, proxyBase, sessionId));
    }
  });
  
  // Inject our frame-buster prevention and navigation interception script
  const injectedScript = generateInjectedScript(targetUrl, proxyBase, sessionId);
  $('head').prepend(`<script>${injectedScript}</script>`);
  
  return $.html();
}

/**
 * Rewrite url() references in CSS
 */
function rewriteCssUrls(css, baseUrl, proxyBase, sessionId) {
  return css.replace(/url\s*\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (match, quote, url) => {
    const trimmedUrl = url.trim();
    if (trimmedUrl.startsWith('data:')) {
      return match;
    }
    const resolvedUrl = resolveUrl(trimmedUrl, baseUrl);
    const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
    return `url(${quote}${proxiedUrl}${quote})`;
  });
}

/**
 * Generate JavaScript to inject into the page for frame-buster prevention
 * and navigation interception
 */
function generateInjectedScript(targetUrl, proxyBase, sessionId) {
  return `
(function() {
  'use strict';
  
  const PROXY_BASE = ${JSON.stringify(proxyBase)};
  const SESSION_ID = ${JSON.stringify(sessionId)};
  const TARGET_ORIGIN = ${JSON.stringify(new URL(targetUrl).origin)};
  
  // Prevent frame-busting by making window.top appear to be window.self
  try {
    if (window.top !== window.self) {
      Object.defineProperty(window, 'top', {
        get: function() { return window.self; }
      });
      Object.defineProperty(window, 'parent', {
        get: function() { return window.self; }
      });
    }
  } catch(e) {}
  
  // Helper to convert URLs to proxied URLs
  function toProxyUrl(url) {
    if (!url) return url;
    if (typeof url !== 'string') url = String(url);
    
    // Handle relative URLs
    if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
      if (url.startsWith('/')) {
        url = TARGET_ORIGIN + url;
      } else if (!url.startsWith('data:') && !url.startsWith('javascript:') && !url.startsWith('mailto:') && !url.startsWith('#')) {
        url = TARGET_ORIGIN + '/' + url;
      } else {
        return url;
      }
    }
    
    if (url.startsWith('//')) url = 'https:' + url;
    if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('#')) {
      return url;
    }
    
    return PROXY_BASE + '/proxy?url=' + encodeURIComponent(url) + '&sid=' + SESSION_ID;
  }
  
  // Intercept location changes
  const locationHandler = {
    set: function(target, prop, value) {
      if (prop === 'href' || prop === 'pathname' || prop === 'search' || prop === 'hash') {
        const newUrl = prop === 'href' ? value : target.href.replace(target[prop], value);
        window.location.href = toProxyUrl(newUrl);
        return true;
      }
      return Reflect.set(target, prop, value);
    }
  };
  
  // Override window.location.assign and replace
  const origAssign = window.location.assign.bind(window.location);
  const origReplace = window.location.replace.bind(window.location);
  
  window.location.assign = function(url) {
    origAssign(toProxyUrl(url));
  };
  
  window.location.replace = function(url) {
    origReplace(toProxyUrl(url));
  };
  
  // Intercept fetch
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    if (typeof input === 'string') {
      input = toProxyUrl(input);
    } else if (input instanceof Request) {
      input = new Request(toProxyUrl(input.url), input);
    }
    
    init = init || {};
    init.credentials = init.credentials || 'include';
    init.headers = init.headers || {};
    if (!(init.headers instanceof Headers)) {
      init.headers = new Headers(init.headers);
    }
    init.headers.set('X-Proxy-Session', SESSION_ID);
    
    return origFetch(input, init);
  };
  
  // Intercept XMLHttpRequest
  const origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    return origXHROpen.call(this, method, toProxyUrl(url), ...args);
  };
  
  const origXHRSetHeader = XMLHttpRequest.prototype.setRequestHeader;
  XMLHttpRequest.prototype.setRequestHeader = function(name, value) {
    origXHRSetHeader.call(this, name, value);
  };
  
  const origXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    try {
      this.setRequestHeader('X-Proxy-Session', SESSION_ID);
    } catch(e) {}
    return origXHRSend.call(this, body);
  };
  
  // Intercept window.open
  const origOpen = window.open;
  window.open = function(url, target, features) {
    return origOpen(toProxyUrl(url), target, features);
  };
  
  // Intercept form submissions
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form && form.action) {
      const action = form.getAttribute('action') || '';
      if (!action.includes('/proxy?url=')) {
        form.action = toProxyUrl(action || window.location.href);
      }
    }
  }, true);
  
  // Intercept click on links (for dynamically created links)
  document.addEventListener('click', function(e) {
    const link = e.target.closest('a[href]');
    if (link) {
      const href = link.getAttribute('href');
      if (href && !href.startsWith('javascript:') && !href.startsWith('#') && !href.includes('/proxy?url=')) {
        e.preventDefault();
        window.location.href = toProxyUrl(href);
      }
    }
  }, true);
  
  console.log('[IframeProxy] Frame protection and navigation interception active');
})();
`;
}

/**
 * Strip/modify headers that prevent iframe embedding
 */
function sanitizeResponseHeaders(headers) {
  const sanitized = {};
  
  for (const [key, value] of Object.entries(headers)) {
    const lowerKey = key.toLowerCase();
    
    // Skip headers that prevent iframe embedding
    if (lowerKey === 'x-frame-options') continue;
    if (lowerKey === 'content-security-policy') {
      // Remove frame-ancestors and adjust other directives
      let csp = value;
      csp = csp.replace(/frame-ancestors[^;]*(;|$)/gi, '');
      // Also relax script-src to allow our injected script
      if (!csp.includes("'unsafe-inline'")) {
        csp = csp.replace(/script-src/gi, "script-src 'unsafe-inline'");
      }
      if (csp.trim()) {
        sanitized['content-security-policy'] = csp;
      }
      continue;
    }
    if (lowerKey === 'content-security-policy-report-only') continue;
    if (lowerKey === 'x-content-type-options') continue;
    
    // Keep other headers
    sanitized[key] = value;
  }
  
  return sanitized;
}

/**
 * Get stored cookies for a target domain
 */
function getCookiesForDomain(sessionId, targetUrl) {
  const key = `${sessionId}:${new URL(targetUrl).hostname}`;
  return cookieJar.get(key) || {};
}

/**
 * Store cookies from response
 */
function storeCookies(sessionId, targetUrl, setCookieHeaders) {
  if (!setCookieHeaders) return;
  
  const key = `${sessionId}:${new URL(targetUrl).hostname}`;
  const existing = cookieJar.get(key) || {};
  
  const cookies = Array.isArray(setCookieHeaders) ? setCookieHeaders : [setCookieHeaders];
  for (const cookie of cookies) {
    const parsed = cookieModule.parse(cookie.split(';')[0]);
    Object.assign(existing, parsed);
  }
  
  cookieJar.set(key, existing);
}

/**
 * Format cookies for request
 */
function formatCookies(cookies) {
  return Object.entries(cookies)
    .map(([k, v]) => `${k}=${v}`)
    .join('; ');
}

/**
 * Main proxy handler
 */
async function handleProxy(req, res) {
  const targetUrl = req.query.url;
  
  if (!targetUrl) {
    return res.status(400).json({ error: 'Missing url parameter' });
  }
  
  let decodedUrl;
  try {
    decodedUrl = decodeURIComponent(targetUrl);
    new URL(decodedUrl); // Validate URL
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL', details: e.message });
  }
  
  const sessionId = req.query.sid || getSessionId(req);
  const proxyBase = getProxyBase(req);
  
  try {
    // Build request headers
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
      'Accept': req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.5',
      'Accept-Encoding': 'identity', // Don't accept compressed responses for easier manipulation
    };
    
    // Add cookies
    const storedCookies = getCookiesForDomain(sessionId, decodedUrl);
    if (Object.keys(storedCookies).length > 0) {
      headers['Cookie'] = formatCookies(storedCookies);
    }
    
    // Forward referer as the target origin
    headers['Referer'] = new URL(decodedUrl).origin;
    headers['Origin'] = new URL(decodedUrl).origin;
    
    // Build fetch options
    const fetchOptions = {
      method: req.method,
      headers,
      redirect: 'follow',
    };
    
    // Handle POST body
    if (req.method === 'POST') {
      if (req.is('application/x-www-form-urlencoded')) {
        fetchOptions.body = new URLSearchParams(req.body).toString();
        headers['Content-Type'] = 'application/x-www-form-urlencoded';
      } else if (req.is('application/json')) {
        fetchOptions.body = JSON.stringify(req.body);
        headers['Content-Type'] = 'application/json';
      } else if (Buffer.isBuffer(req.body)) {
        fetchOptions.body = req.body;
        if (req.headers['content-type']) {
          headers['Content-Type'] = req.headers['content-type'];
        }
      }
    }
    
    // Fetch the target URL
    const response = await fetch(decodedUrl, fetchOptions);
    
    // Store any cookies from the response
    const setCookieHeader = response.headers.raw()['set-cookie'];
    if (setCookieHeader) {
      storeCookies(sessionId, decodedUrl, setCookieHeader);
    }
    
    // Get content type
    const contentType = response.headers.get('content-type') || '';
    
    // Get response body
    let body;
    if (contentType.includes('text/html')) {
      const html = await response.text();
      body = rewriteHtml(html, decodedUrl, proxyBase, sessionId);
    } else if (contentType.includes('text/css')) {
      const css = await response.text();
      body = rewriteCssUrls(css, decodedUrl, proxyBase, sessionId);
    } else if (contentType.includes('javascript') || contentType.includes('application/json')) {
      // For JS/JSON, we pass through as-is (our injected script handles dynamic URLs)
      body = await response.buffer();
    } else {
      // Binary content (images, fonts, etc.) - pass through
      body = await response.buffer();
    }
    
    // Sanitize and set response headers
    const responseHeaders = {};
    response.headers.forEach((value, key) => {
      responseHeaders[key] = value;
    });
    
    const sanitizedHeaders = sanitizeResponseHeaders(responseHeaders);
    
    for (const [key, value] of Object.entries(sanitizedHeaders)) {
      if (key.toLowerCase() !== 'content-encoding' && 
          key.toLowerCase() !== 'content-length' &&
          key.toLowerCase() !== 'transfer-encoding') {
        res.setHeader(key, value);
      }
    }
    
    // Always set these headers
    res.setHeader('X-Proxy-Session', sessionId);
    res.setHeader('Access-Control-Allow-Origin', '*');
    
    res.status(response.status);
    res.send(body);
    
  } catch (error) {
    console.error('[IframeProxy] Error fetching:', decodedUrl, error.message);
    res.status(500).json({ 
      error: 'Proxy error', 
      details: error.message,
      url: decodedUrl 
    });
  }
}

// Routes
app.get('/proxy', handleProxy);
app.post('/proxy', handleProxy);

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/', (req, res) => {
  res.json({
    name: 'Iframe Bypass Proxy',
    version: '1.0.0',
    usage: {
      proxy: 'GET /proxy?url=<encoded-url>',
      health: 'GET /health'
    },
    example: `/proxy?url=${encodeURIComponent('https://example.com')}`
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🔓 Iframe Bypass Proxy running on http://localhost:${PORT}`);
  console.log(`📝 Usage: /proxy?url=<encoded-url>`);
  console.log(`💚 Health: /health`);
});

module.exports = app;
