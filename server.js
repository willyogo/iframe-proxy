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

// Track last-used origin per session (for catch-all proxying of dynamic imports)
const sessionOrigins = new Map();
let lastGlobalOrigin = null; // Fallback for requests without session

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
 * CDN domains that should load directly (no proxy needed - they allow cross-origin)
 */
const CDN_PASSTHROUGH_DOMAINS = [
  'cdn.shopify.com',
  'cdn.shopifycdn.net',
  'images.unsplash.com',
  'cloudflare-ipfs.com',
  'ipfs.io',
  'arweave.net',
  'fonts.googleapis.com',
  'fonts.gstatic.com',
  'cdnjs.cloudflare.com',
  'unpkg.com',
  'cdn.jsdelivr.net',
  'ajax.googleapis.com',
  'maxcdn.bootstrapcdn.com',
  'stackpath.bootstrapcdn.com',
  'kit.fontawesome.com',
  'use.fontawesome.com',
  'googletagmanager.com',
  'google-analytics.com',
  'facebook.net',
  'connect.facebook.net',
  'platform.twitter.com',
  'static.hotjar.com',
  'js.intercomcdn.com',
  'widget.intercom.io',
  '.amazonaws.com',
  'storage.googleapis.com',
  '.cloudfront.net',
  '.akamaized.net',
  '.fastly.net',
];

/**
 * Check if a URL should bypass the proxy (CDN/static assets)
 */
function shouldBypassProxy(url) {
  if (!url) return false;
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    
    // Check CDN domains
    for (const cdn of CDN_PASSTHROUGH_DOMAINS) {
      if (cdn.startsWith('.')) {
        // Wildcard suffix match
        if (hostname.endsWith(cdn)) return true;
      } else {
        // Exact match
        if (hostname === cdn || hostname.endsWith('.' + cdn)) return true;
      }
    }
    
    // Check for CDN subdomain patterns in same domain
    // e.g., bigshottoyshop.com/cdn/shop/...
    if (urlObj.pathname.startsWith('/cdn/')) return true;
    
    return false;
  } catch (e) {
    return false;
  }
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
      targetUrl.startsWith('blob:') ||
      targetUrl.startsWith('#')) {
    return targetUrl;
  }
  
  // Check if this URL should bypass the proxy (CDN/static assets)
  if (shouldBypassProxy(targetUrl)) {
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
  
  // Attributes that contain URLs (expanded for lazy-loading support)
  const urlAttributes = [
    { selector: '[href]', attr: 'href' },
    { selector: '[src]', attr: 'src' },
    { selector: '[action]', attr: 'action' },
    { selector: '[data-src]', attr: 'data-src' },
    { selector: '[data-href]', attr: 'data-href' },
    { selector: '[poster]', attr: 'poster' },
    { selector: '[srcset]', attr: 'srcset' },
    { selector: '[data-srcset]', attr: 'data-srcset' },
    // Lazy-loading image attributes (various frameworks)
    { selector: '[data-lazy-src]', attr: 'data-lazy-src' },
    { selector: '[data-lazy]', attr: 'data-lazy' },
    { selector: '[data-original]', attr: 'data-original' },
    { selector: '[data-image]', attr: 'data-image' },
    { selector: '[data-bg]', attr: 'data-bg' },
    { selector: '[data-background]', attr: 'data-background' },
    { selector: '[data-bg-src]', attr: 'data-bg-src' },
    { selector: '[data-full-src]', attr: 'data-full-src' },
    { selector: '[data-large-src]', attr: 'data-large-src' },
    { selector: '[data-thumb]', attr: 'data-thumb' },
    { selector: '[data-zoom-image]', attr: 'data-zoom-image' },
    { selector: '[data-hires]', attr: 'data-hires' },
    // WooCommerce / Shopify specific
    { selector: '[data-large_image]', attr: 'data-large_image' },
    { selector: '[data-src-retina]', attr: 'data-src-retina' },
    // Video
    { selector: '[data-video-src]', attr: 'data-video-src' },
    { selector: '[data-poster]', attr: 'data-poster' },
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
  
  // Rewrite <noscript> tags (cheerio treats their content as text)
  $('noscript').each((i, el) => {
    let content = $(el).html();
    if (content) {
      // Rewrite src, href, data-src attributes in noscript content
      content = content.replace(/(src|href|data-src|data-href|action|poster)=(["'])((?:\/\/|https?:\/\/)[^"']+)\2/gi, 
        (match, attr, quote, url) => {
          let resolvedUrl = url;
          if (url.startsWith('//')) {
            resolvedUrl = 'https:' + url;
          }
          const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
          return `${attr}=${quote}${proxiedUrl}${quote}`;
        }
      );
      // Also handle protocol-relative URLs without quotes (rare but possible)
      content = content.replace(/(src|href|data-src)=(\/\/[^\s>]+)/gi,
        (match, attr, url) => {
          const resolvedUrl = 'https:' + url;
          const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
          return `${attr}="${proxiedUrl}"`;
        }
      );
      $(el).html(content);
    }
  });
  
  // Inject our frame-buster prevention and navigation interception script
  const injectedScript = generateInjectedScript(targetUrl, proxyBase, sessionId);
  $('head').prepend(`<script>${injectedScript}</script>`);
  
  // Get HTML output
  let output = $.html();
  
  // Final pass: regex-based replacement for any remaining protocol-relative URLs
  // that cheerio might have missed (common with multiline attributes or edge cases)
  const urlAttrs = ['src', 'href', 'data-src', 'data-href', 'action', 'poster', 'srcset', 'data-srcset'];
  for (const attr of urlAttrs) {
    // Match attr="//..." or attr='//...'
    const regex = new RegExp(`(${attr})=(["'])(\/\/[^"']+)\\2`, 'gi');
    output = output.replace(regex, (match, attrName, quote, url) => {
      const fullUrl = 'https:' + url;
      const proxiedUrl = toProxyUrl(fullUrl, proxyBase, sessionId);
      return `${attrName}=${quote}${proxiedUrl}${quote}`;
    });
  }
  
  return output;
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
  const TARGET_URL = ${JSON.stringify(targetUrl)};
  
  // ===== PRESERVE WEB3 WALLET PROVIDERS =====
  // Store reference to ethereum provider BEFORE any modifications
  // This ensures MetaMask and other wallet extensions work
  const _originalEthereum = window.ethereum;
  const _originalWeb3 = window.web3;
  
  // Prevent frame-busting by making window.top appear to be window.self
  // but only for non-extension contexts
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
  
  // Restore ethereum provider if it was overwritten
  if (_originalEthereum && !window.ethereum) {
    window.ethereum = _originalEthereum;
  }
  if (_originalWeb3 && !window.web3) {
    window.web3 = _originalWeb3;
  }
  
  // Watch for ethereum provider injection (extensions inject after page load)
  let ethereumCheckCount = 0;
  const ethereumWatcher = setInterval(() => {
    ethereumCheckCount++;
    // MetaMask typically injects within 100ms, but give it up to 5 seconds
    if (ethereumCheckCount > 50 || window.ethereum) {
      clearInterval(ethereumWatcher);
    }
  }, 100);
  
  // ===== URL REWRITING HELPERS =====
  
  // CDN domains that load directly (no proxy needed)
  const CDN_PASSTHROUGH = [
    'cdn.shopify.com', 'cdn.shopifycdn.net', 'images.unsplash.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com',
    'unpkg.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com',
    'googletagmanager.com', 'google-analytics.com', 'facebook.net',
    '.amazonaws.com', 'storage.googleapis.com', '.cloudfront.net',
    '.akamaized.net', '.fastly.net'
  ];
  
  function shouldBypassProxy(url) {
    if (!url) return false;
    try {
      const hostname = new URL(url).hostname.toLowerCase();
      for (const cdn of CDN_PASSTHROUGH) {
        if (cdn.startsWith('.')) {
          if (hostname.endsWith(cdn)) return true;
        } else {
          if (hostname === cdn || hostname.endsWith('.' + cdn)) return true;
        }
      }
      // Also bypass /cdn/ paths on same domain
      if (new URL(url).pathname.startsWith('/cdn/')) return true;
      return false;
    } catch(e) { return false; }
  }
  
  // Helper to convert URLs to proxied URLs
  function toProxyUrl(url) {
    if (!url) return url;
    if (typeof url !== 'string') url = String(url);
    
    // Skip already-proxied URLs
    if (url.includes('/proxy?url=')) return url;
    
    // Handle relative URLs
    if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
      if (url.startsWith('/')) {
        url = TARGET_ORIGIN + url;
      } else if (!url.startsWith('data:') && !url.startsWith('javascript:') && !url.startsWith('mailto:') && !url.startsWith('tel:') && !url.startsWith('blob:') && !url.startsWith('#')) {
        // Relative path - resolve against current path
        const base = TARGET_URL.replace(/\\/[^\\/]*$/, '/');
        url = base + url;
      } else {
        return url;
      }
    }
    
    if (url.startsWith('//')) url = 'https:' + url;
    if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('tel:') || url.startsWith('blob:') || url.startsWith('#')) {
      return url;
    }
    
    // Bypass proxy for CDN URLs
    if (shouldBypassProxy(url)) return url;
    
    return PROXY_BASE + '/proxy?url=' + encodeURIComponent(url) + '&sid=' + SESSION_ID;
  }
  
  // Convert proxied URL back to original URL
  function fromProxyUrl(proxyUrl) {
    if (!proxyUrl || typeof proxyUrl !== 'string') return proxyUrl;
    const match = proxyUrl.match(/\\/proxy\\?url=([^&]+)/);
    if (match) {
      try {
        return decodeURIComponent(match[1]);
      } catch(e) {}
    }
    return proxyUrl;
  }
  
  // ===== SPA HISTORY API INTERCEPTION =====
  
  // Track the "virtual" URL the app thinks it's at
  let virtualUrl = TARGET_URL;
  
  // Store original history methods
  const origPushState = history.pushState.bind(history);
  const origReplaceState = history.replaceState.bind(history);
  
  // Helper to convert a path to a proxy-compatible path (not full URL)
  function toProxyPath(url) {
    if (!url) return url;
    
    // If it's already a full proxy URL, extract just the path part for history
    if (typeof url === 'string' && url.includes('/proxy?url=')) {
      // Keep it as-is since it's already a proxy path
      return url.startsWith('http') ? new URL(url).pathname + new URL(url).search : url;
    }
    
    // For relative paths, keep them relative to proxy
    if (typeof url === 'string') {
      if (url.startsWith('/') && !url.startsWith('//')) {
        // Absolute path - convert to proxy path
        return '/proxy?url=' + encodeURIComponent(TARGET_ORIGIN + url) + '&sid=' + SESSION_ID;
      }
      if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
        // Relative path
        const base = new URL(virtualUrl).pathname.replace(/\\/[^\\/]*$/, '/');
        return '/proxy?url=' + encodeURIComponent(TARGET_ORIGIN + base + url) + '&sid=' + SESSION_ID;
      }
      if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
        // Full URL - proxy it
        const fullUrl = url.startsWith('//') ? 'https:' + url : url;
        return '/proxy?url=' + encodeURIComponent(fullUrl) + '&sid=' + SESSION_ID;
      }
    }
    return url;
  }
  
  // Override pushState for SPA navigation
  history.pushState = function(state, title, url) {
    if (url) {
      try {
        // Resolve the virtual URL for tracking
        const resolvedUrl = new URL(url, virtualUrl).href;
        virtualUrl = resolvedUrl;
        
        // Convert to a proxy-compatible path (same origin as current doc)
        const proxyPath = toProxyPath(url);
        const enhancedState = { ...state, __virtualUrl: resolvedUrl };
        origPushState(enhancedState, title, proxyPath);
        
        window.dispatchEvent(new CustomEvent('proxy:navigate', { detail: { url: resolvedUrl } }));
      } catch(e) {
        console.warn('[IframeProxy] pushState error:', e);
        origPushState(state, title, url);
      }
    } else {
      origPushState(state, title, url);
    }
  };
  
  // Override replaceState for SPA navigation  
  history.replaceState = function(state, title, url) {
    if (url) {
      try {
        const resolvedUrl = new URL(url, virtualUrl).href;
        virtualUrl = resolvedUrl;
        
        const proxyPath = toProxyPath(url);
        const enhancedState = { ...state, __virtualUrl: resolvedUrl };
        origReplaceState(enhancedState, title, proxyPath);
      } catch(e) {
        console.warn('[IframeProxy] replaceState error:', e);
        origReplaceState(state, title, url);
      }
    } else {
      origReplaceState(state, title, url);
    }
  };
  
  // Handle popstate (back/forward navigation)
  window.addEventListener('popstate', function(e) {
    if (e.state && e.state.__virtualUrl) {
      virtualUrl = e.state.__virtualUrl;
    }
  });
  
  // ===== LOCATION INTERCEPTION =====
  
  // Override window.location.assign and replace
  const origAssign = window.location.assign.bind(window.location);
  const origReplace = window.location.replace.bind(window.location);
  
  window.location.assign = function(url) {
    origAssign(toProxyUrl(url));
  };
  
  window.location.replace = function(url) {
    origReplace(toProxyUrl(url));
  };
  
  // ===== FETCH INTERCEPTION =====
  
  const origFetch = window.fetch;
  window.fetch = function(input, init) {
    let url = input;
    if (typeof input === 'string') {
      url = toProxyUrl(input);
    } else if (input instanceof Request) {
      url = new Request(toProxyUrl(input.url), input);
    }
    
    init = init || {};
    init.credentials = init.credentials || 'include';
    
    // Don't modify headers for wallet/web3 requests
    const originalUrl = typeof input === 'string' ? input : input.url;
    const isWeb3Request = originalUrl && (
      originalUrl.includes('infura.io') ||
      originalUrl.includes('alchemy.com') ||
      originalUrl.includes('rpc.') ||
      originalUrl.includes('/rpc')
    );
    
    if (!isWeb3Request) {
      init.headers = init.headers || {};
      if (!(init.headers instanceof Headers)) {
        init.headers = new Headers(init.headers);
      }
      init.headers.set('X-Proxy-Session', SESSION_ID);
    }
    
    return origFetch(url, init);
  };
  
  // ===== XHR INTERCEPTION =====
  
  const origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this.__proxyUrl = url; // Store for later
    return origXHROpen.call(this, method, toProxyUrl(url), ...args);
  };
  
  const origXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    try {
      // Don't add header for web3 RPC requests
      const isWeb3 = this.__proxyUrl && (
        this.__proxyUrl.includes('infura.io') ||
        this.__proxyUrl.includes('alchemy.com') ||
        this.__proxyUrl.includes('rpc.')
      );
      if (!isWeb3) {
        this.setRequestHeader('X-Proxy-Session', SESSION_ID);
      }
    } catch(e) {}
    return origXHRSend.call(this, body);
  };
  
  // ===== WINDOW.OPEN INTERCEPTION =====
  
  const origOpen = window.open;
  window.open = function(url, target, features) {
    return origOpen(toProxyUrl(url), target, features);
  };
  
  // ===== FORM SUBMISSION INTERCEPTION =====
  
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form && form.tagName === 'FORM') {
      const action = form.getAttribute('action') || '';
      if (!action.includes('/proxy?url=')) {
        form.action = toProxyUrl(action || virtualUrl);
      }
    }
  }, true);
  
  // ===== LINK CLICK INTERCEPTION =====
  
  document.addEventListener('click', function(e) {
    // Don't intercept if modifier keys are pressed (new tab, etc)
    if (e.ctrlKey || e.metaKey || e.shiftKey) return;
    
    const link = e.target.closest('a[href]');
    if (link) {
      const href = link.getAttribute('href');
      // Don't intercept wallet connect links
      if (href && href.includes('metamask') || href && href.includes('walletconnect')) {
        return;
      }
      if (href && !href.startsWith('javascript:') && !href.startsWith('#') && !href.includes('/proxy?url=')) {
        e.preventDefault();
        e.stopPropagation();
        
        // Check if it's same-origin (SPA navigation) vs cross-origin
        let resolvedUrl;
        try {
          resolvedUrl = new URL(href, virtualUrl).href;
        } catch(err) {
          resolvedUrl = href;
        }
        
        // For same-origin, try to let SPA routers handle it
        const resolvedOrigin = new URL(resolvedUrl).origin;
        if (resolvedOrigin === TARGET_ORIGIN) {
          // Simulate click for SPA routers that intercept events
          const pathname = new URL(resolvedUrl).pathname + new URL(resolvedUrl).search + new URL(resolvedUrl).hash;
          
          // Try pushState first (for SPAs)
          history.pushState({}, '', pathname);
          
          // Dispatch events that SPA routers listen for
          window.dispatchEvent(new PopStateEvent('popstate', { state: {} }));
        } else {
          // Cross-origin - do full navigation
          window.location.href = toProxyUrl(resolvedUrl);
        }
      }
    }
  }, true);
  
  // ===== DYNAMIC IMAGE LOADING (MutationObserver) =====
  
  const lazyAttrs = ['data-src', 'data-lazy-src', 'data-original', 'data-bg', 'data-background', 'data-image'];
  
  function rewriteElement(el) {
    for (const attr of lazyAttrs) {
      const val = el.getAttribute(attr);
      if (val && !val.includes('/proxy?url=') && !val.startsWith('data:')) {
        el.setAttribute(attr, toProxyUrl(val));
      }
    }
    // Handle srcset
    const srcset = el.getAttribute('srcset') || el.getAttribute('data-srcset');
    if (srcset && !srcset.includes('/proxy?url=')) {
      const rewritten = srcset.split(',').map(part => {
        const [url, ...rest] = part.trim().split(/\\s+/);
        return [toProxyUrl(url), ...rest].join(' ');
      }).join(', ');
      if (el.hasAttribute('srcset')) el.setAttribute('srcset', rewritten);
      if (el.hasAttribute('data-srcset')) el.setAttribute('data-srcset', rewritten);
    }
  }
  
  // Observe DOM for dynamically added images
  const observer = new MutationObserver(function(mutations) {
    for (const mutation of mutations) {
      for (const node of mutation.addedNodes) {
        if (node.nodeType === 1) { // Element
          rewriteElement(node);
          // Also check descendants
          if (node.querySelectorAll) {
            node.querySelectorAll('img, source, [data-src], [data-lazy-src], [data-original]').forEach(rewriteElement);
          }
        }
      }
    }
  });
  
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
  
  // ===== POSTMESSAGE FORWARDING FOR WALLET EXTENSIONS =====
  
  // Don't interfere with postMessage - wallets need this
  // Just ensure the proxy doesn't break it
  
  console.log('[IframeProxy] Frame protection, SPA routing, and Web3 support active');
  console.log('[IframeProxy] Virtual URL:', virtualUrl);
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
    
    // Skip headers that prevent iframe embedding or restrict content loading
    if (lowerKey === 'x-frame-options') continue;
    // Remove CSP entirely - it causes too many issues with proxied content
    // since all URLs are rewritten to go through the proxy
    if (lowerKey === 'content-security-policy') continue;
    if (lowerKey === 'content-security-policy-report-only') continue;
    if (lowerKey === 'x-content-type-options') continue;
    // Remove cross-origin policies that might interfere
    if (lowerKey === 'cross-origin-embedder-policy') continue;
    if (lowerKey === 'cross-origin-opener-policy') continue;
    if (lowerKey === 'cross-origin-resource-policy') continue;
    
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
  
  // Track the origin for this session (for catch-all routing of dynamic imports)
  try {
    const targetOrigin = new URL(decodedUrl).origin;
    sessionOrigins.set(sessionId, targetOrigin);
    lastGlobalOrigin = targetOrigin;
  } catch (e) {}
  
  try {
    // Build request headers - make them as Chrome-like as possible
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Accept-Encoding': 'identity', // Don't accept compressed responses for easier manipulation
      // Modern Chrome headers that help pass bot detection
      'sec-ch-ua': '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
      'sec-ch-ua-mobile': '?0',
      'sec-ch-ua-platform': '"Windows"',
      'sec-fetch-dest': 'document',
      'sec-fetch-mode': 'navigate',
      'sec-fetch-site': 'none',
      'sec-fetch-user': '?1',
      'upgrade-insecure-requests': '1',
      'cache-control': 'max-age=0',
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

// Catch-all for dynamic imports (Next.js, etc.)
// Routes like /_next/static/chunks/... need to be proxied to the original site
app.use(async (req, res, next) => {
  const path = req.path;
  
  // Skip if it's a known route or static file exists
  if (path === '/' || path === '/proxy' || path === '/health' || path.startsWith('/test')) {
    return next();
  }
  
  // Try to get the origin from session or fallback
  const sessionId = req.query.sid || req.headers['x-proxy-session'];
  let targetOrigin = sessionId ? sessionOrigins.get(sessionId) : null;
  
  // Fallback to last global origin (works for single-site testing)
  if (!targetOrigin) {
    targetOrigin = lastGlobalOrigin;
  }
  
  if (!targetOrigin) {
    return res.status(404).json({ error: 'No origin context available for catch-all proxy' });
  }
  
  // Proxy this path to the target origin
  const targetUrl = targetOrigin + path + (req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '');
  
  try {
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': req.headers['accept'] || '*/*',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Referer': targetOrigin,
      'Origin': targetOrigin,
    };
    
    const response = await fetch(targetUrl, { headers, redirect: 'follow' });
    const body = await response.buffer();
    
    // Forward relevant headers
    const contentType = response.headers.get('content-type');
    if (contentType) res.setHeader('Content-Type', contentType);
    
    const cacheControl = response.headers.get('cache-control');
    if (cacheControl) res.setHeader('Cache-Control', cacheControl);
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(response.status).send(body);
    
  } catch (error) {
    console.error('[IframeProxy] Catch-all error:', targetUrl, error.message);
    res.status(500).json({ error: 'Catch-all proxy error', details: error.message });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🔓 Iframe Bypass Proxy running on http://localhost:${PORT}`);
  console.log(`📝 Usage: /proxy?url=<encoded-url>`);
  console.log(`💚 Health: /health`);
});

module.exports = app;
