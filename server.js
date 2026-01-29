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

// Allow self-signed certificates (necessary for proxy functionality)
// This is safe for a local proxy that's just fetching content
process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';

// Global error handlers to prevent crashes
process.on('uncaughtException', (err) => {
  console.error('[FATAL] Uncaught Exception:', err.message);
  console.error(err.stack);
  // Don't exit - try to keep running
});

process.on('unhandledRejection', (reason, promise) => {
  console.error('[FATAL] Unhandled Rejection at:', promise);
  console.error('Reason:', reason);
  // Don't exit - try to keep running
});

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

// Proxy context cookies (help route same-origin subresource requests)
const PROXY_CTX_SID_COOKIE = '__proxy_sid';
const PROXY_CTX_ORIGIN_COOKIE = '__proxy_origin';

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

function safeDecode(value) {
  if (!value) return value;
  try {
    return decodeURIComponent(value);
  } catch (e) {
    return value;
  }
}

function getProxyContextFromCookies(req) {
  const raw = req.headers['cookie'] || '';
  if (!raw) return {};
  const parsed = cookieModule.parse(raw);
  return {
    sid: safeDecode(parsed[PROXY_CTX_SID_COOKIE]),
    origin: safeDecode(parsed[PROXY_CTX_ORIGIN_COOKIE]),
  };
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

/**
 * Determine whether an incoming request is a top-level document navigation.
 * Use fetch metadata where possible; fall back only when headers are missing.
 */
function isTopLevelNavigation(req) {
  const accept = (req.headers['accept'] || '').toLowerCase();
  const dest = (req.headers['sec-fetch-dest'] || '').toLowerCase();
  const mode = (req.headers['sec-fetch-mode'] || '').toLowerCase();
  const user = (req.headers['sec-fetch-user'] || '').toLowerCase();
  const hasFetchMeta = Boolean(dest || mode || user);
  
  if (dest === 'document' || mode === 'navigate' || user === '?1') return true;
  
  // Conservative fallback when metadata is missing
  if (!hasFetchMeta && req.method === 'GET') {
    if (accept.includes('text/html') || accept.includes('application/xhtml+xml')) return true;
  }
  
  return false;
}

/**
 * Unwrap a proxied URL back to its original target (handles nested proxy URLs)
 */
function unwrapProxyUrl(possibleUrl, proxyBase) {
  if (!possibleUrl) return possibleUrl;
  let current = possibleUrl;
  let guard = 0;
  let proxyOrigin;
  try {
    proxyOrigin = new URL(proxyBase).origin;
  } catch (e) {
    return possibleUrl;
  }
  while (guard < 3) {
    guard++;
    try {
      const u = new URL(current);
      if (u.origin !== proxyOrigin || !u.pathname.endsWith('/proxy')) break;
      const raw = u.searchParams.get('url');
      if (!raw) break;
      let next = raw;
      try {
        next = decodeURIComponent(raw);
      } catch (e) {
        // Keep raw if decode fails
      }
      current = next;
      continue;
    } catch (e) {
      break;
    }
  }
  return current;
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
  'cdn-global.configcat.com',
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
  
  // Avoid double-proxying
  if (targetUrl.includes('/proxy?') && targetUrl.includes('url=')) {
    return targetUrl;
  }
  
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
  const targetOrigin = new URL(targetUrl).origin;
  
  // Get base tag if present
  const baseTag = $('base').attr('href');
  const effectiveBase = baseTag ? resolveUrl(baseTag, targetUrl) : targetUrl;
  
  // Remove existing base tag (we'll handle URLs ourselves)
  $('base').remove();
  
  // Rewrite anchor links separately to preserve SPA routing for same-origin
  $('a[href], area[href]').each((i, el) => {
    const value = $(el).attr('href');
    if (!value) return;
    const trimmed = value.trim();
    if (!trimmed || 
        trimmed.startsWith('#') || 
        trimmed.startsWith('javascript:') ||
        trimmed.startsWith('mailto:') ||
        trimmed.startsWith('tel:')) {
      return;
    }
    
    // Already proxied
    if (trimmed.includes('/proxy?') && trimmed.includes('url=')) return;
    
    const resolvedUrl = resolveUrl(trimmed, effectiveBase);
    try {
      const resolved = new URL(resolvedUrl);
      if (resolved.origin === targetOrigin) {
        const relative = `${resolved.pathname}${resolved.search}${resolved.hash}`;
        $(el).attr('href', relative || '/');
        return;
      }
    } catch (e) {
      // Fall through to proxying
    }
    
    const proxiedUrl = toProxyUrl(resolvedUrl, proxyBase, sessionId);
    $(el).attr('href', proxiedUrl);
  });
  
  // Attributes that contain URLs (expanded for lazy-loading support)
  const urlAttributes = [
    { selector: '[href]:not(a):not(area)', attr: 'href' },
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
  // We need to ensure it runs BEFORE any other JavaScript, including inline scripts
  const injectedScript = generateInjectedScript(targetUrl, proxyBase, sessionId);
  
  // Get HTML output first
  let output = $.html();
  
  // Now inject our script at the VERY beginning of the document
  // This ensures it runs before any other scripts, even those that capture fetch
  // We inject it before the <!DOCTYPE> or <html> tag if possible
  const scriptTag = `<script data-proxy-injected="true">${injectedScript}</script>`;
  
  // Find the best injection point - before <html> or at very start
  const htmlMatch = output.match(/(<html[^>]*>)/i);
  if (htmlMatch) {
    const htmlPos = output.indexOf(htmlMatch[0]);
    output = output.slice(0, htmlPos + htmlMatch[0].length) + scriptTag + output.slice(htmlPos + htmlMatch[0].length);
  } else {
    // Fallback: prepend to document
    output = scriptTag + output;
  }
  
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
 * Rewrite JavaScript to intercept fetch calls and route them through proxy
 * This handles bundled code that captures fetch in module scope
 */
function rewriteJavaScript(js, baseUrl, proxyBase, sessionId) {
  const targetOrigin = new URL(baseUrl).origin;
  
  // Inject a wrapper at the beginning that provides proxied fetch
  // This wrapper also captures fetch before any other code can
  const wrapper = `
;(function(){
  var g = (typeof window !== 'undefined' ? window : (typeof self !== 'undefined' ? self : globalThis));
  if(!g || !g.fetch) return;
  if(g.__proxyFetchInstalled)return;
  g.__proxyFetchInstalled=true;
  var _origFetch=g.fetch.bind(g);
  var PROXY_BASE=${JSON.stringify(proxyBase)};
  var SID=${JSON.stringify(sessionId)};
  var TARGET_ORIGIN=${JSON.stringify(targetOrigin)};
  var RPC_DOMAINS=['infura.io','alchemy.com','quicknode.com','ankr.com','flashbots.net'];
  
  function isRpcDomain(u){
    for(var i=0;i<RPC_DOMAINS.length;i++){
      if(u.indexOf(RPC_DOMAINS[i])!==-1)return true;
    }
    return false;
  }
  
  function proxyUrl(u){
    if(!u||typeof u!=='string')return u;
    if((u.indexOf(PROXY_BASE+'/proxy?')===0||u.indexOf('/proxy?')===0)&&u.indexOf('url=')!==-1)return u;
    if(u.indexOf('data:')===0||u.indexOf('blob:')===0)return u;
    if(isRpcDomain(u))return u;
    var full=u;
    if(u.indexOf('//')===0)full='https:'+u;
    else if(u.indexOf('http')!==0){
      try{
        var base=(g.__proxyVirtualUrl|| (g.location&&g.location.href) || (TARGET_ORIGIN+'/'));
        full=new URL(u,base).href;
      }catch(e){
        return u;
      }
    }
    // If URL points to proxy origin, remap to target origin
    try{
      var pbase=new URL(PROXY_BASE);
      var uo=new URL(full, pbase.origin);
      if(uo.origin===pbase.origin){
        var remap=new URL(TARGET_ORIGIN);
        remap.pathname=uo.pathname;
        remap.search=uo.search;
        remap.hash=uo.hash;
        full=remap.href;
      }
    }catch(e){}
    return PROXY_BASE+'/proxy?url='+encodeURIComponent(full)+'&sid='+SID;
  }
  
  // Create a proxy fetch function
  function proxyFetch(input,init){
    var url=typeof input==='string'?input:(input&&input.url?input.url:String(input));
    var proxied=proxyUrl(url);
    if(proxied&&proxied!==url){
      if(typeof input==='string')input=proxied;
      else if(input&&input.url)input=new Request(proxied,input);
    }
    init=init||{};
    if(!init.credentials) init.credentials='include';
    return _origFetch(input,init);
  }
  
  // Override fetch
  g.fetch=proxyFetch;
  
  // Also try to make it non-configurable to prevent overwriting
  try{
    Object.defineProperty(g,'fetch',{
      value:proxyFetch,
      writable:false,
      configurable:false
    });
  }catch(e){}
  
  // Export for modules that might capture it
  g.__proxyFetch=proxyFetch;
})();
`;

  return wrapper + js;
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
  
  console.log('[IframeProxy] Initializing for:', TARGET_ORIGIN);
  
  // ===== WEB3 WALLET PRESERVATION =====
  // Critical: Don't interfere with wallet provider injection or communication
  // Store references but don't modify
  
  // Domains that should NEVER be proxied (wallets, RPC, extensions)
  const WALLET_BYPASS_DOMAINS = [
    // WalletConnect
    'walletconnect.org', 'walletconnect.com', 'bridge.walletconnect.org',
    'relay.walletconnect.com', 'relay.walletconnect.org',
    'verify.walletconnect.com', 'verify.walletconnect.org',
    'rpc.walletconnect.com', 'rpc.walletconnect.org',
    'explorer-api.walletconnect.com', 'pulse.walletconnect.com',
    'push.walletconnect.com', 'echo.walletconnect.com',
    // Reown (WalletConnect rebrand)
    'reown.com', 'reown.network', 'api.reown.com',
    'keys.reown.com', 'verify.reown.com', 'rpc.reown.com',
    // RPC Providers
    'infura.io', 'alchemy.com', 'quicknode.com', 'ankr.com', 'llamarpc.com',
    'mainnet.optimism.io', 'arb1.arbitrum.io', 'polygon-rpc.com',
    'cloudflare-eth.com', 'ethereum.publicnode.com', 'base.org',
    'rpc.linea.build', 'zksync.io', 'blast.io',
    // MetaMask
    'metamask.io', 'portfolio.metamask.io', 'api.cx.metamask.io',
    'gas-api.metaswap.codefi.network', 'token-api.metaswap.codefi.network',
    'phishing-detection.metaswap.codefi.network', 'codefi.network',
    // Coinbase
    'keys.coinbase.com', 'api.coinbase.com', 'coinbase.com',
    'wallet.coinbase.com', 'rpc.wallet.coinbase.com',
    // Privy
    'auth.privy.io', 'privy.io', 'api.privy.io',
    // Other wallets
    'meshconnect.com', 'api.mesh.id', 'mesh.id',
    'porto.sh', 'api.porto.sh',
    'safe.global', 'safe.io', 'gnosis-safe.io',
    'rainbow.me', 'api.rainbow.me',
    'phantom.app', 'api.phantom.app',
    'trustwallet.com', 'api.trustwallet.com',
    // Blockchain explorers and APIs commonly used by wallets
    'etherscan.io', 'api.etherscan.io',
    'polygonscan.com', 'api.polygonscan.com',
    'arbiscan.io', 'api.arbiscan.io',
    'optimistic.etherscan.io',
    'basescan.org', 'api.basescan.org',
    // Other services
    'socket.tech', 'api.socket.tech', // Bridge aggregator
    'li.fi', 'api.li.fi', // Another bridge
    '1inch.io', 'api.1inch.io', // DEX aggregator
    '0x.org', 'api.0x.org', // 0x protocol
  ];
  
  const RPC_PATTERNS = [
    '/rpc', 'rpc.', '/v1/mainnet', '/v1/optimism', '/v1/arbitrum', '/v1/polygon',
    '/eth/', 'eth_', 'jsonrpc', 'web3', '/v1/base', '/v1/linea', '/v1/zksync',
  ];
  
  function isWalletOrRpcUrl(url) {
    if (!url) return false;
    try {
      const urlStr = url.toLowerCase();
      // Check RPC patterns
      for (const pattern of RPC_PATTERNS) {
        if (urlStr.includes(pattern)) return true;
      }
      // Check wallet domains
      const hostname = new URL(url.startsWith('//') ? 'https:' + url : url).hostname.toLowerCase();
      for (const domain of WALLET_BYPASS_DOMAINS) {
        if (hostname === domain || hostname.endsWith('.' + domain)) return true;
      }
      return false;
    } catch(e) { return false; }
  }
  
  // Prevent frame-busting but preserve window references for wallets
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
  
  // ===== URL REWRITING HELPERS =====
  
  // CDN domains that load directly (no proxy needed)
  const CDN_PASSTHROUGH = [
    'cdn.shopify.com', 'cdn.shopifycdn.net', 'images.unsplash.com',
    'fonts.googleapis.com', 'fonts.gstatic.com', 'cdnjs.cloudflare.com',
    'cdn-global.configcat.com',
    'unpkg.com', 'cdn.jsdelivr.net', 'ajax.googleapis.com',
    'googletagmanager.com', 'google-analytics.com', 'facebook.net',
    '.amazonaws.com', 'storage.googleapis.com', '.cloudfront.net',
    '.akamaized.net', '.fastly.net'
  ];
  
  function shouldBypassProxy(url) {
    if (!url) return false;
    // Always bypass wallet/RPC URLs
    if (isWalletOrRpcUrl(url)) return true;
    try {
      const hostname = new URL(url.startsWith('//') ? 'https:' + url : url).hostname.toLowerCase();
      for (const cdn of CDN_PASSTHROUGH) {
        if (cdn.startsWith('.')) {
          if (hostname.endsWith(cdn)) return true;
        } else {
          if (hostname === cdn || hostname.endsWith('.' + cdn)) return true;
        }
      }
      if (new URL(url).pathname.startsWith('/cdn/')) return true;
      return false;
    } catch(e) { return false; }
  }
  
  // Helper to convert URLs to proxied URLs
  function toProxyUrl(url) {
    if (!url) return url;
    if (typeof url !== 'string') url = String(url);
    
    // Skip already-proxied URLs
    if ((url.startsWith(PROXY_BASE + '/proxy?') || url.startsWith('/proxy?')) && url.includes('url=')) return url;
    
    // If URL is absolute and points back to proxy origin, remap to target origin
    if (url.startsWith(PROXY_BASE) || url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
      try {
        const proxyOrigin = new URL(PROXY_BASE).origin;
        const parsed = new URL(url, proxyOrigin);
        if (parsed.origin === proxyOrigin) {
          const remap = new URL(TARGET_ORIGIN);
          remap.pathname = parsed.pathname;
          remap.search = parsed.search;
          remap.hash = parsed.hash;
          url = remap.href;
        }
      } catch (e) {}
    }
    
    // Handle relative URLs
    if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
      if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('tel:') || url.startsWith('blob:') || url.startsWith('#')) {
        return url;
      }
      try {
        if (url.startsWith('/')) {
          url = TARGET_ORIGIN + url;
        } else {
          url = new URL(url, virtualUrl).href;
        }
      } catch(e) {
        return url;
      }
    }
    
    if (url.startsWith('//')) url = 'https:' + url;
    if (url.startsWith('data:') || url.startsWith('javascript:') || url.startsWith('mailto:') || url.startsWith('tel:') || url.startsWith('blob:') || url.startsWith('#')) {
      return url;
    }
    
    // Bypass proxy for CDN and wallet URLs
    if (shouldBypassProxy(url)) return url;
    
    return PROXY_BASE + '/proxy?url=' + encodeURIComponent(url) + '&sid=' + SESSION_ID;
  }
  
  // Convert proxied URL back to original URL
  function fromProxyUrl(proxyUrl) {
    if (!proxyUrl || typeof proxyUrl !== 'string') return proxyUrl;
    try {
      const u = new URL(proxyUrl, PROXY_BASE);
      const raw = u.searchParams.get('url');
      if (raw) return decodeURIComponent(raw);
    } catch(e) {}
    return proxyUrl;
  }
  
  // ===== SPA HISTORY API INTERCEPTION =====
  // This is CRITICAL for SPAs - must convert paths to proxy URLs
  
  // Track the "virtual" URL the app thinks it's at
  let virtualUrl = TARGET_URL;
  if (typeof virtualUrl === 'string' && virtualUrl.includes('/proxy?') && virtualUrl.includes('url=')) {
    const extracted = fromProxyUrl(virtualUrl);
    if (extracted) virtualUrl = extracted;
  }
  window.__proxyVirtualUrl = virtualUrl; // Expose for debugging
  
  // Store original history methods IMMEDIATELY
  const _origPushState = History.prototype.pushState;
  const _origReplaceState = History.prototype.replaceState;
  
  // Helper to convert a path to a proxy-compatible path
  function toProxyPath(url) {
    if (!url) return url;
    if (typeof url !== 'string') url = String(url);
    
    // Already a proxy path
    if (url.includes('/proxy?') && url.includes('url=')) {
      return url.startsWith('http') ? new URL(url).pathname + new URL(url).search : url;
    }
    
    // Absolute path starting with /
    if (url.startsWith('/') && !url.startsWith('//')) {
      const fullUrl = TARGET_ORIGIN + url;
      console.log('[IframeProxy] toProxyPath:', url, '->', fullUrl);
      return '/proxy?url=' + encodeURIComponent(fullUrl) + '&sid=' + SESSION_ID;
    }
    
    // Relative path (no leading /)
    if (!url.startsWith('http://') && !url.startsWith('https://') && !url.startsWith('//')) {
      try {
        const resolved = new URL(url, virtualUrl).href;
        return '/proxy?url=' + encodeURIComponent(resolved) + '&sid=' + SESSION_ID;
      } catch(e) {
        return url;
      }
    }
    
    // Full URL
    if (url.startsWith('http://') || url.startsWith('https://') || url.startsWith('//')) {
      const fullUrl = url.startsWith('//') ? 'https:' + url : url;
      return '/proxy?url=' + encodeURIComponent(fullUrl) + '&sid=' + SESSION_ID;
    }
    
    return url;
  }
  
  // Override on prototype to catch ALL pushState calls
  History.prototype.pushState = function(state, title, url) {
    console.log('[IframeProxy] pushState called with:', url);
    if (url) {
      try {
        // Update virtual URL tracking
        let resolvedUrl;
        if (typeof url === 'string' && url.includes('/proxy?') && url.includes('url=')) {
          resolvedUrl = fromProxyUrl(url) || new URL(url, virtualUrl).href;
        } else {
          resolvedUrl = new URL(url, virtualUrl).href;
        }
        virtualUrl = resolvedUrl;
        window.__proxyVirtualUrl = virtualUrl;
        
        // Convert to proxy path
        const proxyPath = toProxyPath(url);
        console.log('[IframeProxy] pushState converted to:', proxyPath);
        
        const enhancedState = Object.assign({}, state || {}, { __virtualUrl: resolvedUrl });
        return _origPushState.call(this, enhancedState, title, proxyPath);
      } catch(e) {
        console.warn('[IframeProxy] pushState error:', e);
        return _origPushState.call(this, state, title, url);
      }
    }
    return _origPushState.call(this, state, title, url);
  };
  
  // Override replaceState on prototype
  History.prototype.replaceState = function(state, title, url) {
    console.log('[IframeProxy] replaceState called with:', url);
    if (url) {
      try {
        let resolvedUrl;
        if (typeof url === 'string' && url.includes('/proxy?') && url.includes('url=')) {
          resolvedUrl = fromProxyUrl(url) || new URL(url, virtualUrl).href;
        } else {
          resolvedUrl = new URL(url, virtualUrl).href;
        }
        virtualUrl = resolvedUrl;
        window.__proxyVirtualUrl = virtualUrl;
        
        const proxyPath = toProxyPath(url);
        console.log('[IframeProxy] replaceState converted to:', proxyPath);
        
        const enhancedState = Object.assign({}, state || {}, { __virtualUrl: resolvedUrl });
        return _origReplaceState.call(this, enhancedState, title, proxyPath);
      } catch(e) {
        console.warn('[IframeProxy] replaceState error:', e);
        return _origReplaceState.call(this, state, title, url);
      }
    }
    return _origReplaceState.call(this, state, title, url);
  };
  
  // Handle popstate (back/forward navigation)
  window.addEventListener('popstate', function(e) {
    if (e.state && e.state.__virtualUrl) {
      virtualUrl = e.state.__virtualUrl;
      window.__proxyVirtualUrl = virtualUrl;
      console.log('[IframeProxy] popstate updated virtualUrl:', virtualUrl);
    }
  });
  
  // ===== LOCATION VIRTUALIZATION =====
  // Critical: SPAs check location.pathname to decide what to render
  // We need to make it return the virtual path, not /proxy?url=...
  
  const _realLocation = window.location;
  
  // Create a virtual location that returns the "app" URL, not proxy URL
  function getVirtualLocation() {
    try {
      const vUrl = new URL(virtualUrl);
      return {
        href: virtualUrl,
        protocol: vUrl.protocol,
        host: vUrl.host,
        hostname: vUrl.hostname,
        port: vUrl.port,
        pathname: vUrl.pathname,
        search: vUrl.search,
        hash: _realLocation.hash, // Hash is local, not sent to server
        origin: vUrl.origin,
        ancestorOrigins: _realLocation.ancestorOrigins,
        // Methods that need proxying
        assign: function(url) {
          console.log('[IframeProxy] location.assign:', url);
          _realLocation.assign(toProxyUrl(new URL(url, virtualUrl).href));
        },
        replace: function(url) {
          console.log('[IframeProxy] location.replace:', url);
          _realLocation.replace(toProxyUrl(new URL(url, virtualUrl).href));
        },
        reload: function() {
          _realLocation.reload();
        },
        toString: function() {
          return virtualUrl;
        }
      };
    } catch(e) {
      console.warn('[IframeProxy] getVirtualLocation error:', e);
      return _realLocation;
    }
  }
  
  // Try to override window.location with a proxy
  // This is tricky because location is a special object
  try {
    // Method 1: Define property on window (works in some contexts)
    const locationProxy = new Proxy(_realLocation, {
      get: function(target, prop) {
        const vLoc = getVirtualLocation();
        if (prop in vLoc) {
          const val = vLoc[prop];
          if (typeof val === 'function') {
            return val.bind(vLoc);
          }
          return val;
        }
        // Fallback to real location for unknown props
        const realVal = target[prop];
        if (typeof realVal === 'function') {
          return realVal.bind(target);
        }
        return realVal;
      },
      set: function(target, prop, value) {
        console.log('[IframeProxy] location.' + prop + ' =', value);
        if (prop === 'href') {
          target.href = toProxyUrl(new URL(value, virtualUrl).href);
          return true;
        }
        if (prop === 'pathname') {
          target.href = toProxyUrl(TARGET_ORIGIN + value);
          return true;
        }
        target[prop] = value;
        return true;
      }
    });
    
    Object.defineProperty(window, 'location', {
      get: function() { return locationProxy; },
      set: function(val) { 
        console.log('[IframeProxy] window.location =', val);
        _realLocation.href = toProxyUrl(new URL(val, virtualUrl).href);
      },
      configurable: true
    });
    console.log('[IframeProxy] Location virtualization: SUCCESS');
  } catch(e) {
    console.warn('[IframeProxy] Could not virtualize window.location:', e);
    // Fallback: just override methods
    try {
      const origAssign = _realLocation.assign.bind(_realLocation);
      const origReplace = _realLocation.replace.bind(_realLocation);
      _realLocation.assign = function(url) {
        origAssign(toProxyUrl(new URL(url, virtualUrl).href));
      };
      _realLocation.replace = function(url) {
        origReplace(toProxyUrl(new URL(url, virtualUrl).href));
      };
    } catch(e2) {}
  }
  
  // Also provide a helper for apps that need the real location
  window.__realLocation = _realLocation;
  window.__getVirtualLocation = getVirtualLocation;
  
  // ===== FETCH INTERCEPTION =====
  // Keep it writable so wallet libraries can wrap it if needed
  
  const _origFetch = window.fetch.bind(window);
  
  function proxyFetch(input, init) {
    const originalUrl = typeof input === 'string' ? input : (input instanceof Request ? input.url : String(input));
    
    // NEVER proxy wallet/RPC URLs
    if (isWalletOrRpcUrl(originalUrl)) {
      console.log('[IframeProxy] fetch BYPASS (wallet/RPC):', originalUrl);
      return _origFetch(input, init);
    }
    
    const proxiedUrl = toProxyUrl(originalUrl);
    let url = input;
    if (proxiedUrl && proxiedUrl !== originalUrl) {
      if (typeof input === 'string') {
        url = proxiedUrl;
      } else if (input instanceof Request) {
        url = new Request(proxiedUrl, input);
      }
      console.log('[IframeProxy] fetch PROXY:', originalUrl, '->', proxiedUrl);
    } else {
      console.log('[IframeProxy] fetch DIRECT:', originalUrl);
    }
    
    init = init || {};
    init.credentials = init.credentials || 'include';
    
    return _origFetch(url, init);
  }
  
  // Override fetch but keep it WRITABLE for wallet libraries
  window.fetch = proxyFetch;
  window.__origFetch = _origFetch;
  window.__proxyFetch = proxyFetch;
  window.__proxyFetchInstalled = true;
  
  // ===== XHR INTERCEPTION =====
  
  const origXHROpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...args) {
    this.__originalUrl = url; // Store original URL
    
    // Check if this should bypass proxy (wallet/RPC)
    if (isWalletOrRpcUrl(url) || shouldBypassProxy(url)) {
      console.log('[IframeProxy] XHR BYPASS:', url);
      this.__bypassProxy = true;
      return origXHROpen.call(this, method, url, ...args);
    }
    
    // Proxy the URL
    const proxiedUrl = toProxyUrl(url);
    console.log('[IframeProxy] XHR PROXY:', url, '->', proxiedUrl);
    this.__bypassProxy = false;
    return origXHROpen.call(this, method, proxiedUrl, ...args);
  };
  
  const origXHRSend = XMLHttpRequest.prototype.send;
  XMLHttpRequest.prototype.send = function(body) {
    // Don't add session header for bypassed requests
    if (!this.__bypassProxy) {
      try {
        this.setRequestHeader('X-Proxy-Session', SESSION_ID);
      } catch(e) {}
    }
    return origXHRSend.call(this, body);
  };
  
  // ===== WINDOW.OPEN INTERCEPTION =====
  
  const origOpen = window.open;
  window.open = function(url, target, features) {
    // Don't proxy wallet-related popups
    if (url && (isWalletOrRpcUrl(url) || shouldBypassProxy(url))) {
      console.log('[IframeProxy] window.open BYPASS:', url);
      return origOpen(url, target, features);
    }
    const proxiedUrl = toProxyUrl(url);
    console.log('[IframeProxy] window.open PROXY:', url, '->', proxiedUrl);
    return origOpen(proxiedUrl, target, features);
  };
  
  // ===== FORM SUBMISSION INTERCEPTION =====
  
  document.addEventListener('submit', function(e) {
    const form = e.target;
    if (form && form.tagName === 'FORM') {
      const action = form.getAttribute('action') || '';
      if (!(action.includes('/proxy?') && action.includes('url='))) {
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
      if (!href) return;
      
      // Don't intercept wallet/web3 links
      if (href.includes('metamask') || href.includes('walletconnect') || 
          href.includes('coinbase') || href.includes('rainbow') ||
          href.includes('wc:') || href.startsWith('ethereum:')) {
        console.log('[IframeProxy] click BYPASS (wallet link):', href);
        return;
      }
      
      // Skip special URLs
      if (href.startsWith('javascript:') || href.startsWith('#') || (href.includes('/proxy?') && href.includes('url='))) {
        return;
      }
      
      // Resolve the URL
      let resolvedUrl;
      try {
        resolvedUrl = new URL(href, virtualUrl).href;
      } catch(err) {
        resolvedUrl = href;
      }
      
      // Check if it's same-origin (SPA navigation)
      try {
        const resolvedOrigin = new URL(resolvedUrl).origin;
        if (resolvedOrigin === TARGET_ORIGIN) {
          // Same-origin: Let the SPA router handle it via our pushState override
          // Don't prevent default - let the natural click flow through
          // Our History.prototype.pushState override will catch it
          console.log('[IframeProxy] click same-origin, letting SPA router handle:', href);
          return; // Let it propagate naturally
        } else {
          // Cross-origin: Prevent and redirect through proxy
          e.preventDefault();
          e.stopPropagation();
          console.log('[IframeProxy] click cross-origin, proxying:', resolvedUrl);
          window.location.href = toProxyUrl(resolvedUrl);
        }
      } catch(err) {
        console.warn('[IframeProxy] click handler error:', err);
      }
    }
  }, true);
  
  // ===== WEBSOCKET PRESERVATION =====
  // Don't interfere with WebSocket connections - wallets use these
  // The native WebSocket should work fine, just log for debugging
  const _OrigWebSocket = window.WebSocket;
  window.WebSocket = function(url, protocols) {
    console.log('[IframeProxy] WebSocket connection:', url);
    // Never proxy WebSocket URLs
    return new _OrigWebSocket(url, protocols);
  };
  window.WebSocket.prototype = _OrigWebSocket.prototype;
  window.WebSocket.CONNECTING = _OrigWebSocket.CONNECTING;
  window.WebSocket.OPEN = _OrigWebSocket.OPEN;
  window.WebSocket.CLOSING = _OrigWebSocket.CLOSING;
  window.WebSocket.CLOSED = _OrigWebSocket.CLOSED;
  
  // ===== DYNAMIC IMAGE LOADING (MutationObserver) =====
  
  const lazyAttrs = ['data-src', 'data-lazy-src', 'data-original', 'data-bg', 'data-background', 'data-image'];
  
  function rewriteElement(el) {
    for (const attr of lazyAttrs) {
      const val = el.getAttribute(attr);
      if (val && !(val.includes('/proxy?') && val.includes('url=')) && !val.startsWith('data:')) {
        el.setAttribute(attr, toProxyUrl(val));
      }
    }
    // Handle srcset
    const srcset = el.getAttribute('srcset') || el.getAttribute('data-srcset');
    if (srcset && !(srcset.includes('/proxy?') && srcset.includes('url='))) {
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
  
  const proxyBase = getProxyBase(req);
  // If the URL points back to this proxy, unwrap it to the real target
  decodedUrl = unwrapProxyUrl(decodedUrl, proxyBase);
  try {
    new URL(decodedUrl);
  } catch (e) {
    return res.status(400).json({ error: 'Invalid URL after unwrapping', details: e.message, url: decodedUrl });
  }
  
  let sessionId = req.query.sid || getSessionId(req);
  let extraPath = '';
  if (typeof sessionId === 'string' && sessionId.includes('/')) {
    const idx = sessionId.indexOf('/');
    extraPath = sessionId.slice(idx);
    sessionId = sessionId.slice(0, idx) || getSessionId(req);
  }
  
  if (extraPath) {
    try {
      const base = new URL(decodedUrl);
      const extra = new URL(extraPath, base.origin);
      base.pathname = base.pathname.replace(/\/$/, '') + extra.pathname;
      if (extra.search) base.search = extra.search;
      if (extra.hash) base.hash = extra.hash;
      decodedUrl = base.href;
    } catch (e) {
      decodedUrl = decodedUrl + extraPath;
    }
  }
  
  try {
    // Build request headers - make them as Chrome-like as possible
    const acceptEncoding = (req.headers['accept-encoding'] || '').toLowerCase();
    const safeEncoding = acceptEncoding.includes('br') ? 'gzip, deflate' : (acceptEncoding || 'gzip, deflate');
    
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36',
      'Accept': req.headers['accept'] || 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Accept-Encoding': safeEncoding,
      // Modern Chrome headers that help pass bot detection
      'sec-ch-ua': req.headers['sec-ch-ua'] || '"Chromium";v="122", "Not(A:Brand";v="24", "Google Chrome";v="122"',
      'sec-ch-ua-mobile': req.headers['sec-ch-ua-mobile'] || '?0',
      'sec-ch-ua-platform': req.headers['sec-ch-ua-platform'] || '"Windows"',
      'sec-fetch-dest': req.headers['sec-fetch-dest'],
      'sec-fetch-mode': req.headers['sec-fetch-mode'],
      'sec-fetch-site': req.headers['sec-fetch-site'],
      'sec-fetch-user': req.headers['sec-fetch-user'],
      'upgrade-insecure-requests': req.headers['upgrade-insecure-requests'],
      'cache-control': req.headers['cache-control'] || 'max-age=0',
    };
    
    // Drop undefined headers to avoid sending "undefined"
    for (const [key, value] of Object.entries(headers)) {
      if (value === undefined) delete headers[key];
    }
    
    // Add cookies
    const storedCookies = getCookiesForDomain(sessionId, decodedUrl);
    if (Object.keys(storedCookies).length > 0) {
      headers['Cookie'] = formatCookies(storedCookies);
    }
    
    // Forward referer as the unwrapped target URL when possible
    const rawRef = req.headers['referer'] || req.headers['referrer'];
    if (rawRef) {
      const unwrappedRef = unwrapProxyUrl(rawRef, proxyBase);
      headers['Referer'] = unwrappedRef;
    } else {
      headers['Referer'] = new URL(decodedUrl).origin;
    }
    headers['Origin'] = new URL(decodedUrl).origin;
    
    // Build fetch options - use manual redirect to keep redirects within proxy
    const fetchOptions = {
      method: req.method,
      headers,
      redirect: 'manual', // Handle redirects ourselves to keep them proxied
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
    let response = await fetch(decodedUrl, fetchOptions);
    
    // Handle redirects - keep them within the proxy
    let redirectCount = 0;
    const maxRedirects = 10;
    while (response.status >= 300 && response.status < 400 && redirectCount < maxRedirects) {
      const location = response.headers.get('location');
      if (!location) break;
      
      // Resolve relative redirects
      const redirectUrl = new URL(location, decodedUrl).href;
      console.log('[IframeProxy] Following redirect:', decodedUrl, '->', redirectUrl);
      
      // Update the decoded URL for subsequent processing
      decodedUrl = redirectUrl;
      
      // Fetch the redirect target
      response = await fetch(redirectUrl, { 
        ...fetchOptions, 
        headers: {
          ...headers,
          'Referer': new URL(redirectUrl).origin,
          'Origin': new URL(redirectUrl).origin,
        }
      });
      redirectCount++;
    }
    
    // Store any cookies from the response
    const setCookieHeader = response.headers.raw()['set-cookie'];
    if (setCookieHeader) {
      storeCookies(sessionId, decodedUrl, setCookieHeader);
    }
    
    // Get content type
    const contentType = response.headers.get('content-type') || '';
    
    let contextOriginForCookie = null;
    
    // Track the origin for this session only for top-level HTML documents
    if (contentType.includes('text/html') && isTopLevelNavigation(req)) {
      try {
        const proxyOrigin = new URL(proxyBase).origin;
        let targetOrigin = new URL(decodedUrl).origin;
        
        if (targetOrigin === proxyOrigin) {
          const ref = req.headers['referer'] || req.headers['referrer'];
          if (ref) {
            const unwrappedRef = unwrapProxyUrl(ref, proxyBase);
            try {
              targetOrigin = new URL(unwrappedRef).origin;
            } catch (e) {}
          }
        }
        
        if (targetOrigin && targetOrigin !== proxyOrigin) {
          sessionOrigins.set(sessionId, targetOrigin);
          lastGlobalOrigin = targetOrigin;
          contextOriginForCookie = targetOrigin;
        } else {
          console.warn('[IframeProxy] Skipping proxy origin for session tracking:', targetOrigin);
        }
      } catch (e) {}
    }
    
    // Get response body
    let body;
    if (contentType.includes('text/html')) {
      const html = await response.text();
      body = rewriteHtml(html, decodedUrl, proxyBase, sessionId);
    } else if (contentType.includes('text/css')) {
      const css = await response.text();
      body = rewriteCssUrls(css, decodedUrl, proxyBase, sessionId);
    } else if (contentType.includes('javascript')) {
      // Rewrite JavaScript to proxy fetch calls
      const js = await response.text();
      body = rewriteJavaScript(js, decodedUrl, proxyBase, sessionId);
    } else if (contentType.includes('application/json')) {
      // JSON passes through as-is
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
    setProxyContextCookies(res, req, sessionId, contextOriginForCookie);
    
    res.status(response.status);
    res.send(body);
    
  } catch (error) {
    console.error('[IframeProxy] Error fetching:', decodedUrl, error.message);
    if (error && error.stack) console.error(error.stack);
    res.status(500).json({ 
      error: 'Proxy error', 
      details: error.message || String(error),
      code: error.code,
      errno: error.errno,
      type: error.type,
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

// Catch-all for SPA navigation and dynamic imports
// When browser navigates to /portfolio, redirect to /proxy?url=https://site.com/portfolio
app.use(async (req, res, next) => {
  const path = req.path;
  
  // Skip if it's a known route or static file exists
  if (path === '/' || path === '/proxy' || path === '/health' || path.startsWith('/test')) {
    return next();
  }
  
  // Try to get the origin from session or fallback
  let sessionId = req.query.sid || req.headers['x-proxy-session'];
  const ctxCookies = getProxyContextFromCookies(req);
  if (!sessionId && ctxCookies.sid) {
    sessionId = ctxCookies.sid;
  }
  let targetOrigin = sessionId ? sessionOrigins.get(sessionId) : null;
  let proxyOrigin = null;
  try {
    proxyOrigin = new URL(getProxyBase(req)).origin;
  } catch (e) {}
  
  // Prefer referer origin when available (more accurate for resources)
  let refererOrigin = null;
  const ref = req.headers['referer'] || req.headers['referrer'];
  if (ref) {
    try {
      const unwrappedRef = unwrapProxyUrl(ref, getProxyBase(req));
      refererOrigin = new URL(unwrappedRef).origin;
    } catch (e) {}
  }
  
  if (refererOrigin && (!proxyOrigin || refererOrigin !== proxyOrigin)) {
    targetOrigin = refererOrigin;
  }
  
  if (!targetOrigin && ctxCookies.origin && (!proxyOrigin || ctxCookies.origin !== proxyOrigin)) {
    targetOrigin = ctxCookies.origin;
  }
  
  // Fallback to last global origin (works for single-site testing)
  if (!targetOrigin) {
    targetOrigin = lastGlobalOrigin;
  }
  
  // Avoid proxy-origin poisoning
  if (proxyOrigin && targetOrigin === proxyOrigin) {
    targetOrigin = lastGlobalOrigin && lastGlobalOrigin !== proxyOrigin ? lastGlobalOrigin : null;
  }
  
  if (!targetOrigin) {
    return res.status(404).json({ 
      success: false, 
      error: 'No origin context - please load a site through /proxy?url= first',
      path: path 
    });
  }
  
  // Build the full target URL
  const queryString = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
  const targetUrl = targetOrigin + path + queryString;
  
  // Check if this is a document/navigation request vs a resource request
  const acceptHeader = (req.headers['accept'] || '').toLowerCase();
  const destHeader = (req.headers['sec-fetch-dest'] || '').toLowerCase();
  const modeHeader = (req.headers['sec-fetch-mode'] || '').toLowerCase();
  const urlHasRsc = req.url.includes('_rsc=') || req.url.includes('__rsc=') || req.url.includes('__flight__');
  
  let isDocRequest = false;
  if (destHeader === 'document' || modeHeader === 'navigate') {
    isDocRequest = true;
  } else if (acceptHeader.includes('text/html') || acceptHeader.includes('application/xhtml+xml')) {
    isDocRequest = true;
  } else if (!destHeader && !modeHeader && !acceptHeader.includes('application/json') && !acceptHeader.includes('text/x-component')) {
    // Fallback heuristics when fetch metadata is missing
    isDocRequest = path === '/' || (!path.includes('.') && path.match(/^\/[a-z0-9-\/]+$/i));
  }
  
  // For document requests (SPA navigation), redirect to proper proxy URL
  if (urlHasRsc || acceptHeader.includes('text/x-component')) {
    isDocRequest = false;
  }
  
  if (isDocRequest && req.method === 'GET') {
    console.log('[IframeProxy] Redirecting SPA navigation:', path, '->', targetUrl);
    const proxyUrl = `/proxy?url=${encodeURIComponent(targetUrl)}${sessionId ? '&sid=' + sessionId : ''}`;
    return res.redirect(302, proxyUrl);
  }
  
  // For resource requests (JS, CSS, images), proxy directly
  console.log('[IframeProxy] Proxying resource:', path, '->', targetUrl);
  
  try {
    const headers = {
      'User-Agent': req.headers['user-agent'] || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      'Accept': req.headers['accept'] || '*/*',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.9',
      'Referer': targetOrigin,
      'Origin': targetOrigin,
    };
    
    const response = await fetch(targetUrl, { headers, redirect: 'follow' });
    
    // Check if the response is HTML (might be a soft 404 or redirect)
    const contentType = response.headers.get('content-type') || '';
    
    // If we got HTML for a resource request, it might be an error page - proxy it properly
    if (contentType.includes('text/html') && !isDocRequest) {
      const html = await response.text();
      const proxyBase = getProxyBase(req);
      const rewritten = rewriteHtml(html, targetUrl, proxyBase, sessionId || 'default');
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.setHeader('Access-Control-Allow-Origin', '*');
      return res.status(response.status).send(rewritten);
    }
    
    const body = await response.buffer();
    
    // Forward relevant headers
    if (contentType) res.setHeader('Content-Type', contentType);
    
    const cacheControl = response.headers.get('cache-control');
    if (cacheControl) res.setHeader('Cache-Control', cacheControl);
    
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.status(response.status).send(body);
    
  } catch (error) {
    console.error('[IframeProxy] Catch-all error:', targetUrl, error.message);
    if (error && error.stack) console.error(error.stack);
    res.status(500).json({ 
      success: false,
      error: 'Proxy error', 
      details: error.message || String(error),
      code: error.code,
      errno: error.errno,
      type: error.type,
      path: path,
      targetUrl: targetUrl
    });
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`🔓 Iframe Bypass Proxy running on http://localhost:${PORT}`);
  console.log(`📝 Usage: /proxy?url=<encoded-url>`);
  console.log(`💚 Health: /health`);
});

module.exports = app;
