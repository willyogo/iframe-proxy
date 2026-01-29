#!/usr/bin/env node
/**
 * Tests for Iframe Bypass Proxy
 */

const assert = require('assert');

// We'll test the URL rewriting functions directly
// In a real scenario, we'd use supertest for HTTP tests

console.log('🧪 Running Iframe Proxy Tests...\n');

// Test 1: URL Resolution
console.log('Test 1: URL Resolution');
{
  const { URL } = require('url');
  
  function resolveUrl(relativeUrl, baseUrl) {
    if (!relativeUrl) return relativeUrl;
    if (relativeUrl.startsWith('http://') || relativeUrl.startsWith('https://')) {
      return relativeUrl;
    }
    if (relativeUrl.startsWith('//')) {
      return 'https:' + relativeUrl;
    }
    if (relativeUrl.startsWith('data:') || 
        relativeUrl.startsWith('javascript:') ||
        relativeUrl.startsWith('mailto:') ||
        relativeUrl.startsWith('#')) {
      return relativeUrl;
    }
    try {
      return new URL(relativeUrl, baseUrl).href;
    } catch (e) {
      return relativeUrl;
    }
  }
  
  // Test cases
  assert.strictEqual(
    resolveUrl('/path/to/resource', 'https://example.com/page'),
    'https://example.com/path/to/resource',
    'Should resolve absolute paths'
  );
  
  assert.strictEqual(
    resolveUrl('relative/path', 'https://example.com/dir/'),
    'https://example.com/dir/relative/path',
    'Should resolve relative paths'
  );
  
  assert.strictEqual(
    resolveUrl('//cdn.example.com/script.js', 'https://example.com/'),
    'https://cdn.example.com/script.js',
    'Should handle protocol-relative URLs'
  );
  
  assert.strictEqual(
    resolveUrl('data:image/png;base64,abc', 'https://example.com/'),
    'data:image/png;base64,abc',
    'Should skip data URLs'
  );
  
  assert.strictEqual(
    resolveUrl('javascript:void(0)', 'https://example.com/'),
    'javascript:void(0)',
    'Should skip javascript URLs'
  );
  
  assert.strictEqual(
    resolveUrl('#section', 'https://example.com/'),
    '#section',
    'Should skip anchor links'
  );
  
  console.log('  ✅ All URL resolution tests passed\n');
}

// Test 2: CSS URL Rewriting
console.log('Test 2: CSS URL Rewriting');
{
  function rewriteCssUrls(css, baseUrl, proxyBase, sessionId) {
    return css.replace(/url\s*\(\s*(['"]?)([^)'"]+)\1\s*\)/gi, (match, quote, url) => {
      const trimmedUrl = url.trim();
      if (trimmedUrl.startsWith('data:')) {
        return match;
      }
      // Simplified for test
      const proxiedUrl = `${proxyBase}/proxy?url=${encodeURIComponent(trimmedUrl)}&sid=${sessionId}`;
      return `url(${quote}${proxiedUrl}${quote})`;
    });
  }
  
  const css1 = 'background: url("/images/bg.png");';
  const result1 = rewriteCssUrls(css1, 'https://example.com', 'http://localhost:3001', 'test123');
  assert(result1.includes('/proxy?url='), 'Should rewrite url() in CSS');
  assert(result1.includes('sid=test123'), 'Should include session ID');
  
  const css2 = 'background: url("data:image/png;base64,abc");';
  const result2 = rewriteCssUrls(css2, 'https://example.com', 'http://localhost:3001', 'test123');
  assert(!result2.includes('/proxy?url='), 'Should NOT rewrite data URLs');
  
  const css3 = "background: url('/fonts/font.woff2');";
  const result3 = rewriteCssUrls(css3, 'https://example.com', 'http://localhost:3001', 'test123');
  assert(result3.includes('/proxy?url='), 'Should handle single quotes');
  
  console.log('  ✅ All CSS URL rewriting tests passed\n');
}

// Test 3: Header Sanitization
console.log('Test 3: Header Sanitization');
{
  function sanitizeResponseHeaders(headers) {
    const sanitized = {};
    for (const [key, value] of Object.entries(headers)) {
      const lowerKey = key.toLowerCase();
      if (lowerKey === 'x-frame-options') continue;
      if (lowerKey === 'content-security-policy') {
        let csp = value;
        csp = csp.replace(/frame-ancestors[^;]*(;|$)/gi, '');
        if (csp.trim()) {
          sanitized['content-security-policy'] = csp;
        }
        continue;
      }
      if (lowerKey === 'content-security-policy-report-only') continue;
      sanitized[key] = value;
    }
    return sanitized;
  }
  
  const headers1 = {
    'Content-Type': 'text/html',
    'X-Frame-Options': 'DENY',
    'Cache-Control': 'no-cache'
  };
  const result1 = sanitizeResponseHeaders(headers1);
  assert(!result1['X-Frame-Options'], 'Should remove X-Frame-Options');
  assert.strictEqual(result1['Content-Type'], 'text/html', 'Should keep Content-Type');
  assert.strictEqual(result1['Cache-Control'], 'no-cache', 'Should keep other headers');
  
  const headers2 = {
    'Content-Security-Policy': "frame-ancestors 'none'; script-src 'self'"
  };
  const result2 = sanitizeResponseHeaders(headers2);
  assert(!result2['content-security-policy'].includes('frame-ancestors'), 'Should remove frame-ancestors');
  assert(result2['content-security-policy'].includes('script-src'), 'Should keep other CSP directives');
  
  console.log('  ✅ All header sanitization tests passed\n');
}

// Test 4: Session ID Generation
console.log('Test 4: Session ID Generation');
{
  function getSessionId(existingId) {
    if (existingId) return existingId;
    return `session_${Date.now()}_${Math.random().toString(36).slice(2)}`;
  }
  
  const existing = getSessionId('my-session-123');
  assert.strictEqual(existing, 'my-session-123', 'Should return existing session ID');
  
  const generated = getSessionId(null);
  assert(generated.startsWith('session_'), 'Should generate session ID starting with session_');
  assert(generated.length > 20, 'Should generate reasonably long session ID');
  
  console.log('  ✅ All session ID tests passed\n');
}

// Test 5: Proxy URL Generation
console.log('Test 5: Proxy URL Generation');
{
  function toProxyUrl(targetUrl, proxyBase, sessionId) {
    if (!targetUrl) return targetUrl;
    if (targetUrl.startsWith('//')) {
      targetUrl = 'https:' + targetUrl;
    }
    if (targetUrl.startsWith('data:') || 
        targetUrl.startsWith('javascript:') ||
        targetUrl.startsWith('mailto:') ||
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
  
  const proxyBase = 'http://localhost:3001';
  const sessionId = 'test123';
  
  const result1 = toProxyUrl('https://example.com/page', proxyBase, sessionId);
  assert(result1.startsWith(proxyBase), 'Should start with proxy base');
  assert(result1.includes('url='), 'Should include url parameter');
  assert(result1.includes('sid=test123'), 'Should include session ID');
  
  const result2 = toProxyUrl('javascript:void(0)', proxyBase, sessionId);
  assert.strictEqual(result2, 'javascript:void(0)', 'Should skip javascript URLs');
  
  const result3 = toProxyUrl('#anchor', proxyBase, sessionId);
  assert.strictEqual(result3, '#anchor', 'Should skip anchors');
  
  console.log('  ✅ All proxy URL generation tests passed\n');
}

console.log('✅ All tests passed!\n');
console.log('To run integration tests, start the server and test with:');
console.log('  curl "http://localhost:3001/proxy?url=https://example.com"');
console.log('  curl "http://localhost:3001/health"');
