# iframe-proxy → WebFuse Parity Upgrade Guide

## Summary

Successfully upgraded iframe-proxy to match WebFuse's capabilities by switching from `node-fetch` to **Playwright** (real browser engine).

### ✅ Verified: Now handles `moltbot.guru` (previously blocked by Cloudflare)

---

## What Was Missing

### The Problem
Your original proxy (using `node-fetch`) was getting blocked by Cloudflare's bot detection because:

1. **Node.js TLS fingerprint** — Cloudflare analyzes:
   - TLS handshake (cipher suites, extensions, order)
   - HTTP/2 fingerprint (frame prioritization, settings)
   - These patterns immediately flag Node.js as a bot

2. **No JavaScript execution** — Sites with Cloudflare challenges require a real JS runtime to solve them

3. **Incomplete browser headers** — Modern sites check for sec-ch-ua and other browser-specific headers

### WebFuse's Secret Sauce
WebFuse uses **Virtual Web Sessions** powered by a real browser engine (like Playwright/Puppeteer), giving them:
- Authentic Chrome TLS fingerprint
- JavaScript execution (auto-solves Cloudflare challenges)
- Full browser context (cookies, storage, async JS)

---

## The Solution

### New Architecture: `server-playwright.js`

**Key Changes:**
1. **Browser pool** (3 concurrent Chromium instances by default)
2. **Real page navigation** with `networkidle` wait (handles async content)
3. **Automatic JS challenge solving** (Cloudflare, etc.)
4. **Authentic browser fingerprint**

**Features Retained:**
- ✅ X-Frame-Options & CSP header removal
- ✅ URL rewriting (HTML, CSS, JS)
- ✅ Session isolation & cookie management
- ✅ CDN bypass for performance
- ✅ Frame-buster prevention scripts

**New Capabilities:**
- ✅ Cloudflare bypass
- ✅ Dynamic content rendering
- ✅ Better redirect handling
- ✅ Viewport rendering (1920x1080)

---

## Deployment

### 1. Update Dependencies

```bash
cd ~/clawd/iframe-proxy
npm install playwright --save
npx playwright install chromium
```

### 2. Update package.json

```json
{
  "scripts": {
    "start": "node server-playwright.js",
    "dev": "node server-playwright.js",
    "legacy": "node server.js"
  },
  "dependencies": {
    "cheerio": "^1.0.0",
    "cookie": "^0.7.0",
    "express": "^4.21.0",
    "playwright": "^1.50.1"
  }
}
```

Note: Removed `node-fetch` dependency (Playwright handles all fetching now).

### 3. Environment Variables

Add to your Render deployment:

```bash
# Browser pool size (3 is optimal for most workloads)
MAX_BROWSERS=3

# Cache settings (same as before)
ASSET_CACHE_TTL_MS=600000
ASSET_CACHE_MAX_BYTES=52428800

# Domain settings (if using custom domains)
PROXY_BASE_DOMAIN=proxy.blank.space
```

### 4. Render Configuration

Update `render.yaml`:

```yaml
services:
  - type: web
    name: iframe-proxy-playwright
    env: node
    buildCommand: npm install && npx playwright install chromium --with-deps
    startCommand: npm start
    envVars:
      - key: NODE_ENV
        value: production
      - key: MAX_BROWSERS
        value: 3
    numInstances: 1
    plan: starter # Or higher for better performance
```

**Important:** Playwright needs system dependencies. The `--with-deps` flag installs them automatically on Render.

### 5. Memory Considerations

Playwright browsers use ~200-300MB each. Recommended Render plan:
- **Starter** (512MB): 2 browsers max
- **Standard** (1GB): 3 browsers ✅ (recommended)
- **Pro** (2GB+): 5+ browsers (for high traffic)

Update MAX_BROWSERS based on your plan:

```javascript
const MAX_BROWSERS = parseInt(process.env.MAX_BROWSERS || '2', 10);
```

### 6. Deploy to Render

```bash
cd ~/clawd/iframe-proxy
git add server-playwright.js package.json package-lock.json
git commit -m "Upgrade to Playwright for Cloudflare bypass"
git push origin main
```

Or deploy via Render's "Manual Deploy" button.

### 7. Testing

After deployment:

```bash
# Test with a Cloudflare-protected site
curl "https://proxy.blank.space/proxy?url=https%3A%2F%2Fmoltbot.guru%2F"

# Should return HTML content, not "Just a moment..."
```

---

## Performance Optimization

### Browser Pool Management

The proxy uses a round-robin browser pool:
- Requests are distributed across N browsers
- Each browser handles one request at a time
- Browsers persist across requests (faster than launching each time)

**Tuning:**
- **Low traffic** (< 10 req/min): 1-2 browsers
- **Medium traffic** (10-50 req/min): 3 browsers ✅
- **High traffic** (50+ req/min): 5+ browsers + load balancer

### Caching

Static assets are still cached in memory:
- CSS, JS, images, fonts: 10 min TTL
- CDN resources bypass proxy entirely
- Cache survives browser pool (shared across all browsers)

### Timeout Settings

Default: 30s page load timeout. Adjust for slow sites:

```javascript
const response = await page.goto(url, {
  waitUntil: 'networkidle',
  timeout: 60000, // 60 seconds for very slow sites
});
```

---

## Known Limitations

1. **Heavy sites** — Sites with massive JS bundles may be slow (use caching)
2. **WebSocket** — Not currently proxied (add if needed)
3. **Memory** — Each browser ~250MB; monitor with `GET /health`
4. **Rate limiting** — Some sites may still block; add delays if needed

---

## Monitoring

Health check endpoint:

```bash
GET /health
```

Returns:
```json
{
  "status": "ok",
  "browsers": 3,
  "uptime": 3600
}
```

Monitor browser pool size — if it's 0, the service is degraded.

---

## Rollback Plan

If you need to roll back to the old version:

```bash
# Update start script in package.json
"start": "node server.js"

# Remove playwright dependency
npm uninstall playwright

# Redeploy
git push origin main
```

---

## Next Steps

1. **Test thoroughly** with sites you want to embed (moltbook.space widgets, etc.)
2. **Monitor memory usage** on Render (may need to upgrade plan)
3. **Add WebSocket support** if needed for real-time apps
4. **Implement rate limiting** if you get too much traffic

---

## Comparison: Before vs After

| Feature | node-fetch (old) | Playwright (new) |
|---------|------------------|------------------|
| Cloudflare bypass | ❌ Blocked | ✅ Works |
| JS execution | ❌ No | ✅ Full runtime |
| TLS fingerprint | Node.js | Chrome |
| Memory usage | ~50MB | ~800MB (3 browsers) |
| Speed (cached) | Fast | Fast |
| Speed (uncached) | Fast | Slower (browser overhead) |
| Dynamic content | ❌ Limited | ✅ Full support |

---

## Questions?

Check the logs:
```bash
# Render dashboard → Logs
# Look for: [IframeProxy] Browser pool ready (X instances)
```

If browsers fail to init, check Render build logs for system dependency errors.

---

**Status:** ✅ Tested and working with moltbot.guru
**Ready for production:** Yes, after memory/plan check
