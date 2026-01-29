# 🔓 Iframe Bypass Proxy

A proxy server that enables embedding websites in iframes that normally block embedding via `X-Frame-Options` or `Content-Security-Policy` headers.

## Features

- ✅ **Strips X-Frame-Options** headers
- ✅ **Removes frame-ancestors** from Content-Security-Policy
- ✅ **Rewrites all URLs** (href, src, action, srcset, etc.) to go through proxy
- ✅ **Rewrites CSS url()** references
- ✅ **Injects JavaScript** to prevent frame-buster scripts
- ✅ **Intercepts navigation** (location changes, fetch, XHR, window.open)
- ✅ **Handles form submissions** (POST requests)
- ✅ **Session-based cookie handling** for isolated sessions
- ✅ **CORS enabled** for cross-origin iframe embedding

## Installation

```bash
npm install
```

## Usage

### Start the server

```bash
npm start
# or
node server.js
```

The server runs on port 3001 by default (configurable via `PORT` env var).

### API Endpoints

#### Proxy a URL
```
GET /proxy?url=<encoded-url>
POST /proxy?url=<encoded-url>  (for form submissions)
```

**Parameters:**
- `url` (required): URL-encoded target URL
- `sid` (optional): Session ID for cookie isolation (not needed when using session subdomains)

**Example:**
```bash
curl "http://localhost:3001/proxy?url=https://github.com"
```

#### Create a Session (Widget-style toggle)
```
POST /session
```

**Body:**
```json
{ "url": "https://app.katana.network" }
```

**Response:**
```json
{
  "sessionId": "session_...",
  "sessionUrl": "https://<session>.<yourdomain>/proxy?url=https%3A%2F%2Fapp.katana.network",
  "proxyUrl": "https://<session>.<yourdomain>/proxy?url=...",
  "targetUrl": "https://app.katana.network",
  "targetOrigin": "https://app.katana.network"
}
```

#### Health Check
```
GET /health
```

Returns: `{ "status": "ok", "timestamp": "..." }`

### Test Page

Visit `http://localhost:3001/test.html` to see a side-by-side comparison of direct embedding vs proxied embedding.

## Integration with nounspace.com

To use this proxy for "load via proxy" functionality with a toggle:

```html
<script src="https://your-proxy-domain.com/nounspace-proxy.js"></script>
```

```javascript
const proxyClient = NounspaceProxy.create({
  baseUrl: 'https://your-proxy-domain.com'
});

const iframe = document.getElementById('myIframe');

async function setProxyEnabled(enabled, targetUrl) {
  if (enabled) {
    await proxyClient.enableProxy(iframe, targetUrl);
  } else {
    proxyClient.disableProxy(iframe, targetUrl);
  }
}
```

### Detecting iframe load failures

Since browsers don't fire `onerror` for X-Frame-Options blocks, you may need to:

1. **Try-catch approach**: Attempt to access `iframe.contentWindow` after load
2. **Timeout approach**: If iframe doesn't load content within N seconds, try proxy
3. **Server-side check**: Pre-check the URL's headers server-side

```javascript
iframe.onload = function() {
  try {
    // If we can access contentDocument, it loaded (or same-origin)
    const doc = iframe.contentDocument;
  } catch(e) {
    // Cross-origin but loaded - check if it has content
    // If blocked by X-Frame-Options, this usually results in about:blank
  }
};

// Timeout fallback
setTimeout(() => {
  if (!iframeLoaded) {
    loadViaProxy(url, iframe);
  }
}, 5000);
```

## How It Works

1. **Request Interception**: Client requests `/proxy?url=<target>`
2. **Fetch**: Server fetches the target URL with appropriate headers
3. **Header Sanitization**: Remove X-Frame-Options, modify CSP
4. **URL Rewriting**: Parse HTML/CSS and rewrite all URLs to go through proxy
5. **Script Injection**: Add JavaScript to:
   - Spoof `window.top` and `window.parent` (anti-frame-buster)
   - Intercept `fetch()`, `XMLHttpRequest`, `window.open`
   - Handle dynamic navigation
6. **Cookie Handling**: Store and forward cookies per session
7. **Response**: Return modified content with CORS headers

## Limitations

- **JavaScript-heavy SPAs**: Some complex apps may not work perfectly
- **WebSockets**: Not currently proxied (would need upgrade handling)
- **Authentication flows**: OAuth redirects may need special handling
- **Rate limiting**: Target sites may rate-limit proxy server IP
- **Legal considerations**: Respect robots.txt and terms of service

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT`   | 3001    | Server port |
| `PROXY_BASE_DOMAIN` | (empty) | Base domain for per-session subdomains (e.g. `lvh.me` for local dev). When set, `sid` is omitted from proxied URLs. |

## Development

```bash
# Run tests
npm test

# Start development server
npm run dev
```

## License

MIT
