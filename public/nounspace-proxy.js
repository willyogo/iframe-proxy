(function(global){
  'use strict';

  function resolveBaseUrl(options){
    if (options && options.baseUrl) return options.baseUrl.replace(/\/$/, '');
    if (options && options.apiBase) return options.apiBase.replace(/\/$/, '');
    if (options && options.scriptUrl) {
      try { return new URL(options.scriptUrl).origin; } catch (e) {}
    }
    if (global && global.location && global.location.origin) return global.location.origin;
    return '';
  }

  function createClient(options){
    options = options || {};
    var baseUrl = resolveBaseUrl(options);
    var sessionPath = options.sessionPath || '/session';

    async function createSession(targetUrl, extra){
      if (!targetUrl) throw new Error('targetUrl is required');
      var body = { url: targetUrl };
      if (extra && extra.sid) body.sid = extra.sid;
      var resp = await fetch(baseUrl + sessionPath, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body)
      });
      if (!resp.ok) {
        var text = '';
        try { text = await resp.text(); } catch (e) {}
        throw new Error('Session request failed: ' + resp.status + (text ? (': ' + text) : ''));
      }
      return resp.json();
    }

    async function enableProxy(iframe, targetUrl, extra){
      if (!iframe) throw new Error('iframe is required');
      var session = await createSession(targetUrl, extra);
      iframe.src = session.sessionUrl || session.proxyUrl;
      return session;
    }

    function disableProxy(iframe, targetUrl){
      if (!iframe) throw new Error('iframe is required');
      iframe.src = targetUrl;
    }

    async function toggle(iframe, targetUrl, enabled, extra){
      if (enabled) return enableProxy(iframe, targetUrl, extra);
      disableProxy(iframe, targetUrl);
      return null;
    }

    function isProxiedUrl(url){
      return typeof url === 'string' && url.indexOf('/proxy?url=') !== -1;
    }

    return {
      baseUrl: baseUrl,
      createSession: createSession,
      enableProxy: enableProxy,
      disableProxy: disableProxy,
      toggle: toggle,
      isProxiedUrl: isProxiedUrl
    };
  }

  global.NounspaceProxy = global.NounspaceProxy || {};
  global.NounspaceProxy.create = createClient;
})(typeof window !== 'undefined' ? window : this);
