'use strict';
const https = require('https');

/**
 * Minimal JSON HTTP helpers shared by the threat-intel handlers.
 * Both resolve { status, data } and reject on network/timeout/parse error.
 * `opts.timeout` is in milliseconds (default 8000).
 */
function httpGet(url, headers = {}, opts = {}) {
  const timeout = opts.timeout || 8000;
  return new Promise((resolve, reject) => {
    const req = https.get(url, { headers }, (res) => {
      let body = '';
      res.on('data', (c) => (body += c));
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, data: JSON.parse(body) });
        } catch {
          reject(new Error('Failed to parse response: ' + body.slice(0, 200)));
        }
      });
    });
    req.on('error', reject);
    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
  });
}

function httpPost(url, postBody, headers = {}, opts = {}) {
  const timeout = opts.timeout || 8000;
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = https.request(
      {
        hostname: u.hostname,
        path: u.pathname + u.search,
        method: 'POST',
        headers: { ...headers },
      },
      (res) => {
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, data: JSON.parse(body) });
          } catch {
            reject(new Error('Failed to parse response: ' + body.slice(0, 200)));
          }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(timeout, () => {
      req.destroy();
      reject(new Error('Request timeout'));
    });
    req.write(postBody);
    req.end();
  });
}

/**
 * Like httpGet but resolves the raw response body as text (no JSON parse) and
 * follows up to `opts.maxRedirects` (default 3) redirects. Used by handlers
 * whose upstream returns text/plain (HackerTarget CSV) or very large payloads
 * (MITRE ATT&CK STIX bundle) that we parse ourselves.
 */
function httpGetText(url, headers = {}, opts = {}) {
  const timeout = opts.timeout || 8000;
  const maxRedirects = opts.maxRedirects ?? 3;
  return new Promise((resolve, reject) => {
    const visit = (u, redirectsLeft) => {
      const req = https.get(u, { headers }, (res) => {
        const sc = res.statusCode;
        if (sc >= 300 && sc < 400 && res.headers.location && redirectsLeft > 0) {
          res.resume(); // drain so the socket can be reused
          let next;
          try {
            next = new URL(res.headers.location, u).toString();
          } catch {
            return reject(new Error('Invalid redirect location'));
          }
          return visit(next, redirectsLeft - 1);
        }
        let body = '';
        res.on('data', (c) => (body += c));
        res.on('end', () => resolve({ status: sc, text: body }));
      });
      req.on('error', reject);
      req.setTimeout(timeout, () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
    };
    visit(url, maxRedirects);
  });
}

module.exports = { httpGet, httpPost, httpGetText };
