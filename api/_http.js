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

module.exports = { httpGet, httpPost };
