'use strict';

const fs = require('node:fs');
const http = require('node:http');
const https = require('node:https');
const net = require('node:net');
const { createShareRelay } = require('./share-relay');
const { shareInvitePage } = require('./share-invite-page');

function isPublicIPv4(host) {
  if (net.isIP(host) !== 4) return false;
  const [a, b, c] = host.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || a === 100 && b >= 64 && b <= 127
    || a === 169 && b === 254
    || a === 172 && b >= 16 && b <= 31
    || a === 192 && (b === 168 || b === 0 && c === 0 || b === 0 && c === 2 || b === 88 && c === 99)
    || a === 198 && (b === 18 || b === 19 || b === 51 && c === 100)
    || a === 203 && b === 0 && c === 113);
}

function directOrigin(value, { allowLoopback = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new Error('invalid direct share URL'); }
  const host = url.hostname;
  if (!['http:', 'https:'].includes(url.protocol) || !url.port
      || url.pathname !== '/' || url.search || url.hash || url.username || url.password
      || !(isPublicIPv4(host) || allowLoopback && net.isIP(host) === 4 && host.startsWith('127.'))) {
    throw new Error('direct share URL must use a public IPv4 address and explicit port');
  }
  return url.origin;
}

function tunnelOrigin(value, { allowLoopback = false } = {}) {
  let url;
  try { url = new URL(value); } catch { throw new Error('invalid tunnel share URL'); }
  const loopback = allowLoopback && url.protocol === 'http:' && ['127.0.0.1', 'localhost'].includes(url.hostname);
  if (!loopback && url.protocol !== 'https:') throw new Error('tunnel share URL must use https');
  if (url.username || url.password || url.search || url.hash || url.pathname !== '/' || !url.hostname) {
    throw new Error('tunnel share URL must be a plain https origin (no path, query, fragment or credentials)');
  }
  return url.origin;
}

function createDirectShareEndpoints({ publicUrl, certFile, keyFile, probeToken, allowLoopback = false, tunnelPort = null } = {}) {
  const isTunnel = !!tunnelPort;
  const origin = isTunnel ? tunnelOrigin(publicUrl, { allowLoopback }) : directOrigin(publicUrl, { allowLoopback });
  const url = new URL(origin);
  if (!isTunnel && url.protocol === 'https:' && (!certFile || !keyFile)) throw new Error('direct HTTPS share requires a certificate and private key');
  if (!isTunnel && url.protocol === 'http:' && (certFile || keyFile)) throw new Error('direct HTTP share must not specify TLS files');
  if (isTunnel && (certFile || keyFile)) throw new Error('tunnel share must not specify TLS files');
  const relay = createShareRelay();
  let activeProbeToken = probeToken || null;
  const handle = (req, res, internal = false) => {
    let route;
    try { route = new URL(req.url, 'http://localhost'); }
    catch { res.writeHead(400).end(); return; }
    if (!internal && activeProbeToken && req.method === 'GET'
        && route.pathname === `/api/share-relay/probe/${activeProbeToken}`) {
      res.writeHead(204, { 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' }).end();
      return;
    }
    if (req.method === 'GET' && /^\/api\/share-relay\/invite\/[a-f0-9]{32}$/.test(route.pathname)) {
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store',
        'Referrer-Policy': 'no-referrer', 'X-Content-Type-Options': 'nosniff',
        'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'" });
      res.end(shareInvitePage(req.headers['accept-language'] || ''));
      return;
    }
    // The public listener only serves recipient operations. Session creation,
    // owner polling, envelope writes and cancellation stay on loopback.
    if (!internal && !(
      req.method === 'POST' && /^\/api\/share-relay\/sessions\/[a-f0-9]{32}\/(claim|ack)$/.test(route.pathname)
      || req.method === 'GET' && /^\/api\/share-relay\/sessions\/[a-f0-9]{32}\/envelope$/.test(route.pathname)
    )) {
      res.writeHead(404, { 'Cache-Control': 'no-store' }).end();
      return;
    }
    Promise.resolve(relay.handle(req, res, route)).then(handled => {
      if (!handled && !res.headersSent) res.writeHead(404, { 'Cache-Control': 'no-store' }).end();
    }).catch(() => { if (!res.headersSent) res.writeHead(500).end(); else res.destroy(); });
  };
  let external;
  let internal;
  let starting;
  const listen = (server, port, host) => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, host, () => { server.removeListener('error', reject); resolve(); });
  });
  const stop = async () => {
    const servers = [external, internal].filter(Boolean);
    external = internal = null;
    relay.stop();
    await Promise.all(servers.map(server => new Promise(resolve => server.close(resolve))));
  };
  const start = () => {
    if (starting) return starting;
    starting = (async () => {
      // A tunnel transport terminates TLS at the tunnel provider and forwards
      // plain HTTP to a loopback port, so the recipient-facing listener stays
      // on 127.0.0.1 and never binds a public interface.
      external = !isTunnel && url.protocol === 'https:'
        ? https.createServer({ cert: fs.readFileSync(certFile), key: fs.readFileSync(keyFile) }, (req, res) => handle(req, res))
        : http.createServer((req, res) => handle(req, res));
      internal = http.createServer((req, res) => handle(req, res, true));
      for (const server of [external, internal]) {
        server.requestTimeout = 10000;
        server.headersTimeout = 10000;
      }
      try {
        await listen(external, isTunnel ? tunnelPort : Number(url.port), isTunnel ? '127.0.0.1' : '0.0.0.0');
        await listen(internal, 0, '127.0.0.1');
        return { publicUrl: origin, localUrl: `http://127.0.0.1:${internal.address().port}`,
          tunnelLocalUrl: isTunnel ? `http://127.0.0.1:${external.address().port}` : null };
      } catch (error) {
        await stop();
        starting = null;
        throw error;
      }
    })();
    return starting;
  };
  return { start, stop, setProbeToken: token => { activeProbeToken = token || null; } };
}

module.exports = { directOrigin, tunnelOrigin, isPublicIPv4, createDirectShareEndpoints };
