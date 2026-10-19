#!/usr/bin/env node
'use strict'

// Local reverse proxy for the ZeroCreds local server.
//
// It gives the service a readable, self-describing address:
//
//   http://localhost/zerocreds/...  ->  http://127.0.0.1:3456/...
//
// Port 80 is privileged, so this is meant to run from a root LaunchDaemon
// (scripts/local-proxy.plist). The request path is forwarded unchanged: the
// server itself strips the mount prefix, which keeps one routing implementation
// for both the proxied and the direct address.
//
// The proxy is loopback-only: it binds 127.0.0.1 and ::1 and never a routable
// interface. The Host header is rewritten to the configured host so the server's
// own loopback check accepts the request.

const http = require('node:http')

const PORT = Number(process.env.ZEROCREDS_PROXY_PORT || 80)
const TARGET = new URL(process.env.ZEROCREDS_PROXY_TARGET || 'http://127.0.0.1:3456')
const HOST_HEADER = process.env.ZEROCREDS_PROXY_HOST || 'localhost'
const HOSTS = (process.env.ZEROCREDS_PROXY_HOSTS || '127.0.0.1,::1').split(',').map((h) => h.trim()).filter(Boolean)

const HOP_BY_HOP = new Set([
  'connection',
  'keep-alive',
  'proxy-authenticate',
  'proxy-authorization',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
])

function copyHeaders(source) {
  const headers = {}
  for (const [name, value] of Object.entries(source)) {
    if (!HOP_BY_HOP.has(name.toLowerCase())) headers[name] = value
  }
  return headers
}

function handle(req, res) {
  const headers = copyHeaders(req.headers)
  headers.host = HOST_HEADER

  const upstream = http.request(
    {
      protocol: TARGET.protocol,
      hostname: TARGET.hostname,
      port: TARGET.port || 80,
      method: req.method,
      path: req.url,
      headers,
    },
    (upstreamRes) => {
      res.writeHead(upstreamRes.statusCode || 502, copyHeaders(upstreamRes.headers))
      upstreamRes.pipe(res)
    },
  )

  upstream.on('error', (error) => {
    if (res.headersSent) {
      res.destroy()
      return
    }
    res.writeHead(502, { 'content-type': 'application/json' })
    res.end(JSON.stringify({ error: 'zerocreds local server is unreachable', detail: error.message }))
  })

  req.pipe(upstream)
}

let bound = 0
for (const host of HOSTS) {
  const server = http.createServer(handle)
  server.on('error', (error) => {
    console.error(`[zerocreds-proxy] cannot listen on ${host}:${PORT} (${error.code || error.message})`)
    if (bound === 0 && HOSTS.indexOf(host) === HOSTS.length - 1) process.exit(1)
  })
  server.listen(PORT, host, () => {
    bound += 1
    console.log(`[zerocreds-proxy] http://${host}:${PORT} -> ${TARGET.origin}`)
  })
}
