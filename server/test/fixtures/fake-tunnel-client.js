'use strict';

// A stand-in for a tunnel client. It publishes a local address and forwards
// every request to the loopback port the sender started, so it sees the
// sealed invitation only, exactly like a real tunnel operator.
//
// Usage: node fake-tunnel-client.js <target-port>
// It prints the published address on stdout and keeps running until stopped.

const http = require('node:http');

const targetPort = Number(process.argv[2]);
if (!Number.isInteger(targetPort) || targetPort < 1) {
  process.stderr.write('a target port is required\n');
  process.exit(2);
}

const server = http.createServer((req, res) => {
  const chunks = [];
  req.on('data', chunk => chunks.push(chunk));
  req.on('end', async () => {
    try {
      const headers = { 'Content-Type': req.headers['content-type'] || 'application/json' };
      if (req.headers.authorization) headers.Authorization = req.headers.authorization;
      const upstream = await fetch(`http://127.0.0.1:${targetPort}${req.url}`, {
        method: req.method, headers,
        ...(chunks.length ? { body: Buffer.concat(chunks) } : {}), redirect: 'error' });
      res.writeHead(upstream.status, { 'Content-Type': upstream.headers.get('content-type') || 'application/json' });
      res.end(Buffer.from(await upstream.arrayBuffer()));
    } catch { res.writeHead(502).end(); }
  });
});

server.listen(0, '127.0.0.1', () => {
  const port = server.address().port;
  // A synthetic host: the tests never contact a real tunnel operator.
  process.stdout.write(`synthetic0000.synthetic-tunnel.test tunneled with tls termination, http://localhost:${port}\n`);
});
