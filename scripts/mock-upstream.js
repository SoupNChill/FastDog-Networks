#!/usr/bin/env node
/** Tiny mock origin for local proxy/agent tests. LAN-only helper. */
import http from 'node:http';

const PORT = Number(process.env.MOCK_PORT || 9999);
const server = http.createServer((req, res) => {
  const body = JSON.stringify({
    mock: true,
    service: 'fastdog-mock-upstream',
    method: req.method,
    url: req.url,
    host: req.headers.host,
  });
  res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
  res.end(body);
});
server.listen(PORT, '127.0.0.1', () => {
  console.log(`mock upstream on http://127.0.0.1:${PORT}`);
});
