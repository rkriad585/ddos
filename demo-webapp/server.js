const http = require('http');
const https = require('https');
const dgram = require('dgram');
const net = require('net');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT || 3030);
const TLS_PORT = Number(process.env.TLS_PORT || 3043);
const UDP_PORT = Number(process.env.UDP_PORT || 3031);
const DNS_PORT = Number(process.env.DNS_PORT || 3053);
const PROXY_PORT = Number(process.env.PROXY_PORT || 8080);
const STRESS_LIMIT_RPS = Number(process.env.STRESS_LIMIT_RPS || 22);
const API_LIMIT_RPS = Number(process.env.API_LIMIT_RPS || 30);
const ROOT = __dirname;

const SECURE_HEADERS = {
  'Strict-Transport-Security': 'max-age=63072000; includeSubDomains',
  'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Permissions-Policy': 'geolocation=(), camera=(), microphone=()',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Embedder-Policy': 'require-corp'
};

const PARTIAL_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'Referrer-Policy': 'no-referrer',
  'Access-Control-Allow-Origin': '*'
};

const DEMO_ENV = {
  DEMO_SECRET: process.env.DEMO_SECRET || 'flag{env_secret}',
  DEMO_API_KEY: process.env.DEMO_API_KEY || 'demo-api-key-123',
  DEMO_DB_PASSWORD: process.env.DEMO_DB_PASSWORD || 'postgres://demo:demo@127.0.0.1/demo'
};

const users = [
  { id: 1, user: 'admin', password: 'admin123', role: 'admin', email: 'admin@demo.local' },
  { id: 2, user: 'alice', password: 'alice123', role: 'user', email: 'alice@demo.local' },
  { id: 3, user: 'bob', password: 'bob123', role: 'user', email: 'bob@demo.local' }
];

const metrics = {
  started_at: new Date().toISOString(),
  total: 0,
  by_status: {},
  by_path: {},
  api_rate_limited: 0,
  stress_rejected: 0,
  proxy_requests: 0
};

const apiWindow = new Map();
const stressWindow = new Map();

function overLimit(map, limit) {
  const second = Math.floor(Date.now() / 1000);
  const next = (map.get(second) || 0) + 1;
  map.set(second, next);
  for (const key of map.keys()) {
    if (key < second - 2) map.delete(key);
  }
  return next > limit;
}

function track(res, pathname) {
  let recorded = false;
  const original = res.writeHead.bind(res);
  res.writeHead = (status, headers) => {
    if (!recorded) {
      recorded = true;
      metrics.total += 1;
      metrics.by_status[status] = (metrics.by_status[status] || 0) + 1;
      metrics.by_path[pathname] = (metrics.by_path[pathname] || 0) + 1;
    }
    return original(status, headers);
  };
  return res;
}

function baseHeaders(profile) {
  return {
    Server: 'ddos-demo/1.0',
    'X-Powered-By': 'Express/5.1.0',
    'X-Demo-Profile': profile,
    ...(profile === 'full' ? SECURE_HEADERS : profile === 'partial' ? PARTIAL_HEADERS : {})
  };
}

function send(req, res, status, profile, headers, body) {
  const merged = { ...baseHeaders(profile), ...(headers || {}) };
  if (body !== undefined && body !== null) {
    if (!merged['Content-Type']) merged['Content-Type'] = 'application/json; charset=utf-8';
    if (req.method !== 'HEAD') merged['Content-Length'] = Buffer.byteLength(body);
    res.writeHead(status, merged);
    res.end(req.method === 'HEAD' ? undefined : body);
    return;
  }
  res.writeHead(status, merged);
  res.end();
}

function sendJson(req, res, status, value, profile, headers) {
  send(req, res, status, profile || 'none', {
    'Content-Type': 'application/json; charset=utf-8',
    ...(headers || {})
  }, JSON.stringify(value));
}

function sendHtml(req, res, status, value, profile, headers) {
  send(req, res, status, profile || 'none', {
    'Content-Type': 'text/html; charset=utf-8',
    ...(headers || {})
  }, value);
}

function isLoopback(host) {
  if (!host) return false;
  if (host === 'localhost') return true;
  const value = host.replace(/^\[|\]$/g, '');
  if (net.isIP(value) === 4) return value.startsWith('127.');
  if (net.isIP(value) === 6) return value === '::1';
  return false;
}

function home(query) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>ddos demo target</title></head>
<body>
<h1>ddos demo target</h1>
<p>Intentionally vulnerable. Loopback only.</p>
<form method="get" action="/"><input name="q" value="${query}"><button>Search</button></form>
<p>You searched for: ${query}</p>
<ul>
<li><a href="/headers/full">/headers/full</a></li>
<li><a href="/headers/partial">/headers/partial</a></li>
<li><a href="/headers/none">/headers/none</a></li>
<li><a href="/api/users">/api/users</a></li>
<li><a href="/api/private">/api/private</a></li>
<li><a href="/admin">/admin</a></li>
<li><a href="/debug">/debug</a></li>
<li><a href="/download?file=package.json">/download</a></li>
<li><a href="/openapi.json">/openapi.json</a></li>
<li><a href="/metrics">/metrics</a></li>
</ul>
</body>
</html>`;
}

function dnsResponse(query) {
  if (query.length < 12) return null;
  let offset = 12;
  const labels = [];
  while (offset < query.length) {
    const length = query[offset];
    if (length === 0) {
      offset += 1;
      break;
    }
    if (length > 63 || offset + 1 + length > query.length) return null;
    labels.push(query.subarray(offset + 1, offset + 1 + length).toString('ascii'));
    offset += 1 + length;
  }
  if (offset + 4 > query.length) return null;
  const qtype = query.readUInt16BE(offset);
  const question = query.subarray(12, offset + 4);
  const name = labels.join('.');
  let rcode = 0;
  let answer = Buffer.alloc(0);
  if (name === 'missing.demo.local') {
    rcode = 3;
  } else if (qtype === 1) {
    answer = Buffer.from([0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 127, 0, 0, 1]);
  } else if (qtype === 28) {
    answer = Buffer.concat([
      Buffer.from([0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x10]),
      Buffer.from([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
    ]);
  } else if (qtype === 16) {
    const text = Buffer.from('ddos-demo');
    const rdata = Buffer.concat([Buffer.from([text.length]), text]);
    answer = Buffer.concat([
      Buffer.from([0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, rdata.length]),
      rdata
    ]);
  } else {
    rcode = 4;
  }
  const header = Buffer.alloc(12);
  query.copy(header, 0, 0, 2);
  header.writeUInt16BE(0x8180 + rcode, 2);
  header.writeUInt16BE(1, 4);
  header.writeUInt16BE(answer.length > 0 ? 1 : 0, 6);
  return Buffer.concat([header, question, answer]);
}

function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = url.pathname;
  track(res, pathname);

  if (pathname.startsWith('/api/') && overLimit(apiWindow, API_LIMIT_RPS)) {
    metrics.api_rate_limited += 1;
    sendJson(req, res, 429, { error: 'rate limited', limit_rps: API_LIMIT_RPS }, 'partial', { 'Retry-After': '1' });
    return;
  }

  if (pathname.startsWith('/stress') && overLimit(stressWindow, STRESS_LIMIT_RPS)) {
    metrics.stress_rejected += 1;
    sendJson(req, res, 503, { error: 'over capacity', limit_rps: STRESS_LIMIT_RPS }, 'none', { 'Retry-After': '1' });
    return;
  }

  if (pathname === '/health') {
    sendJson(req, res, 200, { status: 'ok', tls: TLS_PORT }, 'full');
    return;
  }

  if (pathname === '/stress') {
    sendJson(req, res, 200, { stress: true, limit_rps: STRESS_LIMIT_RPS }, 'none');
    return;
  }

  if (pathname === '/') {
    sendHtml(req, res, 200, home(url.searchParams.get('q') || 'hello'), 'none');
    return;
  }

  if (pathname === '/headers/full') {
    sendJson(req, res, 200, { profile: 'full', headers: SECURE_HEADERS }, 'full');
    return;
  }

  if (pathname === '/headers/partial') {
    sendJson(req, res, 200, { profile: 'partial', headers: PARTIAL_HEADERS }, 'partial');
    return;
  }

  if (pathname === '/headers/none') {
    sendJson(req, res, 200, { profile: 'none', headers: {} }, 'none');
    return;
  }

  if (pathname === '/api/users') {
    sendJson(req, res, 200, { users }, 'partial');
    return;
  }

  if (pathname === '/api/login') {
    const user = url.searchParams.get('user') || 'admin';
    sendJson(req, res, 200, {
      ok: true,
      user,
      token: user === 'admin' ? 'admin-token' : 'user-token',
      bypass: true
    }, 'partial', { 'Set-Cookie': 'session=admin-token; Path=/' });
    return;
  }

  if (pathname === '/api/private') {
    if (req.headers.authorization !== 'Bearer s3cr3t') {
      sendJson(req, res, 401, { error: 'unauthorized' }, 'partial', { 'WWW-Authenticate': 'Bearer' });
      return;
    }
    sendJson(req, res, 200, { ok: true, secret: 'flag{private_api}' }, 'partial');
    return;
  }

  if (pathname === '/api/admin') {
    if (req.headers.authorization !== 'Bearer admin-token') {
      sendJson(req, res, 403, { error: 'forbidden' }, 'partial');
      return;
    }
    sendJson(req, res, 200, { ok: true, flag: 'flag{admin_api}' }, 'full');
    return;
  }

  if (pathname === '/admin') {
    sendHtml(req, res, 200, '<h1>Admin panel</h1><p>flag{no_auth_required}</p>', 'none');
    return;
  }

  if (pathname === '/debug') {
    sendJson(req, res, 200, { cwd: process.cwd(), node: process.version, env: DEMO_ENV, users }, 'none');
    return;
  }

  if (pathname === '/redirect') {
    send(req, res, 302, 'none', { Location: url.searchParams.get('to') || '/headers/full' });
    return;
  }

  if (pathname === '/redirect/internal') {
    send(req, res, 302, 'none', { Location: '/headers/full' });
    return;
  }

  if (pathname === '/redirect/external') {
    send(req, res, 302, 'none', { Location: 'http://198.51.100.10/outside-scope' });
    return;
  }

  if (pathname === '/slow') {
    setTimeout(() => sendJson(req, res, 200, { slow: true }, 'none'), 1500);
    return;
  }

  if (pathname === '/slow-body') {
    if (req.method === 'HEAD') {
      send(req, res, 200, 'none', { 'Content-Type': 'text/plain' });
      return;
    }
    res.writeHead(200, { ...baseHeaders('none'), 'Content-Type': 'text/plain' });
    let index = 0;
    const timer = setInterval(() => {
      if (index >= 10) {
        clearInterval(timer);
        res.end();
        return;
      }
      res.write(`chunk-${index};`);
      index += 1;
    }, 300);
    return;
  }

  if (pathname === '/large') {
    const requested = Number(url.searchParams.get('bytes') || 1024);
    const size = Math.max(0, Math.min(Number.isFinite(requested) ? requested : 1024, 1048576));
    send(req, res, 200, 'none', { 'Content-Type': 'text/plain' }, 'A'.repeat(size));
    return;
  }

  if (pathname === '/status') {
    const code = Number(url.searchParams.get('code') || 200);
    const status = Number.isInteger(code) && code >= 100 && code <= 599 ? code : 200;
    if (status === 204 || status === 304) {
      send(req, res, status, 'none');
      return;
    }
    sendJson(req, res, status, { status }, 'none');
    return;
  }

  if (pathname === '/echo') {
    const chunks = [];
    req.on('data', (chunk) => {
      if (chunks.length < 64) chunks.push(chunk);
    });
    req.on('end', () => {
      const body = Buffer.concat(chunks).toString('utf8');
      sendJson(req, res, 200, {
        method: req.method,
        path: pathname,
        query: Object.fromEntries(url.searchParams),
        headers: req.headers,
        body_bytes: Buffer.byteLength(body),
        body_preview: body.slice(0, 200)
      }, 'partial');
    });
    return;
  }

  if (pathname === '/download') {
    const file = url.searchParams.get('file') || 'package.json';
    const target = path.resolve(ROOT, file);
    const repoRoot = path.resolve(ROOT, '..');
    if (!target.startsWith(repoRoot + path.sep) && target !== repoRoot) {
      sendJson(req, res, 403, { error: 'outside repository' }, 'none');
      return;
    }
    fs.readFile(target, (error, data) => {
      if (error) {
        sendJson(req, res, 404, { error: error.message }, 'none');
        return;
      }
      send(req, res, 200, 'none', { 'Content-Type': 'application/octet-stream' }, data);
    });
    return;
  }

  if (pathname === '/openapi.json') {
    sendJson(req, res, 200, {
      openapi: '3.0.0',
      info: { title: 'ddos demo target', version: '1.0.0' },
      paths: {
        '/health': { get: {} },
        '/headers/full': { get: {} },
        '/headers/partial': { get: {} },
        '/headers/none': { get: {} },
        '/api/users': { get: {} },
        '/api/login': { get: {} },
        '/api/private': { get: { security: [{ bearer: [] }] } },
        '/api/admin': { get: { security: [{ bearer: [] }] } },
        '/admin': { get: {} },
        '/debug': { get: {} },
        '/download': { get: {} },
        '/redirect': { get: {} },
        '/slow': { get: {} },
        '/metrics': { get: {} }
      }
    }, 'partial');
    return;
  }

  if (pathname === '/metrics') {
    sendJson(req, res, 200, { ...metrics, uptime_seconds: Math.round(process.uptime()) }, 'none');
    return;
  }

  if (pathname === '/reset-metrics' && req.method === 'POST') {
    metrics.total = 0;
    metrics.by_status = {};
    metrics.by_path = {};
    metrics.api_rate_limited = 0;
    metrics.stress_rejected = 0;
    metrics.proxy_requests = 0;
    metrics.started_at = new Date().toISOString();
    sendJson(req, res, 200, { reset: true }, 'none');
    return;
  }

  if (pathname === '/robots.txt') {
    send(req, res, 200, 'none', { 'Content-Type': 'text/plain' }, 'User-agent: *\nDisallow: /admin\nDisallow: /debug\n');
    return;
  }

  if (req.method === 'OPTIONS') {
    send(req, res, 204, 'partial', { Allow: 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS' });
    return;
  }

  if (pathname.includes('%00') || pathname.includes('%ff') || pathname.includes('%fe')) {
    sendJson(req, res, 400, { error: 'invalid path' }, 'none');
    return;
  }

  if (pathname === '/shape') {
    sendJson(req, res, 200, { shape: true, method: req.method }, 'partial');
    return;
  }

  sendJson(req, res, 404, { error: 'not found', path: pathname }, 'none');
}

const server = http.createServer(handler);
server.requestTimeout = 0;
server.headersTimeout = 0;
server.keepAliveTimeout = 65000;

const certPath = path.join(ROOT, 'certs', 'cert.pem');
const keyPath = path.join(ROOT, 'certs', 'key.pem');
let tlsServer = null;
if (fs.existsSync(certPath) && fs.existsSync(keyPath)) {
  tlsServer = https.createServer({ key: fs.readFileSync(keyPath), cert: fs.readFileSync(certPath) }, handler);
  tlsServer.requestTimeout = 0;
  tlsServer.headersTimeout = 0;
  tlsServer.listen(TLS_PORT, '127.0.0.1', () => {
    console.log(`https listening on https://127.0.0.1:${TLS_PORT} (self-signed)`);
  });
}

const proxy = http.createServer((req, res) => {
  metrics.proxy_requests += 1;
  let target;
  try {
    target = new URL(req.url);
  } catch {
    res.writeHead(400, { 'Content-Type': 'text/plain' });
    res.end('bad proxy request');
    return;
  }
  if (!isLoopback(target.hostname)) {
    res.writeHead(403, { 'Content-Type': 'text/plain' });
    res.end('proxy only allows loopback targets');
    return;
  }
  const upstream = http.request({
    hostname: target.hostname,
    port: target.port || 80,
    path: target.pathname + target.search,
    method: req.method,
    headers: { ...req.headers, host: target.host, 'x-proxy': 'ddos-demo-proxy' }
  }, (response) => {
    res.writeHead(response.statusCode, response.headers);
    response.pipe(res);
  });
  upstream.on('error', () => {
    if (!res.headersSent) res.writeHead(502, { 'Content-Type': 'text/plain' });
    res.end('bad gateway');
  });
  req.pipe(upstream);
});

proxy.on('connect', (req, clientSocket, head) => {
  metrics.proxy_requests += 1;
  const [host, portText] = req.url.split(':');
  if (!isLoopback(host)) {
    clientSocket.end('HTTP/1.1 403 Forbidden\r\n\r\n');
    return;
  }
  const port = Number(portText || 443);
  const upstream = net.connect(port, host, () => {
    clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
    upstream.write(head);
    upstream.pipe(clientSocket);
    clientSocket.pipe(upstream);
  });
  upstream.on('error', () => clientSocket.end('HTTP/1.1 502 Bad Gateway\r\n\r\n'));
});

const udp = dgram.createSocket('udp4');
udp.on('message', (message, remote) => {
  const reply = Buffer.concat([Buffer.from('echo:'), message]);
  udp.send(reply, remote.port, remote.address);
});
udp.on('error', (error) => console.error('udp error', error.message));

const dns = dgram.createSocket('udp4');
dns.on('message', (message, remote) => {
  const reply = dnsResponse(message);
  if (reply) dns.send(reply, remote.port, remote.address);
});
dns.on('error', (error) => console.error('dns error', error.message));

server.listen(PORT, '127.0.0.1', () => {
  console.log(`http listening on http://127.0.0.1:${PORT}`);
});

proxy.listen(PROXY_PORT, '127.0.0.1', () => {
  console.log(`proxy listening on http://127.0.0.1:${PROXY_PORT}`);
});

udp.bind(UDP_PORT, '127.0.0.1', () => {
  console.log(`udp echo listening on 127.0.0.1:${UDP_PORT}`);
});

dns.bind(DNS_PORT, '127.0.0.1', () => {
  console.log(`dns listening on 127.0.0.1:${DNS_PORT}`);
});
