'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const { Store } = require('./lib/store');

const PUBLIC_DIR = path.join(__dirname, 'public');
const DEFAULT_DATA_FILE = path.join(__dirname, 'data', 'board.json');
const MAX_BODY = 1024 * 1024;
const STATIC_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
};
const ALLOWED_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

function send(res, status, body) {
  const payload = body === undefined ? '' : JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    const type = (req.headers['content-type'] || '').toLowerCase();
    if (!type.startsWith('application/json')) {
      const err = new Error('Content-Type 必須是 application/json');
      err.status = 415;
      reject(err);
      return;
    }
    let size = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        const err = new Error('請求內容過大');
        err.status = 413;
        reject(err);
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const text = Buffer.concat(chunks).toString('utf8');
        resolve(text ? JSON.parse(text) : {});
      } catch {
        const err = new Error('JSON 格式錯誤');
        err.status = 400;
        reject(err);
      }
    });
    req.on('error', reject);
  });
}

function hostAllowed(hostHeader) {
  if (!hostHeader) return false;
  const host = hostHeader.replace(/:\d+$/, '').toLowerCase();
  return ALLOWED_HOSTS.has(host);
}

function serveStatic(req, res, pathname) {
  const rel = pathname === '/' ? 'index.html' : pathname.slice(1);
  const filePath = path.resolve(PUBLIC_DIR, rel);
  if (!filePath.startsWith(PUBLIC_DIR + path.sep)) {
    send(res, 404, { error: '找不到' });
    return;
  }
  fs.readFile(filePath, (err, data) => {
    if (err) {
      send(res, 404, { error: '找不到' });
      return;
    }
    res.writeHead(200, {
      'Content-Type': STATIC_TYPES[path.extname(filePath)] || 'application/octet-stream',
      'X-Content-Type-Options': 'nosniff',
      'Content-Security-Policy': "default-src 'self'; style-src 'self'; script-src 'self'; frame-ancestors 'none'",
    });
    res.end(data);
  });
}

function createServer({ dataFile = DEFAULT_DATA_FILE } = {}) {
  const store = new Store(dataFile);

  async function handleApi(req, res, url) {
    const parts = url.pathname.split('/').filter(Boolean); // ['api','cards',id?,'move'?]
    if (parts[1] !== 'cards' || parts.length > 4) return send(res, 404, { error: '找不到' });
    const id = parts[2] ? decodeURIComponent(parts[2]) : null;
    const action = parts[3] || null;

    if (!id && req.method === 'GET') {
      return send(res, 200, { cards: store.list(url.searchParams.get('q')) });
    }
    if (!id && req.method === 'POST') {
      return send(res, 201, { card: store.create(await readJson(req)) });
    }
    if (id && !action && req.method === 'GET') {
      return send(res, 200, { card: store.get(id) });
    }
    if (id && !action && (req.method === 'PATCH' || req.method === 'PUT')) {
      return send(res, 200, { card: store.update(id, await readJson(req)) });
    }
    if (id && !action && req.method === 'DELETE') {
      store.remove(id);
      res.writeHead(204);
      return res.end();
    }
    if (id && action === 'move' && req.method === 'POST') {
      const body = await readJson(req);
      return send(res, 200, { card: store.move(id, body.column, body.beforeId) });
    }
    return send(res, 405, { error: '不支援的操作' });
  }

  const server = http.createServer(async (req, res) => {
    // Block DNS-rebinding: only answer requests addressed to localhost.
    if (!hostAllowed(req.headers.host)) {
      return send(res, 403, { error: '只接受 localhost 連線' });
    }
    let url;
    try {
      url = new URL(req.url, 'http://localhost');
    } catch {
      return send(res, 400, { error: '網址錯誤' });
    }
    try {
      if (url.pathname.startsWith('/api/')) {
        await handleApi(req, res, url);
      } else if (req.method === 'GET' || req.method === 'HEAD') {
        serveStatic(req, res, url.pathname);
      } else {
        send(res, 405, { error: '不支援的操作' });
      }
    } catch (err) {
      const status = err.status || 500;
      if (status === 500) console.error(err);
      if (!res.headersSent) send(res, status, { error: status === 500 ? '伺服器錯誤' : err.message });
    }
  });

  server.store = store;
  return server;
}

if (require.main === module) {
  const port = Number(process.env.PORT) || 3000;
  const host = process.env.HOST || '127.0.0.1';
  const dataFile = process.env.KANBAN_DATA_FILE || DEFAULT_DATA_FILE;
  const server = createServer({ dataFile });
  server.listen(port, host, () => {
    console.log(`看板已啟動：http://localhost:${port}`);
    console.log(`資料檔：${path.resolve(dataFile)}`);
  });
}

module.exports = { createServer };
