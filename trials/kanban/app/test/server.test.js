'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const TMP_ROOT = require('path').join(__dirname, '..', '.test-tmp');
const path = require('path');
const http = require('http');
const { createServer } = require('../server');

let dir;
let dataFile;
let server;
let base;

function startServer() {
  return new Promise((resolve) => {
    const s = createServer({ dataFile });
    s.listen(0, '127.0.0.1', () => resolve(s));
  });
}

before(async () => {
  dir = (fs.mkdirSync(TMP_ROOT, { recursive: true }), fs.mkdtempSync(path.join(TMP_ROOT, 'kanban-http-')));
  dataFile = path.join(dir, 'board.json');
  server = await startServer();
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  server.close();
  fs.rmSync(dir, { recursive: true, force: true });
});

async function req(method, url, body, headers = {}) {
  const opts = { method, headers: { ...headers } };
  if (body !== undefined) {
    opts.headers['Content-Type'] = opts.headers['Content-Type'] || 'application/json';
    opts.body = typeof body === 'string' ? body : JSON.stringify(body);
  }
  const res = await fetch(base + url, opts);
  const text = await res.text();
  return { status: res.status, headers: res.headers, body: text ? JSON.parse(text) : null };
}

// fetch() won't let us forge the Host header, so use the raw http module for that test.
function rawGet(pathname, host) {
  return new Promise((resolve, reject) => {
    const r = http.request(
      { host: '127.0.0.1', port: server.address().port, path: pathname, headers: { Host: host } },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
      },
    );
    r.on('error', reject);
    r.end();
  });
}

test('首頁與靜態檔可以載入', async () => {
  for (const [p, type] of [['/', 'text/html'], ['/app.js', 'text/javascript'], ['/helpers.js', 'text/javascript'], ['/style.css', 'text/css']]) {
    const res = await fetch(base + p);
    assert.equal(res.status, 200, p);
    assert.ok(res.headers.get('content-type').startsWith(type), p);
  }
  const html = await (await fetch(base + '/')).text();
  assert.match(html, /待辦/);
  assert.match(html, /進行中/);
  assert.match(html, /完成/);
});

test('靜態檔不允許路徑穿越', async () => {
  const status = await rawGet('/../server.js', 'localhost');
  assert.equal(status, 404);
  const status2 = await rawGet('/%2e%2e/server.js', 'localhost');
  assert.equal(status2, 404);
});

test('完整 CRUD 流程與搜尋', async () => {
  let r = await req('POST', '/api/cards', { title: '寫週報', tags: ['工作'], dueDate: '2026-12-01' });
  assert.equal(r.status, 201);
  const card = r.body.card;
  assert.equal(card.column, 'todo');

  r = await req('POST', '/api/cards', { title: '買菜', column: 'doing', description: '牛奶' });
  assert.equal(r.status, 201);
  const second = r.body.card;

  r = await req('GET', '/api/cards');
  assert.equal(r.status, 200);
  assert.equal(r.body.cards.length, 2);

  r = await req('GET', '/api/cards?q=' + encodeURIComponent('牛奶'));
  assert.deepEqual(r.body.cards.map((c) => c.title), ['買菜']);

  r = await req('PATCH', `/api/cards/${card.id}`, { title: '寫月報', tags: ['工作', '重要'] });
  assert.equal(r.status, 200);
  assert.equal(r.body.card.title, '寫月報');
  assert.deepEqual(r.body.card.tags, ['工作', '重要']);
  assert.equal(r.body.card.dueDate, '2026-12-01');

  r = await req('POST', `/api/cards/${card.id}/move`, { column: 'doing', beforeId: second.id });
  assert.equal(r.status, 200);
  r = await req('GET', '/api/cards');
  assert.deepEqual(r.body.cards.map((c) => [c.title, c.column]), [['寫月報', 'doing'], ['買菜', 'doing']]);

  r = await req('DELETE', `/api/cards/${second.id}`);
  assert.equal(r.status, 204);
  r = await req('GET', `/api/cards/${second.id}`);
  assert.equal(r.status, 404);

  r = await req('DELETE', `/api/cards/${card.id}`);
  assert.equal(r.status, 204);
});

test('資料在伺服器重啟後仍在', async () => {
  const r = await req('POST', '/api/cards', { title: '重啟測試', column: 'done' });
  const id = r.body.card.id;
  await new Promise((resolve) => server.close(resolve));
  server = await startServer();
  base = `http://127.0.0.1:${server.address().port}`;
  const g = await req('GET', `/api/cards/${id}`);
  assert.equal(g.status, 200);
  assert.equal(g.body.card.title, '重啟測試');
  assert.equal(g.body.card.column, 'done');
  const onDisk = JSON.parse(fs.readFileSync(dataFile, 'utf8'));
  assert.ok(onDisk.cards.some((c) => c.id === id));
});

test('錯誤輸入回傳 4xx 與中文錯誤訊息', async () => {
  let r = await req('POST', '/api/cards', { title: '' });
  assert.equal(r.status, 400);
  assert.ok(r.body.error);

  r = await req('POST', '/api/cards', '{bad json');
  assert.equal(r.status, 400);

  r = await req('POST', '/api/cards', 'title=x', { 'Content-Type': 'application/x-www-form-urlencoded' });
  assert.equal(r.status, 415);

  r = await req('PATCH', '/api/cards/does-not-exist', { title: 'x' });
  assert.equal(r.status, 404);

  r = await req('POST', '/api/cards/does-not-exist/move', { column: 'done' });
  assert.equal(r.status, 404);

  r = await req('PUT', '/api/cards', {});
  assert.equal(r.status, 405);

  r = await req('GET', '/api/unknown');
  assert.equal(r.status, 404);
});

test('過大的請求內容會被拒絕', async () => {
  const big = JSON.stringify({ title: 'x', description: 'y'.repeat(1.5 * 1024 * 1024) });
  let status;
  try {
    status = (await req('POST', '/api/cards', big)).status;
  } catch {
    status = 413; // server may close the socket before the client finishes sending
  }
  assert.equal(status, 413);
});

test('拒絕非 localhost 的 Host（防 DNS rebinding）', async () => {
  assert.equal(await rawGet('/api/cards', 'evil.example.com'), 403);
  assert.equal(await rawGet('/api/cards', 'localhost:3000'), 200);
  assert.equal(await rawGet('/api/cards', '127.0.0.1'), 200);
});
