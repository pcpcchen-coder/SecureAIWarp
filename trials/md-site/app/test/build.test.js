'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');
const { buildSite, slugify, outputPathFor } = require('../src/build');
const { parseArgs } = require('../bin/md-site');

const CLI = path.join(__dirname, '..', 'bin', 'md-site.js');
let tmp, src, out;

function write(rel, content) {
  const p = path.join(src, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
}
const read = (rel) => fs.readFileSync(path.join(out, rel), 'utf8');
const exists = (rel) => fs.existsSync(path.join(out, rel));
const build = (extra = {}) => buildSite({ input: src, output: out, ...extra });

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'md-site-test-'));
  src = path.join(tmp, 'notes');
  out = path.join(tmp, 'site');
  fs.mkdirSync(src);
});
afterEach(() => fs.rmSync(tmp, { recursive: true, force: true }));

test('每篇筆記產生一頁，保留子資料夾結構', () => {
  write('a.md', '# A');
  write('sub/b.md', '# B');
  write('sub/deep/c.markdown', '# C');
  const r = build();
  assert.equal(r.pages, 3);
  assert.ok(exists('a.html'));
  assert.ok(exists('sub/b.html'));
  assert.ok(exists('sub/deep/c.html'));
  assert.ok(exists('index.html'));
});

test('首頁目錄列出所有筆記並使用標題', () => {
  write('a.md', '# 第一篇');
  write('sub/b.md', '---\ntitle: 前言標題\n---\n# 不是這個');
  write('sub/no-heading.md', '沒有標題');
  build({ title: '我的筆記' });
  const idx = read('index.html');
  assert.match(idx, /<title>我的筆記<\/title>/);
  assert.match(idx, /href="a\.html">第一篇</);
  assert.match(idx, /href="sub\/b\.html">前言標題</);
  assert.match(idx, /href="sub\/no-heading\.html">no-heading</);
  assert.match(idx, /<summary>sub<\/summary>/);
  assert.match(idx, /3 篇筆記/);
});

test('程式碼區塊有語法上色並附上樣式表', () => {
  write('code.md', '```js\nconst x = 1;\n```\n\n```nosuchlang\n<b>raw</b>\n```');
  build();
  const html = read('code.html');
  assert.match(html, /<code class="hljs language-js"><span class="hljs-keyword">const<\/span>/);
  assert.match(html, /&lt;b&gt;raw&lt;\/b&gt;/, '未知語言要跳脫 HTML');
  assert.ok(exists('assets/hljs-light.css'));
  assert.ok(exists('assets/hljs-dark.css'));
  assert.ok(exists('assets/style.css'));
  assert.match(html, /href="assets\/style\.css"/);
});

test('筆記之間的 .md 連結改寫為 .html，含相對路徑與錨點', () => {
  write('a.md', '[去 B](sub/b.md#第二節) [無副檔名](sub/b)');
  write('sub/b.md', '# B\n## 第二節\n[回 A](../a.md) [自己](#第二節)');
  const r = build();
  const a = read('a.html');
  assert.match(a, /href="sub\/b\.html#%E7%AC%AC%E4%BA%8C%E7%AF%80"/);
  assert.match(a, /href="sub\/b\.html">無副檔名/);
  const b = read('sub/b.html');
  assert.match(b, /href="\.\.\/a\.html">回 A/);
  assert.match(b, /<h2 id="第二節">/);
  assert.match(b, /href="\.\.\/assets\/style\.css"/);
  assert.match(b, /href="\.\.\/index\.html"/);
  assert.equal(r.brokenLinks.length, 0);
});

test('支援 [[wiki 連結]] 與別名，程式碼內不轉換', () => {
  write('a.md', '見 [[目標筆記]] 和 [[目標筆記|別名]] 和 [[目標筆記#小節]]\n\n`[[不轉換]]`');
  write('x/目標筆記.md', '# T\n## 小節');
  build();
  const a = read('a.html');
  const href = 'x/' + encodeURIComponent('目標筆記') + '.html';
  assert.ok(a.includes(`href="${href}">目標筆記</a>`));
  assert.ok(a.includes(`href="${href}">別名</a>`));
  assert.ok(a.includes(`href="${href}#小節">`));
  assert.match(a, /<code>\[\[不轉換\]\]<\/code>/);
});

test('圖片與其他檔案會被複製，圖片路徑可用', () => {
  write('notes/p.md', '![圖](img/pic.png)');
  write('notes/img/pic.png', 'PNGDATA');
  write('files/doc.pdf', 'PDF');
  const r = build();
  assert.equal(r.assets, 2);
  assert.equal(read('notes/img/pic.png'), 'PNGDATA');
  assert.ok(exists('files/doc.pdf'));
  assert.match(read('notes/p.html'), /<img src="img\/pic\.png" alt="圖"/);
});

test('失效連結會被回報並標記，外部連結保持不變', () => {
  write('a.md', '[壞](missing.md) [[不存在]] [外部](https://example.com/x.md) [信](mailto:a@b.c)');
  const r = build();
  assert.equal(r.brokenLinks.length, 2);
  const a = read('a.html');
  assert.match(a, /href="missing\.md" class="broken-link"/);
  assert.match(a, /href="https:\/\/example\.com\/x\.md"/);
  assert.match(a, /href="mailto:a@b\.c"/);
});

test('檔名含空白時連結會正確編碼', () => {
  write('my note.md', '# N');
  write('a.md', '[n](my%20note.md) [m](<my note.md>)');
  const r = build();
  assert.ok(exists('my note.html'));
  const a = read('a.html');
  assert.equal((a.match(/href="my%20note\.html"/g) || []).length, 2);
  assert.equal(r.brokenLinks.length, 0);
});

test('根目錄的 index.md 不會覆蓋首頁', () => {
  write('index.md', '# 我的首頁筆記');
  write('a.md', '[首頁筆記](index.md)');
  build();
  assert.ok(exists('index-note.html'));
  assert.match(read('index.html'), /href="index-note\.html">我的首頁筆記/);
  assert.match(read('a.html'), /href="index-note\.html"/);
});

test('略過隱藏資料夾，輸出資料夾在輸入內時不會遞迴收錄', () => {
  write('.obsidian/x.md', '# hidden');
  write('a.md', '# A');
  out = path.join(src, '_site');
  build();
  assert.ok(!exists('.obsidian/x.html'));
  // 第二次建置不應把 _site 內容當成筆記
  const r = build();
  assert.equal(r.pages, 1);
});

test('重複標題產生不重複的 id；slugify 保留中文', () => {
  assert.equal(slugify('Hello World!'), 'hello-world');
  assert.equal(slugify('非同步 程式'), '非同步-程式');
  write('a.md', '## Same\n## Same');
  build();
  const a = read('a.html');
  assert.match(a, /id="same"/);
  assert.match(a, /id="same-1"/);
});

test('標題中的 HTML 會被跳脫', () => {
  write('a.md', '---\ntitle: "<script>x</script>"\n---\nbody');
  build();
  assert.ok(!read('index.html').includes('<script>x</script>'));
  assert.match(read('a.html'), /&lt;script&gt;x&lt;\/script&gt;/);
});

test('--clean 會清除舊輸出；不合法的輸入/輸出會丟出錯誤', () => {
  write('a.md', '# A');
  fs.mkdirSync(out, { recursive: true });
  fs.writeFileSync(path.join(out, 'stale.html'), 'old');
  build({ clean: true });
  assert.ok(!exists('stale.html'));
  assert.throws(() => buildSite({ input: path.join(tmp, 'nope'), output: out }), /not found/);
  assert.throws(() => buildSite({ input: src, output: src }), /differ/);
  assert.throws(() => buildSite({ input: src, output: tmp }), /must not contain/);
});

test('outputPathFor 對應規則', () => {
  assert.equal(outputPathFor('a/b.md'), 'a/b.html');
  assert.equal(outputPathFor('x.markdown'), 'x.html');
  assert.equal(outputPathFor('index.md'), 'index-note.html');
  assert.equal(outputPathFor('sub/index.md'), 'sub/index.html');
});

test('CLI 參數解析', () => {
  assert.deepEqual(
    parseArgs(['notes', '-o', 'site', '--title', 'T', '--clean']),
    { input: 'notes', output: 'site', title: 'T', clean: true, strict: false, quiet: false });
  assert.throws(() => parseArgs(['--bogus']), /未知選項/);
  assert.throws(() => parseArgs(['-o']), /需要一個值/);
});

test('CLI 端對端執行與結束碼', () => {
  write('a.md', '# A\n[壞](nope.md)');
  let r = spawnSync(process.execPath, [CLI, src, '-o', out], { encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /Built 1 page/);
  assert.match(r.stderr, /broken link/);
  assert.ok(exists('a.html'));

  r = spawnSync(process.execPath, [CLI, src, '-o', out, '--strict', '-q'], { encoding: 'utf8' });
  assert.equal(r.status, 2);
  assert.equal(r.stderr, '');

  r = spawnSync(process.execPath, [CLI], { encoding: 'utf8' });
  assert.equal(r.status, 1);
  assert.match(r.stderr, /用法/);

  r = spawnSync(process.execPath, [CLI, '--help'], { encoding: 'utf8' });
  assert.equal(r.status, 0);
  assert.match(r.stdout, /用法/);
});
