'use strict';

const { test, beforeEach, afterEach } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const TMP_ROOT = require('path').join(__dirname, '..', '.test-tmp');
const path = require('path');
const { Store, ValidationError, NotFoundError } = require('../lib/store');

let dir;
let file;

beforeEach(() => {
  dir = (fs.mkdirSync(TMP_ROOT, { recursive: true }), fs.mkdtempSync(path.join(TMP_ROOT, 'kanban-store-')));
  file = path.join(dir, 'board.json');
});
afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

const titles = (cards) => cards.map((c) => c.title);

test('新增卡片：預設在待辦欄並套用正規化', () => {
  const s = new Store(file);
  const c = s.create({ title: '  買牛奶  ', tags: [' 家務 ', '家務', ''], dueDate: '2026-12-01' });
  assert.equal(c.title, '買牛奶');
  assert.equal(c.column, 'todo');
  assert.deepEqual(c.tags, ['家務']);
  assert.equal(c.dueDate, '2026-12-01');
  assert.equal(c.description, '');
  assert.ok(c.id);
});

test('資料寫入檔案，重新開啟後仍在', () => {
  const s1 = new Store(file);
  const c = s1.create({ title: '持久化', column: 'doing' });
  const s2 = new Store(file);
  assert.deepEqual(s2.get(c.id), c);
  assert.ok(fs.existsSync(file));
});

test('不存在的資料檔會以空白看板啟動', () => {
  const s = new Store(path.join(dir, 'nested', 'x.json'));
  assert.deepEqual(s.list(), []);
});

test('損毀的資料檔會被備份而不是覆蓋', () => {
  fs.writeFileSync(file, '{not json');
  const s = new Store(file);
  assert.deepEqual(s.list(), []);
  const backups = fs.readdirSync(dir).filter((f) => f.includes('.corrupt-'));
  assert.equal(backups.length, 1);
  assert.equal(fs.readFileSync(path.join(dir, backups[0]), 'utf8'), '{not json');
});

test('驗證：空標題、錯誤欄位、錯誤日期、過長內容都會被拒絕', () => {
  const s = new Store(file);
  assert.throws(() => s.create({ title: '   ' }), ValidationError);
  assert.throws(() => s.create({}), ValidationError);
  assert.throws(() => s.create({ title: 'a', column: 'later' }), ValidationError);
  assert.throws(() => s.create({ title: 'a', dueDate: '2026-02-30' }), ValidationError);
  assert.throws(() => s.create({ title: 'a', dueDate: '12/01/2026' }), ValidationError);
  assert.throws(() => s.create({ title: 'x'.repeat(201) }), ValidationError);
  assert.throws(() => s.create({ title: 'a', tags: 'not-array' }), ValidationError);
  assert.throws(() => s.create({ title: 'a', tags: ['x'.repeat(31)] }), ValidationError);
  assert.equal(s.list().length, 0);
});

test('編輯：只更新提供的欄位，可清除到期日', () => {
  const s = new Store(file);
  const c = s.create({ title: '原標題', description: '說明', dueDate: '2026-12-01', tags: ['a'] });
  const u = s.update(c.id, { title: '新標題', dueDate: null });
  assert.equal(u.title, '新標題');
  assert.equal(u.description, '說明');
  assert.equal(u.dueDate, null);
  assert.deepEqual(u.tags, ['a']);
  assert.throws(() => s.update(c.id, { title: '' }), ValidationError);
  assert.equal(s.get(c.id).title, '新標題');
});

test('編輯時改欄位會放到新欄位最後', () => {
  const s = new Store(file);
  s.create({ title: 'D1', column: 'doing' });
  const c = s.create({ title: 'T1' });
  s.update(c.id, { column: 'doing' });
  assert.deepEqual(titles(s.list().filter((x) => x.column === 'doing')), ['D1', 'T1']);
});

test('移動：跨欄並插入到指定卡片之前', () => {
  const s = new Store(file);
  const a = s.create({ title: 'A' });
  const b = s.create({ title: 'B' });
  const x = s.create({ title: 'X', column: 'doing' });
  const y = s.create({ title: 'Y', column: 'doing' });
  s.move(a.id, 'doing', y.id);
  const doing = s.list().filter((c) => c.column === 'doing');
  assert.deepEqual(titles(doing), ['X', 'A', 'Y']);
  assert.deepEqual(doing.map((c) => c.order), [0, 1, 2]);
  const todo = s.list().filter((c) => c.column === 'todo');
  assert.deepEqual(titles(todo), ['B']);
  assert.equal(todo[0].order, 0);
  s.move(b.id, 'doing', null);
  assert.deepEqual(titles(s.list().filter((c) => c.column === 'doing')), ['X', 'A', 'Y', 'B']);
  assert.ok(x && b);
});

test('移動：同欄重新排序', () => {
  const s = new Store(file);
  const a = s.create({ title: 'A' });
  s.create({ title: 'B' });
  const c = s.create({ title: 'C' });
  s.move(c.id, 'todo', a.id);
  assert.deepEqual(titles(s.list()), ['C', 'A', 'B']);
  s.move(c.id, 'todo', null);
  assert.deepEqual(titles(s.list()), ['A', 'B', 'C']);
  s.move(a.id, 'todo', a.id); // dropping onto itself is a no-op
  assert.deepEqual(titles(new Store(file).list()), ['A', 'B', 'C']);
});

test('移動：錯誤目標會被拒絕', () => {
  const s = new Store(file);
  const a = s.create({ title: 'A' });
  const x = s.create({ title: 'X', column: 'doing' });
  assert.throws(() => s.move(a.id, 'nope'), ValidationError);
  assert.throws(() => s.move(a.id, 'done', x.id), ValidationError); // x is not in "done"
  assert.throws(() => s.move('missing', 'done'), NotFoundError);
});

test('刪除後重新編號，且不存在的卡片回報 NotFound', () => {
  const s = new Store(file);
  const a = s.create({ title: 'A' });
  s.create({ title: 'B' });
  s.remove(a.id);
  assert.deepEqual(s.list().map((c) => [c.title, c.order]), [['B', 0]]);
  assert.throws(() => s.remove(a.id), NotFoundError);
  assert.throws(() => s.get(a.id), NotFoundError);
  assert.equal(new Store(file).list().length, 1);
});

test('搜尋：比對標題、描述、標籤，不分大小寫，多個關鍵字須全部符合', () => {
  const s = new Store(file);
  s.create({ title: 'Write Report', tags: ['Work'] });
  s.create({ title: '買菜', description: '牛奶和雞蛋', tags: ['家務'] });
  s.create({ title: '整理報告', tags: ['work', '緊急'] });
  assert.deepEqual(titles(s.list('report')), ['Write Report']);
  assert.deepEqual(titles(s.list('牛奶')), ['買菜']);
  assert.deepEqual(titles(s.list('WORK')), ['Write Report', '整理報告']);
  assert.deepEqual(titles(s.list('work 緊急')), ['整理報告']);
  assert.equal(s.list('   ').length, 3);
  assert.equal(s.list('不存在').length, 0);
});
