'use strict';

// End-to-end browser test. Needs a local Chrome/Chromium; it is skipped when none is found.
// Point CHROME_PATH at the browser binary if it is not in a standard location.
const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { createServer } = require('../server');

const TMP_ROOT = path.join(__dirname, '..', '.test-tmp');
const CANDIDATES = [
  process.env.CHROME_PATH,
  '/usr/bin/google-chrome',
  '/usr/bin/google-chrome-stable',
  '/usr/bin/chromium',
  '/usr/bin/chromium-browser',
  '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
].filter(Boolean);
const chromePath = CANDIDATES.find((p) => fs.existsSync(p));

let puppeteer = null;
try {
  puppeteer = require('puppeteer-core');
} catch {
  /* not installed */
}
const skip = !chromePath || !puppeteer ? '找不到 Chrome 或 puppeteer-core，略過瀏覽器測試' : false;

let dir;
let server;
let browser;
let page;
let base;

before(async () => {
  if (skip) return;
  fs.mkdirSync(TMP_ROOT, { recursive: true });
  dir = fs.mkdtempSync(path.join(TMP_ROOT, 'kanban-ui-'));
  server = createServer({ dataFile: path.join(dir, 'board.json') });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  base = `http://localhost:${server.address().port}`;
  browser = await puppeteer.launch({
    executablePath: chromePath,
    headless: true,
    args: ['--no-sandbox', '--disable-dev-shm-usage'],
  });
  page = await browser.newPage();
  page.on('dialog', (d) => d.accept()); // accept the delete confirmation
});

after(async () => {
  if (browser) await browser.close();
  if (server) server.close();
  if (dir) fs.rmSync(dir, { recursive: true, force: true });
});

const columnTitles = (col) =>
  page.$$eval(`.cards[data-column="${col}"] .card-title`, (els) => els.map((e) => e.textContent));

async function waitForTitles(col, expected) {
  await page.waitForFunction(
    (c, exp) =>
      JSON.stringify([...document.querySelectorAll(`.cards[data-column="${c}"] .card-title`)].map((e) => e.textContent)) ===
      JSON.stringify(exp),
    { timeout: 5000 },
    col,
    expected,
  );
}

async function addCard({ title, tags = '', dueDate = '', column = 'todo' }) {
  await page.click('#add-btn');
  await page.waitForSelector('#card-dialog[open]');
  await page.type('#card-form [name=title]', title);
  if (tags) await page.type('#card-form [name=tags]', tags);
  if (dueDate) await page.$eval('#card-form [name=dueDate]', (el, v) => { el.value = v; }, dueDate);
  await page.select('#card-form [name=column]', column);
  await page.click('#card-form button[type=submit]');
  await page.waitForSelector('#card-dialog:not([open])');
}

// Fire the same HTML5 drag events a real mouse drag produces.
async function dragCard(title, targetColumn) {
  await page.evaluate(
    (t, col) => {
      const card = [...document.querySelectorAll('.card')].find((c) => c.querySelector('.card-title').textContent === t);
      const zone = document.querySelector(`.cards[data-column="${col}"]`);
      const dt = new DataTransfer();
      const box = zone.getBoundingClientRect();
      const opts = { bubbles: true, cancelable: true, dataTransfer: dt, clientX: box.left + 5, clientY: box.bottom - 2 };
      card.dispatchEvent(new DragEvent('dragstart', opts));
      zone.dispatchEvent(new DragEvent('dragover', opts));
      zone.dispatchEvent(new DragEvent('drop', opts));
      card.dispatchEvent(new DragEvent('dragend', opts));
    },
    title,
    targetColumn,
  );
}

test('瀏覽器：新增、拖曳、編輯、搜尋、刪除、重新整理後保留', { skip }, async () => {
  await page.goto(base);
  await page.waitForSelector('.cards[data-column="todo"] .empty');

  await addCard({ title: '寫週報', tags: '工作, 重要', dueDate: '2000-01-01' });
  await addCard({ title: '買菜', tags: '家務' });
  await waitForTitles('todo', ['寫週報', '買菜']);

  // tags and overdue due date are rendered
  const tags = await page.$$eval('.card:first-child .tags li', (els) => els.map((e) => e.textContent));
  assert.deepEqual(tags, ['工作', '重要']);
  assert.equal(await page.$eval('.card:first-child .due', (e) => e.classList.contains('overdue')), true);

  // drag to "進行中"
  await dragCard('寫週報', 'doing');
  await waitForTitles('doing', ['寫週報']);
  await waitForTitles('todo', ['買菜']);
  assert.equal(await page.$eval('[data-count="doing"]', (e) => e.textContent), '1');

  // edit
  await page.click('.cards[data-column="doing"] .card .edit');
  await page.waitForSelector('#card-dialog[open]');
  await page.$eval('#card-form [name=title]', (el) => { el.value = ''; });
  await page.type('#card-form [name=title]', '寫月報');
  await page.select('#card-form [name=column]', 'done');
  await page.click('#card-form button[type=submit]');
  await waitForTitles('done', ['寫月報']);
  // overdue styling no longer applies once the card is done
  assert.equal(await page.$eval('.cards[data-column="done"] .due', (e) => e.classList.contains('overdue')), false);

  // empty title shows an error and keeps the dialog open
  await page.click('#add-btn');
  await page.$eval('#card-form [name=title]', (el) => { el.removeAttribute('required'); el.value = '   '; });
  await page.click('#card-form button[type=submit]');
  await page.waitForSelector('#form-error:not([hidden])');
  await page.click('#cancel-btn');

  // search by tag
  await page.type('#search', '家務');
  await waitForTitles('todo', ['買菜']);
  await waitForTitles('done', []);
  await page.$eval('#search', (el) => { el.value = ''; el.dispatchEvent(new Event('input')); });
  await waitForTitles('done', ['寫月報']);

  // delete
  await page.click('.cards[data-column="todo"] .card .delete');
  await waitForTitles('todo', []);

  // reload: data is still there
  await page.reload();
  await waitForTitles('done', ['寫月報']);
  assert.deepEqual(await columnTitles('todo'), []);
});
