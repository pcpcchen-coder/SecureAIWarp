# md-site

把一整個 Markdown 筆記資料夾（含子資料夾、圖片）轉成**可直接用瀏覽器打開**的靜態網站。
不需要架伺服器，產生的網站完全離線可用（不載入任何外部 CDN）。

## 功能

- 每篇筆記（`.md` / `.markdown`）產生一頁 HTML，保留原本的資料夾結構
- 首頁 `index.html`：依資料夾分組的目錄樹，附即時篩選框
- 程式碼區塊語法上色（highlight.js，支援淺色／深色模式）
- 筆記間連結可點：
  - `[文字](其他筆記.md)`、`[文字](../資料夾/筆記.md#小節)` 會改寫成對應的 `.html`
  - 省略副檔名的 `[文字](筆記)` 也可以
  - Obsidian 風格的 `[[筆記名稱]]`、`[[筆記名稱|顯示文字]]`、`[[筆記名稱#小節]]`
- 標題自動產生錨點 id（保留中文），可用 `#小節` 跳轉
- 圖片與其他非 Markdown 檔案原樣複製，相對路徑照常可用
- 失效的筆記連結會在終端機警告，並在頁面上以紅色刪除線標示
- 頁面標題取自 front matter 的 `title`，否則取第一個 `# 標題`，再不然用檔名
- 自動略過隱藏資料夾（如 `.obsidian`、`.git`）與 `node_modules`

## 安裝

需要 Node.js 18 以上。在本目錄執行：

```bash
npm install
```

（選用）想在任何地方用 `md-site` 指令：

```bash
npm link        # 之後可直接打 md-site ...
```

## 使用

```bash
node bin/md-site.js <筆記資料夾> -o <輸出資料夾> [選項]
```

| 選項 | 說明 |
| --- | --- |
| `-o, --out <dir>` | 輸出資料夾（必填，不存在會自動建立） |
| `-t, --title <text>` | 網站標題，預設為輸入資料夾名稱 |
| `--clean` | 建置前先**刪除**整個輸出資料夾的內容（請確認路徑正確） |
| `--strict` | 有失效連結時以結束碼 2 結束（適合 CI） |
| `-q, --quiet` | 不輸出訊息 |
| `-h, --help` | 顯示說明 |

範例：

```bash
node bin/md-site.js ~/Notes -o ~/notes-site --title "我的筆記" --clean
# 然後用瀏覽器打開 ~/notes-site/index.html
```

本目錄附有範例筆記，可以直接試：

```bash
npm run example        # 輸出到 example/site/
# 打開 example/site/index.html
```

也可以在程式中使用：

```js
const { buildSite } = require('./src/build');
const result = buildSite({ input: 'notes', output: 'site', title: '筆記', clean: true });
// result = { pages, assets, brokenLinks: [{ page, href }] }
```

## 輸出規則

- `a/b.md` → `a/b.html`
- 根目錄的 `index.md` → `index-note.html`（避免覆蓋首頁），指向它的連結會自動改寫
- 樣式表放在輸出資料夾的 `assets/`
- 輸出資料夾可以放在筆記資料夾裡面（會自動排除，不會被當成筆記），但不能等於或包含筆記資料夾

## 測試

```bash
npm test
```

使用 Node.js 內建的 `node:test`，不需額外測試框架。

## 專案結構

```
bin/md-site.js     命令列入口
src/build.js       轉換邏輯（buildSite）
src/style.css      網站樣式
test/              自動化測試
example/notes/     範例筆記
```

## 相依套件

- [marked](https://marked.js.org/) — Markdown 解析（GFM：表格、核取清單等）
- [highlight.js](https://highlightjs.org/) — 語法上色
- [gray-matter](https://github.com/jonschlinkert/gray-matter) — 解析 front matter
