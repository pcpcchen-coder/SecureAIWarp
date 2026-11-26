# 本機看板（Local Kanban）

在自己電腦上跑的看板待辦工具。三欄：**待辦／進行中／完成**。

功能：

- 新增、編輯（按 ✎ 或雙擊卡片）、刪除卡片
- 拖曳卡片換欄，或在同一欄內調整順序
- 標籤（以逗號分隔，可用全形逗號）與到期日；未完成且已過期的卡片會以紅字標示「已逾期」
- 搜尋：比對標題、描述、標籤，不分大小寫；空格分隔的多個關鍵字須全部符合
- 資料存在本機 JSON 檔，關掉重開還在
- 不需登入；伺服器只監聽 `127.0.0.1`，外部電腦連不到

## 需求

- Node.js 22 以上（伺服器本身沒有任何第三方相依套件）
- 執行瀏覽器測試需要本機有 Chrome／Chromium（沒有就自動略過該測試）

## 安裝

```bash
cd apps/kanban
npm install
```

`npm install` 只會在這個目錄的 `node_modules/` 裝測試用的 `puppeteer-core`（不會下載瀏覽器）。
只想執行、不跑測試的話可以跳過這一步，或用 `npm install --omit=dev`。

## 啟動

```bash
npm start
```

然後用瀏覽器開啟 <http://localhost:3000>。按 `Ctrl+C` 停止。

可用環境變數調整：

| 變數 | 預設值 | 說明 |
| --- | --- | --- |
| `PORT` | `3000` | 連接埠 |
| `KANBAN_DATA_FILE` | `./data/board.json` | 資料檔位置 |
| `HOST` | `127.0.0.1` | 監聽位址。不建議改成 `0.0.0.0`，因為沒有登入機制 |

例如：`PORT=8080 KANBAN_DATA_FILE=~/kanban.json npm start`

## 資料存放

預設存在 **`data/board.json`**（相對於本目錄，第一次新增卡片時自動建立）。
每次變更都會先寫入暫存檔再改名取代，寫到一半當機也不會留下半個檔案。
若資料檔內容損毀無法解析，程式會先把它備份成 `board.json.corrupt-<時間戳>` 再以空白看板啟動，不會覆蓋原檔。
要備份資料，複製這個檔案即可。

## 測試

```bash
npm test
```

使用 Node 內建的測試執行器（`node:test`），共 23 個測試：

- `test/store.test.js`：資料層（新增、驗證、編輯、移動與排序、刪除、搜尋、持久化、損毀檔處理）
- `test/server.test.js`：HTTP API（完整 CRUD、搜尋、重啟後資料仍在、錯誤處理、路徑穿越、請求大小上限、Host 檢查）
- `test/helpers.test.js`：前端共用的小工具（標籤解析、逾期判斷）
- `test/ui.test.js`：用無頭 Chrome 實際操作網頁（新增、拖曳換欄、編輯、搜尋、刪除、重新整理後保留）。
  找不到瀏覽器時會略過；瀏覽器不在常見路徑時可設 `CHROME_PATH=/path/to/chrome npm test`

測試的暫存資料寫在 `.test-tmp/`，不會碰到你的 `data/board.json`。

## API

| 方法 | 路徑 | 說明 |
| --- | --- | --- |
| `GET` | `/api/cards?q=關鍵字` | 列出（或搜尋）卡片，依欄位與順序排序 |
| `POST` | `/api/cards` | 新增：`{ title, description?, tags?, dueDate?, column? }` |
| `GET` | `/api/cards/:id` | 取得單張卡片 |
| `PATCH` | `/api/cards/:id` | 更新任何欄位（`dueDate: null` 可清除到期日） |
| `POST` | `/api/cards/:id/move` | 移動：`{ column, beforeId }`，`beforeId` 為 `null` 表示放到最後 |
| `DELETE` | `/api/cards/:id` | 刪除 |

欄位值：`todo`、`doing`、`done`；到期日格式 `YYYY-MM-DD`。

## 安全說明

沒有登入，所以設計上只給本機使用：

- 只監聽 `127.0.0.1`
- 只接受 `Host` 為 `localhost`／`127.0.0.1` 的請求，防止 DNS rebinding
- 寫入類 API 要求 `Content-Type: application/json`，一般網頁的表單無法跨站送出
- 網頁設有 Content-Security-Policy，卡片內容一律以純文字顯示

## 檔案結構

```
server.js         HTTP 伺服器（API + 靜態檔）
lib/store.js      資料層：驗證、排序、JSON 檔讀寫
public/           前端（index.html、app.js、helpers.js、style.css）
test/             自動化測試
data/             你的資料（已列入 .gitignore）
```
