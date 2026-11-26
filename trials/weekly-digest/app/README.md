# weekly-digest

這是一個 Node.js 命令列工具。它讀取資料夾裡最近七天的會議記錄（`.txt`、`.md`、`.markdown`），再用 Claude（Anthropic API）整理成一份 Markdown 週報，內容包括：

- 每場會議的**會議資訊、重點、決議、待辦事項（含負責人與期限）**
- 最後一段**本週總結**，內容有整體進展、重要決議、要追蹤的待辦、風險

## 需求

- Node.js 18.18 以上（建議 22）
- 一把 Anthropic API 金鑰（到 https://platform.claude.com 申請）

## 安裝

```bash
cd weekly-digest
npm install
```

相依套件只有官方 SDK `@anthropic-ai/sdk`（版本固定為 1.14.0），會裝在本目錄的 `node_modules/`。

如果想在任何地方直接打 `weekly-digest` 指令，可以另外執行 `npm link`。這一步是選用的。

## 設定金鑰

程式從環境變數 `ANTHROPIC_API_KEY` 讀金鑰，不接受用命令列參數傳金鑰，以免金鑰留在 shell 歷史紀錄裡。

**方法一：用環境變數**

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**方法二：用 `.env` 檔**（`.gitignore` 已經排除 `.env`）

```bash
echo 'ANTHROPIC_API_KEY=sk-ant-...' > .env
chmod 600 .env
node --env-file=.env bin/weekly-digest.js ~/meeting-notes
```

SDK 也支援 `ANTHROPIC_AUTH_TOKEN`，以及 `ant auth login` 存下的設定檔。另外，如果你設了 `ANTHROPIC_BASE_URL`，SDK 會改連到那個網址，不再連 `https://api.anthropic.com`。一般使用請不要設定它。

## 使用方式

```bash
# 整理最近 7 天（含今天）的記錄，輸出到 ./weekly-digest-<今天日期>.md
node bin/weekly-digest.js ~/meeting-notes

# 指定輸出檔，並一併讀取子資料夾
node bin/weekly-digest.js ~/meeting-notes -o reports/2026-W48.md --recursive

# 先看會處理哪些檔案、每份會切成幾段（不呼叫 API、不需要金鑰）
node bin/weekly-digest.js ~/meeting-notes --dry-run
```

### 選項

| 選項 | 說明 | 預設 |
|---|---|---|
| `-o, --output <檔案>` | 週報輸出路徑 | `./weekly-digest-<今天>.md` |
| `-d, --days <天數>` | 往回看幾天（含今天） | `7` |
| `-r, --recursive` | 一併讀取子資料夾 | 關 |
| `-m, --model <模型>` | 使用的 Claude 模型 | `claude-opus-5-5` |
| `--effort <等級>` | `low` / `medium` / `high` / `xhigh` / `max` | `medium` |
| `--max-tokens <數字>` | 每次回應的 token 上限 | `16000` |
| `--chunk-chars <數字>` | 單次請求最多放入的原文字元數，超過就分段 | `40000` |
| `--concurrency <數字>` | 同時進行的 API 請求數 | `3` |
| `--no-fallbacks` | 不使用伺服器端拒答備援（beta），詳見下文 | 關 |
| `--dry-run` | 只列出檔案與分段，不呼叫 API | 關 |

### 怎麼判斷記錄的日期

1. 檔名裡有日期就用檔名的日期。支援的寫法例如 `2026-11-24-產品會議.md`、`standup_20261124.txt`、`notes.2026.11.24.md`。
2. 檔名裡沒有日期，就用檔案的修改時間。

`--dry-run` 的輸出會註明每份檔案的日期是從哪裡來的。隱藏檔、空白檔，以及其他副檔名的檔案都會略過。

## 記錄很多或很長時怎麼處理

程式用分批的「map-reduce」流程處理，不會一次把所有內容塞進同一個請求：

1. **逐場摘要**：每份記錄各自送出一次請求（同時最多 `--concurrency` 個）。
2. **長記錄分段**：單份記錄超過 `--chunk-chars` 時，會優先在段落、換行或句號處切開。每段先整理成條列筆記，最後再合併成該場會議的摘要。
3. **本週總結**：把所有會議摘要交給 Claude 寫總結。如果摘要的總量太大，就先分批濃縮，必要時濃縮好幾層，最後才寫總結。

所有請求都用串流（streaming）方式接收，長輸出也不會遇到 HTTP 逾時。遇到 429 或 5xx 錯誤時，SDK 會自動重試，最多 4 次。

## 連到哪些網址

- **只連 `https://api.anthropic.com/v1/messages`**（Anthropic Messages API，用 POST 加串流）。
- 不會連其他服務，也不會上傳任何統計資料。會議記錄內容只會送到上面這個 API。
- 唯一的例外：如果設了 `ANTHROPIC_BASE_URL` 環境變數，SDK 會改連到那個網址。

## 模型與拒答備援

- 預設模型是 `claude-opus-5-5`，可以用 `-m` 換成別的模型，例如 `claude-sonnet-5-5` 或 `claude-haiku-5-5`，費用會比較低。
- 預設開啟 Anthropic 的**伺服器端備援**（beta 功能 `server-side-fallback-2026-07-01`，參數是 `fallbacks: "default"`）。如果安全分類器誤判、拒絕處理某份記錄，API 會在同一個請求裡改用合適的模型完成，程式不用另外處理。如果你的帳號或代理伺服器不支援這個 beta，請加上 `--no-fallbacks`，程式就會改用一般的 Messages API。
- 如果所有模型都拒答，或回應因為超過 `--max-tokens` 被截斷，程式會停下來並顯示原因，不會產出不完整的週報。

## 測試

```bash
npm test
```

測試使用 Node 內建的 `node:test`，**完全不連外網，也不需要金鑰**：

- 檔案篩選、日期判斷、分段與分批流程的單元測試，用假的 Claude 函式。
- 端對端測試使用真正的 `@anthropic-ai/sdk`，但把 `baseURL` 指向一個只在 `127.0.0.1` 監聽的本機假 API。假 API 會回傳與真實 API 相同格式的 SSE 串流，藉此檢查請求的路徑、標頭、模型、beta 與 `fallbacks` 參數，以及拒答、截斷和 401 錯誤的處理。

## 專案結構

```
bin/weekly-digest.js   CLI 進入點
src/cli.js             參數解析、錯誤訊息、主流程
src/notes.js           掃描資料夾、日期判斷與篩選
src/chunk.js           長文字分段、分組
src/digest.js          map-reduce 週報流程與提示詞
src/claude.js          Claude API 呼叫（串流、備援、拒答與截斷處理）
test/                  自動化測試
```
