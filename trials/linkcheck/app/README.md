# linkcheck

掃描整個資料夾裡的 Markdown 檔，找出所有連結並檢查是否失效：

- **站內連結**：檢查目標檔案是否存在；若帶有 `#錨點`，再檢查目標 Markdown 檔裡有沒有對應的標題或 id。
- **外部網址**（`http://`、`https://`）：實際發出請求，依 HTTP 狀態碼判斷，多個網址會同時檢查。
- 最後列出壞掉的連結在哪個檔案第幾行；只要有壞連結，結束碼就是 `1`，可直接放進 CI。

只用 Go 標準函式庫，沒有第三方相依套件。

## 建置

需要 Go 1.24 以上。

```sh
cd apps/linkcheck
go build -o linkcheck .
```

或安裝到 `$GOBIN`：`go install .`

## 使用

```sh
linkcheck [flags] [directory]      # directory 預設為目前目錄
```

範例：

```sh
./linkcheck docs                          # 檢查 docs/ 下所有 .md、.markdown
./linkcheck -offline docs                 # 只檢查站內連結（不連網）
./linkcheck -concurrency 32 -timeout 10s docs
./linkcheck -exclude '^https://localhost' -exclude 'example\.com' docs
./linkcheck -accept 403,429 docs          # 把某些狀態碼視為正常（例如會擋爬蟲的網站）
./linkcheck -format json docs > report.json
./linkcheck -root site/content site/content/zh   # 以 /開頭的連結相對於 -root 解析
```

輸出（壞連結寫到 stdout，摘要寫到 stderr）：

```
README.md:5: guide/install.md#uninstall (anchor #uninstall not found)
README.md:6: guide/upgrade.md (file not found)
linkcheck: 2 files, 6 links: 5 internal, 1 external (1 unique URLs), 0 skipped; 2 broken
```

`examples/docs/` 有一份可以直接試跑的範例：`./linkcheck -offline examples/docs`。

### 參數

| 參數 | 預設 | 說明 |
| --- | --- | --- |
| `-concurrency` | `16` | 同時檢查的外部網址數 |
| `-timeout` | `15s` | 每個 HTTP 請求的逾時 |
| `-retries` | `2` | 網路錯誤、HTTP 429、5xx 時重試的次數 |
| `-retry-delay` | `1s` | 重試間隔（乘上第幾次重試） |
| `-offline` | `false` | 不檢查外部網址 |
| `-exclude` | | 正規表示式，符合的連結略過；可重複指定 |
| `-accept` | | 額外視為正常的狀態碼，逗號分隔，例如 `403,429` |
| `-ext` | `.md,.markdown` | 要掃描的副檔名 |
| `-root` | 掃描的資料夾 | 以 `/` 開頭的站內連結相對於哪個資料夾 |
| `-format` | `text` | `text` 或 `json` |
| `-quiet` | `false` | 不印摘要行 |

### 結束碼

| 碼 | 意義 |
| --- | --- |
| `0` | 全部連結正常 |
| `1` | 有壞掉的連結 |
| `2` | 參數錯誤或執行錯誤（例如資料夾不存在） |

## 檢查規則

**會抓到的連結**：`[文字](網址 "標題")`、圖片 `![alt](網址)`、參考式定義 `[id]: 網址`、`<https://...>`、HTML 的 `href` / `src` 屬性，以及文字中直接出現的 `https://...`。
程式碼區塊（```` ``` ```` / `~~~`）、行內程式碼、HTML 註解 `<!-- -->` 與檔頭 YAML front matter 內的內容會被忽略。

**站內連結**

- 相對路徑以連結所在檔案的資料夾為準；`/` 開頭以 `-root` 為準。`%20` 等編碼會先解碼，`?query` 會忽略。
- 找不到檔案時，依序嘗試靜態網站常見寫法：`page` → `page.md`、`page.html` → `page.md`；指向資料夾時找 `index.md`、`README.md`、`_index.md`（資料夾存在本身即視為有效）。
- 錨點只在目標是 Markdown 檔時檢查，產生規則與 GitHub 相同：轉小寫、去掉標點、空白換成 `-`，保留中文等非 ASCII 字元；同名標題依序為 `faq`、`faq-1`、`faq-2`。另外也認得 `## 標題 {#自訂-id}` 與 HTML 的 `id="..."`、`name="..."`。比對不分大小寫。
- `mailto:`、`tel:` 等其他協定會略過。
- 以 `.` 開頭的資料夾（如 `.git`）與 `node_modules` 不會掃描。

**外部網址**

- 相同網址（去掉 `#fragment` 後）只請求一次，結果套用到所有出現位置。
- 先送 `HEAD`，若失敗狀態再用 `GET` 確認（很多伺服器不支援 HEAD）。會跟隨重新導向，最終狀態 2xx/3xx 視為正常。
- 4xx（429 除外）直接判定失效；網路錯誤、逾時、429、5xx 會重試 `-retries` 次。
- 會使用環境變數 `HTTPS_PROXY` / `HTTP_PROXY` 設定的代理。

## 放進 CI

GitHub Actions 範例：

```yaml
- uses: actions/setup-go@v5
  with:
    go-version: '1.24'
- run: go build -o linkcheck ./apps/linkcheck
- run: ./linkcheck -exclude '^https?://localhost' docs
```

外部網站偶爾不穩，若不想讓 PR 因此失敗，可以在 PR 上跑 `-offline`，外部網址改在排程工作裡檢查。

## 測試

```sh
go test ./...          # 加 -v 看每個測試，加 -race 檢查資料競爭
```

測試完全不連外網：外部網址的檢查用 `net/http/httptest` 在本機起測試伺服器，模擬 200、404、410、500、重新導向、不支援 HEAD、暫時失敗後恢復、逾時、連線被拒等情況，也驗證並行數上限與 CLI 的輸出和結束碼。
