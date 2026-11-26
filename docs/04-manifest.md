# 04 權限宣告規格（`warp.yaml`）

宣告檔是整個系統的**唯一事實來源**：Agent 產生它、檢查器驗證它、核心執行它、標籤呈現它、版本更新比對它。

設計要求：

- **純宣告**：沒有條件判斷、沒有腳本、沒有可執行內容。Agent 在這裡沒有夾帶邏輯的空間。
- **封閉格式**：未知欄位即錯誤，不默默忽略。
- **每條授權自帶證據與用途**。
- **可機械式比較**：兩個版本的差異可以直接算出來。

完整範例見 [`examples/invoice-helper.warp.yaml`](../examples/invoice-helper.warp.yaml)。

> **第 1 期實作對照**：本文件同時是核心 `warp lint` 的規格。與 v0.1 草案不同、已依實作定案的地方以「（第 1 期）」標出，
> 並集中整理在第 6 節。宣告檔預設位置為應用根目錄下的 `.warp/warp.yaml`（`-f` 可另指定）。

## 1. 結構

| 區段 | 對應通道 | 內容 |
| --- | --- | --- |
| `app` | — | 名稱、版本、型態、進入點、內容雜湊 |
| `runtime` | 程序 | 最低隔離等級、CPU／記憶體／程序數／磁碟上限、可否產生子程序 |
| `files` | 檔案 | 掛載清單：路徑、讀或寫、用途 |
| `network.egress` | 對外連線 | 主機、連接埠、是否經 AI 閘門、流量上限 |
| `network.ingress` | 對內連線 | 監聽位置、開放範圍、驗證方式、頻率限制 |
| `secrets` | 機密 | 名稱、綁定的主機與注入方式、由誰提供 |
| `ai` | AI 呼叫 | 供應商、模型白名單、花費上限、工具清單與風險等級 |
| `data` | 資料 | 資料類別、允許去向、留存 |
| `supply_chain` | 供應鏈 | 相依清單位置、建置期允許的來源、掃描結果摘要 |
| `exceptions` | — | 超出軟性規則的授權，附人工簽核紀錄 |
| `evidence` | — | 每條授權對應的側錄紀錄與測試 |

## 2. 幾個關鍵的設計選擇

### 路徑用變數，不寫死
```yaml
files:
  - path: "${APP_DATA}"            # 核心配給此應用的專屬目錄
    mode: rw
    purpose: "儲存設定與處理結果"
  - path: "${USER_PICK:invoices}"  # 由接收者啟動時選擇
    mode: ro
    purpose: "讀取你選定的發票資料夾"
```
作者機器上的路徑對接收者沒有意義。可用變數只有少數幾個：`APP_DATA`、`APP_CACHE`、`USER_PICK:<名稱>`。

（第 1 期）
- `TMP` 不再是變數：殼內一律有私有、拋棄式、有容量上限的 `/tmp`，不需要授權。
- 不支援絕對路徑（檢查器回報 `files-absolute` 錯誤）；硬性規則中的「家目錄、系統目錄、憑證目錄、容器控制介面」改在**執行期**對實際掛載來源（應用根目錄與每個 `USER_PICK`）檢查，違反即拒絕執行。
- `<名稱>` 以小寫英文字母開頭，只含小寫英數字、`-`、`_`（最多 32 字元）；`warp record`／`enforce` 的 `--pick` 名稱不合格式時直接拒絕執行並說明規則。
  殼內路徑：`${APP_DATA}` → `/warp/data`、`${APP_CACHE}` → `/warp/cache`、`${USER_PICK:x}` → `/warp/pick/x`
  （並以環境變數 `APP_DATA`、`APP_CACHE`、`WARP_PICK_<名稱轉大寫、- 換成 _>` 告知應用，例如 `photo-in` → `WARP_PICK_PHOTO_IN`）。
- `files[].path` 只能是這三種變數**本身**；`${APP_DATA}/子路徑` 之類的寫法是無效路徑（`format` 錯誤）。
- 選定的資料夾不能位於應用目錄或核心狀態目錄內（執行期拒絕）。
- `app.entry` 與 `warp record`／`enforce` 在 `--` 之後的指令中，`${APP_DATA}`、`${APP_CACHE}`、`${USER_PICK:<名稱>}` 會被核心以字面替換成上述殼內路徑
  （也可以出現在參數中間，例如 `--db=${APP_DATA}/x.db`；不做任何其他 shell 展開）。側錄檔與 `triggered_by` 保留未替換的原樣。
  `app.entry` 引用了 `files` 中沒有宣告的變數、或名稱無效時，檢查器以 `entry-var` 拒收；執行期指令引用了這次沒有掛載的變數則拒絕執行。
- `APP_DATA` 存在核心的狀態目錄（預設 `~/.local/state/securewarp/apps/…`），不在應用目錄內。

### 機密綁定目的地
```yaml
secrets:
  - name: ANTHROPIC_API_KEY
    provided_by: recipient
    bind:
      host: api.anthropic.com
      inject: { header: x-api-key }
    visibility: gate-only          # 應用只看得到佔位值
```
`visibility` 只有兩個值：`gate-only`（預設）與 `app-visible`（需列入例外）。

（第 1 期）
- 機密也是授權，必須有 `purpose` 與證據（側錄時誘餌值出現在 `bind.host` 的 `bind.inject.header` 標頭中）。
- `bind.host` 必須同時列在 `network.egress`，且只能是單一具體主機；`inject.header` 不得是 `Host`、`Content-Length`、`Connection` 等傳輸層標頭。
- 執行時真值取自**執行 warp 的主機上同名的環境變數**，缺少即拒絕執行；殼內只有 `warp-placeholder-…` 佔位值，閘門只在該主機、該標頭中把佔位值換成真值，並把回應中出現的真值遮蔽回佔位值。

### 工具要標風險
```yaml
ai:
  tools:
    - name: read_invoice
      risk: low
    - name: send_email
      risk: high
      gate: consent                # 每次執行前經同意代理
```
`risk: high` 的工具若沒有 `gate`，檢查器拒收。

### 證據是必填
```yaml
evidence:
  - grant: network.egress[1]
    observed_in: .warp/evidence/trace-0007.json
    triggered_by: tests/test_fx.py::test_convert_usd
```
`grant` 以路徑指向宣告中的某一條授權。檢查器會打開側錄檔確認真的有這筆行為。上例的 `triggered_by` 是設計草案的寫法；
第 1 期必須是側錄時實際執行的指令（例如 `pytest tests/test_fx.py::test_convert_usd`）。

（第 1 期）`observed_in` 必須是 `.warp/evidence/` 下的相對路徑；側錄檔由核心寫入並以本機金鑰（HMAC-SHA256，存在核心狀態目錄）簽章，
檢查器拒收簽章不符或被修改的側錄檔。`triggered_by` 必須**逐字等於**側錄檔中核心實際執行的指令（`warp draft` 會自動填入；
含空白等字元的參數以單引號表示），否則以 `evidence-command` 拒收；側錄檔記錄的應用內容雜湊必須等於 `app.digest`，否則以 `evidence-stale` 拒收。
簽章與這些規則能擋住意外與其他使用者，擋不住與核心同一個使用者的 Agent；證據的實際意義見 [05](05-agent-fitting-protocol.md) 第 4.1 節，
可用 `warp evidence replay` 重新執行確認。比對規則：`files[i]` 需有該變數根目錄下的存取（`rw` 需有寫入）；`network.egress[i]` 需有連往該主機與連接埠的嘗試；
`network.ingress[i]` 需有監聽該埠；`secrets[i]` 見上。側錄檔是本機產物：換一台機器（換一把金鑰）就必須重新側錄。

## 3. 檢查規則

檢查器是確定性的，分兩級。

### 硬性規則（任何人都不能覆寫）
| 規則 | 原因 |
| --- | --- |
| 對外連線不得使用全域萬用字元 | 等於沒有殼 |
| 不得可寫掛載家目錄、根目錄、系統目錄 | 爆炸半徑無上限 |
| 不得掛載憑證目錄（SSH、雲端 CLI 設定、瀏覽器資料、金鑰圈） | 橫向移動 |
| 不得掛載容器執行環境的控制介面、不得使用特權模式 | 等同逃出殼 |
| 不得連往雲端中繼資料位址 | 竊取主機身分 |
| 對內連線開放超出本機時必須有驗證方式 | 無驗證的公開服務 |
| 高風險工具必須有閘門 | 提示注入的最後防線 |
| 有 AI 呼叫必須有花費上限 | 錢包阻斷 |
| 每條授權必須有證據與用途 | 原則四 |
| 內容雜湊必須與實際檔案相符 | 防掉包 |
| 對外連線不得指向主機本機（`localhost`、`127.0.0.0/8`、`::1`）（第 1 期新增） | 等同存取主機上的服務 |
| 名稱含高風險動作（send、email、pay、delete、exec、run…）的工具，風險不得低於 `high`（第 1 期新增） | 核心內建的下限 |
| 機密的 `bind.host` 必須列在對外連線中、只能注入一般標頭（第 1 期新增） | 注入點必須明確 |
| `app.entry` 中的路徑佔位字必須是 `files` 中宣告的路徑（`entry-var`，第 1 期新增） | 強制模式不會掛載未宣告的路徑 |

內容雜湊（`app.digest`）的算法：對應用根目錄下（排除最上層的 `.warp/`、`.git/`，這兩者在殼內也被遮蔽）每個檔案、目錄、符號連結的
相對路徑、類型、權限位元與內容雜湊排序後再取 SHA-256；`warp digest` 可印出目前的值。

### 軟性規則（可由人工簽核成為例外）
| 規則 | 例外時標籤上顯示 |
| --- | --- |
| 機密應為 `gate-only` | 「此工具可直接看到你的金鑰」 |
| 對外主機不使用子網域萬用字元 | 「可連到 *.example.com 的任何主機」 |
| 不可寫入使用者選擇的資料夾 | 「可修改你選定資料夾中的檔案」 |
| 不可執行殼內未列出的程式 | 「可執行任意指令」 |
| 不可連往區域網路 | 「可連到你的內部網路」 |
| 對外主機數量不超過門檻 | 「連線對象較多（N 個）」 |

例外必須寫入 `exceptions`，包含理由、簽核人、時間。**Agent 不能替人簽核**——簽核是透過同意代理產生的紀錄，Agent 無法偽造。

（第 1 期）軟性規則的識別碼與例外格式：

| 規則識別碼 | 觸發條件 |
| --- | --- |
| `secret-app-visible` | `visibility: app-visible` |
| `egress-subdomain-wildcard` | `host: "*.example.com"`（萬用字元只允許在最左邊一層，且底下至少兩層） |
| `pick-writable` | `${USER_PICK:…}` 為 `rw` |
| `spawn-any` | `runtime.spawn: any` |
| `egress-lan` | 對外連線標示 `lan: true`（只有標示者可連往私有位址；本機迴路、連結本地、中繼資料永遠不行） |
| `egress-many-hosts` | 對外連線超過 10 條（`grant: network.egress`） |

```yaml
exceptions:
  - rule: egress-subdomain-wildcard
    grant: network.egress[0]
    reason: 供應商以 CDN 子網域分流
    approved_by: 王小明
    approved_at: "2026-11-24"
```

第 1 期尚無同意代理：例外只會讓警告消失並顯示在標籤的「需要你特別注意」區，檢查器會另外警告「簽核紀錄尚未經簽章驗證」。

## 4. 風險分數

檢查器由宣告機械式算出一個分數與等級，讓人不必讀完細項也有直覺：

- 每類授權有基礎權重（例：唯讀使用者資料夾 < 可寫 < 可執行任意指令）。
- 例外加重。
- 覆蓋率不足的通道加重（看不到的地方假設最壞）。

分數的用途是**比較與排序**（新版比舊版高了多少、兩個同類工具誰要得多），不是絕對的安全評級，標籤上會如此說明。

## 5. 版本差異

`warp diff old.yaml new.yaml` 輸出人話：

```
＋ 新增對外連線：api.stripe.com（用途：建立付款連結）
＋ 新增高風險工具：create_payment（每次需你同意）
－ 移除檔案存取：${USER_PICK:exports}
～ 每日 AI 花費上限：5 美元 → 20 美元
風險等級：低 → 中
```

沒有變動的部分不顯示。這是使用者在更新時唯一需要看的東西。

## 6. 第 1 期的格式定案與限制

- **封閉格式的實作**：未知欄位、重複鍵、多份 YAML 文件、錨點／別名（`&`、`*`）、合併鍵（`<<`）、明確型別標記（`!!binary` 等）一律視為錯誤；
  布林欄位只接受 `true`／`false`（不接受 YAML 1.1 的 `yes`、`no`、`on`、`off`）；數字欄位不接受字串。
- **新增欄位**：`network.egress[].lan`（布林）、`secrets[].purpose`。
- **`runtime.isolation`**：此核心只實作 `process`；宣告 `container`、`microvm`、`wasm` 時檢查器警告、強制模式**拒絕執行**（不降級）。
- **`runtime.spawn`**：可宣告但尚未強制（標籤的「程序」通道標示為「僅聲明」）。`runtime.background: true` 尚未支援。
- **`runtime.resources`**：`memory`、`pids`、`disk` 以 cgroup（可用時）與 rlimit 盡力套用；未設定時使用預設值（1Gi、256、1Gi）。`cpu` 尚未套用。
  沒有 cgroup 時記憶體上限只限單一程序；實際的套用方式與範圍寫在報告與標籤上（見 [03](03-architecture.md) 第 6.1 節）。
- **`network.egress[].via: ai-gate`**：AI 閘門尚未實作，含此欄位的宣告在強制模式**拒絕執行**。
- **`network.egress[].limits.upload_per_day`**：以目的地主機:連接埠為單位、依 UTC 日期累計，存在核心狀態目錄。
- **`network.ingress`**：只支援 `expose: loopback` 搭配 `auth: local-token`，而且只代理 HTTP（WebSocket 升級未經測試）。
- **`ai`、`data`、`supply_chain`**：只檢查結構與參照（例如 `data.flows[].to` 必須指向存在的 `network.egress[i]`），執行期不強制，標籤標示為「僅聲明」。
- **`denied_by_design`**：`warp draft` 會把側錄中被核心擋下的連線自動列入。
- **`warp draft`**：預設略過結束碼非 0 的側錄（130、143——被 Ctrl+C／SIGTERM 中斷——視為正常停止並採用；`--include-failed` 改為採用並標示）；
  `app.version` 取自應用根目錄的 `package.json` 或 `pyproject.toml`，找不到時暫填 `0.1.0`；`app.kind` 一律暫填 `cli`（側錄中有監聽不代表是網頁應用，
  輸出會列出是哪個指令監聽了哪個埠）；`app.entry` 取自最後一次採用的側錄指令（含參數），輸出會提示確認。
  機密只出現在網址或請求內容時無法授權（閘門只注入標頭，`app-visible` 也需要標頭綁定與標頭證據），初稿會如實說明。
- **宣告中沒有設定環境變數的欄位**：殼內的環境變數由核心產生（見 [03](03-architecture.md) 第 6.1 節），應用需要的設定請以指令參數或 `env 名稱=值 <指令>` 寫在 `app.entry` 中。
