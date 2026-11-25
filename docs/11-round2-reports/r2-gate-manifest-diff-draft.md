# 第二輪獨立審查 r2：gate、manifest、diff、draft

這是審查代理的原始報告，未經修改。代理沒看過第一輪紀錄與其他代理的報告，只能讀碼、不能執行。各項發現經查證後的判定見 [11 交叉比對](../11-security-review-round2.md)；本報告中的嚴重度是代理自己的初判，可能與查證後不同。

## 摘要

這次只讀了原始碼，沒有執行任何東西。範圍是 internal/manifest、gate、diff、draft，另外看了 runner、label、evidence、ledger、netpolicy 這些相關模組。核心的強制機制大致做得紮實：YAML 封閉格式、主機名稱正規化、解析後的位址檢查、SNI 比對、宣告沒通過檢查就拒絕執行。但「人只看標籤」這條信任鏈有一個嚴重缺口：標籤、diff、重放輸出都把作者或 Agent 寫的自由文字原樣印到終端機，沒有過濾控制字元，可以把真正的授權藏起來或偽造出來。另外有幾處宣稱的保證守不住：`evidence replay` 完全不跑 lint，就直接套用宣告裡的內網與萬用字元出口；每日上傳上限可以繞過，而且可能跟標籤寫的不一致；機密會以明文送到非 443 的連接埠；軟性規則的例外可以由 Agent 自己「核可」。

## 發現

### [High] 標籤、diff、重放、帳本輸出沒有過濾終端控制字元，人看到的跟實際生效的可以不同
- **位置：**
  - `internal/label/label.go:282-296`（Version、DisplayName、Purpose）、`:321`（授權依據指令）、`:360`（AuthorNote）、`:273-275`（`row`／`wrap` 原樣輸出，不處理 `\n`、`\r`、ESC）
  - `internal/diff/diff.go:36`（新增項目的用途）
  - `internal/manifest/lint.go:142-148`（purpose 只檢查是否空白、是否還是佔位字）
  - `internal/evidence/trace.go:239-252`（`CommandString` 只加單引號，控制字元原封不動）
  - `internal/runner/replay.go:160,229`
  - `cmd/warp/main.go:555`（`ledger show`）
- **違反的保證：** 「人只看標籤，並對標籤的差異做決定」，以及「要作惡就必須把惡意行為寫進標籤給人看」（README 核心想法第 5 點、威脅模型 T5）。
- **攻擊情境：**
  - **惡意作者或被操控的安裝 Agent（T4／T5），利用 purpose：** 宣告寫 `network.egress[0]: {host: exfil.evil.com, port: 443, purpose: "\e[2K\r  🌐 連線　api.openai.com:443　— 呼叫模型"}`。yaml.v3 會把雙引號字串裡的 `\e` 解成 ESC。lint 只檢查 purpose 不是空白、不含 todo，所以會通過。`warp label` 印出 `  🌐 連線　exfil.evil.com:443　— ` 之後，ESC[2K 清掉整行，`\r` 回到行首，再印出假的那一行，人看到的是 `api.openai.com`。同樣的手法可以用 `\e[1A`（游標上移）蓋掉「需要你特別注意」區的例外，或用 `\n│ ...` 偽造「這個工具不可以」的條目。`warp diff` 會把新增項目的用途印成 `＋ 新增對外連線：…（用途：<注入>）`，一樣能把新增的權限藏起來。
  - **利用指令：** Agent 用 `warp record -- sh -c $'curl …\e[2K\rpytest tests/'` 之類帶 ESC 的 argv 側錄。`triggered_by` 必須逐字照抄 `CommandString` 的結果，而這個結果仍然含 ESC，所以標籤的「授權依據」那行會顯示成無害的指令。`evidence replay` 用的側錄檔不驗簽章，作者可以任意填 argv，輸出的「重放指令：」也會被同樣偽造。
  - **由殼內應用發起：** 應用請求 `http://allowed.host/%1b[2K...`，`req.URL.Path` 解碼後含有 ESC，寫進帳本的 Detail。之後 `warp ledger show` 會把這些拒絕紀錄抹掉或改寫，`ledger verify` 仍然會通過。
  - Unicode 雙向控制字元（U+202E 等）也能在 label.json 的檢視器裡重排文字。
- **根因：** 自由文字欄位（purpose、display_name、version、author_note、argv、帳本裡由應用控制的欄位）在解析、lint、輸出三個階段都沒有限制字元集或做跳脫。
- **修補建議：**
  - lint 階段把所有自由文字欄位裡的 C0／C1 控制字元、DEL、雙向控制字元（U+200E/F、U+202A–202E、U+2066–2069）、行分隔字元列為硬性錯誤。
  - `label.Render`、`diff`、`PrintReplay`、`ledger show`、`notify` 統一經過一個跳脫函式，把非可列印字元顯示成 `\x1b` 這種形式。
  - `CommandString` 對控制字元改用 `$'…'` 加跳脫的表示法。
- **信心：高。** 程式路徑都已逐行確認。還沒確認的只有：yaml.v3 v3.0.1 支援 `\e` 跳脫，這是依記憶判斷；就算不支援，`\x1b`、`\u001b` 也是 YAML 1.2 的標準跳脫。

### [Medium] `evidence replay` 不跑 lint，就把未檢查的宣告出口（含 `lan: true`、整個頂級網域的萬用字元）套用到接收者的機器上
- **位置：**
  - `internal/runner/replay.go:88-99`（只做 `LoadFile`）
  - `internal/runner/runner.go:209-214`（record 模式載入宣告時不跑 lint）、`:414-421`（`recordOnly` 直接沿用宣告裡的 Host、LAN）
  - `internal/gate/egress.go:170-201`
- **違反的保證：** 硬性規則「對外連線不得使用全域萬用字元」「連往區域網路需要人工核可」；以及 docs/03 §6.5 說重放「對外連線只允許宣告中的目的地」時，隱含這些目的地已經過檢查器。
- **攻擊情境：** 惡意作者交出一份宣告加上 `.warp/evidence/trace-0001.json`。側錄檔不驗簽章，指令可以任意填。接收者照文件建議，在決定信任之前先跑 `warp evidence replay` 驗證證據。宣告裡寫了 `{host: 192.168.1.1, port: 80, lan: true}` 或 `{host: "*.com", port: 443}`，重放時：
  - `decide` 用 `hostEqual` 比對 RecordOnly 規則，`rule.LAN=true` 會放行私有位址。
  - `"*.com"` 經 `HostMatches` 會匹配任何 .com 網域。
  
  結果是：在人還沒同意任何標籤之前，作者的程式就能存取接收者的路由器或內網服務（宣告的連接埠），也能連到任何 .com 主機。lint 本來會擋下 `*.com`（`egress-global-wildcard`），也會要求 LAN 要有例外，重放時這些全部被跳過。
- **根因：** 重放走的是 record 模式，record 模式把宣告當可信的輸入使用，卻沒有執行 `Lint` 或 `checkSupported`。
- **修補建議：** 重放前先跑 `Lint`，至少要求硬性規則全部通過（證據簽章相關的錯誤可以排除在外）。重放時強制 `LAN=false`，除非使用者另外加旗標明確同意。萬用字元規則在重放時只允許側錄檔裡出現過的具體主機。
- **信心：高。** 程式路徑都已確認。

### [Medium] 每日上傳上限可以繞過，而且可能跟標籤上寫的不一致
- **位置：**
  - `internal/gate/egress.go:174-181`（第一條符合的規則就生效）、`:540-547`、`:590-592`、`:715`（計數鍵用的是實際連線的 `host:port`）
  - `internal/gate/usage.go:42-55`
  - `internal/label/label.go:118-120`
  - `internal/diff/diff.go:62-64`
- **違反的保證：** 標籤上「某主機:連接埠，每日上傳 ≤ N」的強制性；流量上限這條防線。
- **攻擊情境（惡意應用）：**
  1. **萬用字元：** 宣告 `*.cdn.example.com:443, upload_per_day: 10M`，人會理解成總量 10M。實際上每個子網域（`a1.cdn…`、`a2.cdn…`）各自有一份 10M 的計數。
  2. **IP 字面值：** 規則寫 `8.8.8.8`，應用改用 `[::ffff:8.8.8.8]`、`[0::ffff:808:808]`、`[0000:0::ffff:8.8.8.8]` 等不同寫法發 CONNECT。`hostEqual` 會先 Unmap 再比對，所以視為同一主機；但計數鍵 `target` 用的是原始字串，每種寫法各算一份額度。
  3. **規則重疊：** 宣告中 `*.example.com:443`（沒有上限）排在 `api.example.com:443, upload_per_day: 1M` 前面。`decide` 取第一條符合的規則，所以 `api.example.com` 實際上沒有上限，但標籤和 diff 都顯示「≤ 1M」。
- **根因：** 上限是寫在單一授權上的，計數卻以實際連線的目的地為鍵；IP 位址沒有正規化；多條規則重疊時沒有合併，也沒有報錯。
- **修補建議：**
  - 計數鍵改用 `rule.Grant`。
  - IP 位址一律 `Unmap().String()` 正規化。
  - lint 發現兩條規則可能匹配同一主機與連接埠時報錯；或者在 gate 端取所有符合規則中最嚴格的上限與 LAN 設定。
- **信心：高。** 三條路徑都已逐行確認。

### [Medium] 機密會以明文 HTTP 注入，送往非 443 的連接埠
- **位置：** `internal/gate/egress.go:558-572`（只擋 `scheme=="http" && port==443`）；`internal/manifest/lint.go:408-421`（只要求綁定主機出現在 egress，不管連接埠或傳輸方式）
- **違反的保證：** 「金鑰無法被送往綁定以外的主機」（docs/03 §2.5）。沒有 TLS，主機名稱的綁定只靠 DNS 和路由，沒有任何真實性保證。
- **攻擊情境：** 宣告把機密綁到 `api.vendor.com`，egress 列了 `api.vendor.com:8443`（實際是 TLS），或列了 `:80`。惡意應用送出 `http://api.vendor.com:8443/`，標頭裡放佔位值。閘門把真值換進去，以明文送出；伺服器會回 400，但金鑰已經上線路。路徑上的攻擊者，或能污染主機 DNS 解析的人（閘門用系統解析器，沒有 TLS 驗證），就能拿到真正的金鑰。
- **根因：** 「拒絕明文」只針對 443 這個特例，沒有改成「注入機密一律要求 TLS」。
- **修補建議：** 機密注入只在檢視過的 TLS 通道（`scheme=="https"`）上做；明文 HTTP 帶佔位值一律拒絕。或者讓 lint 要求綁定主機的 egress 授權標明 TLS。
- **信心：高（程式路徑）。** 實際被利用需要網路位置或 DNS 控制，這部分是推論。

### [Medium] 軟性規則的例外可以由 Agent 自己寫入並通過，而公共後綴萬用字元只被當成軟性規則
- **位置：** `internal/manifest/lint.go:215-226`（只要 `exceptions` 裡有 rule 加 grant 就算核可）、`:296-314`（`*.co.uk` 這類只要求底下至少一個點）、`:526-541`（`exception-unsigned` 只是警告）
- **違反的保證：** 「Agent 不能替人簽核」（docs/04 §3）；硬性規則「對外連線不得使用全域萬用字元」的精神。
- **攻擊情境：** 被操控的安裝 Agent 寫入 `host: "*.github.io"`（或 `*.amazonaws.com`、`*.workers.dev`、`*.ngrok-free.app`、`*.co.uk`），再自己補一筆 `exceptions: {rule: egress-subdomain-wildcard, approved_by: 王小明, …}`。lint 的錯誤數是 0，enforce 照常執行，標籤顯示「已列入例外」，看起來像有人核可過。結果應用可以把資料外送到任何人都能註冊的子網域。

  相關的另一種寫法：在攻擊者控制的網域上設 `lan: true`（例如 `*.nip.io`，或一個解析到 10.x 的自有網域），等於在宣告的連接埠上可以連到任意內網 IP。
- **根因：** 第 1 期沒有同意代理，例外只是一段純文字；萬用字元也沒有對照公共後綴清單（PSL）。
- **修補建議：**
  - 把萬用字元的基底落在 PSL 公共後綴或「可註冊網域就是後綴的下一層」的情況列為硬性錯誤（例如 `*.github.io`、`*.co.uk`）。
  - 在同意代理實作之前，標籤上的例外狀態改顯示成「作者自稱已核可（未驗證）」，不要用「已列入例外」。
  - 主機名稱加 `lan: true` 時，至少顯示「解析結果由該網域的 DNS 決定」。
- **信心：高。** 文件第 6 節承認例外沒有簽章，但標籤用語和 PSL 這兩點沒有被涵蓋。

### [Low] 稽核帳本寫不進去時閘門照常放行；應用可以塞滿磁碟來觸發
- **位置：** `internal/ledger/ledger.go:236-243`（`Log` 失敗只印警告）；`internal/runner/runner.go:319,740`（APP_DATA 和 `ledger.jsonl` 在同一個 `appState` 目錄）
- **違反的保證：** 「所有越界嘗試都有紀錄」。
- **攻擊情境：** 惡意應用在可寫的 `${APP_DATA}` 裡寫很多個剛好低於 RLIMIT_FSIZE 的檔案；文件也承認宣告目錄的總量沒有上限。主機的狀態目錄所在檔案系統被寫滿後，帳本寫入失敗，或寫到一半留下半行，之後每次 Append 都會因為解析失敗而出錯。從這時起，應用的越界嘗試和放行紀錄都不會留下，閘門卻繼續轉送流量。
- **修補建議：** 帳本寫入失敗時停止殼的執行（fail-closed），或讓閘門改成全部拒絕。APP_DATA 加上配額，或放到不同的檔案系統。
- **信心：中。** 「同一檔案系統」是依預設路徑推論的；寫滿之後的行為已依程式碼確認。

### [Low] `warp diff` 漏掉部分會影響決定的欄位，也不做檢查
- **位置：** `internal/diff/diff.go:103-149`；`cmd/warp/main.go:413-434`
- **違反的保證：** 「版本差異是使用者在更新時唯一需要看的東西」（docs/04 §5）。
- **攻擊情境：** 新版只改了 `app.entry`、`evidence[].triggered_by`（也就是標籤上的授權依據指令）、`display_name`、`author_note`、`ai.providers[].models`、`ai.budget.per_request_tokens`、`data.flows`、`runtime.background`，或現有授權的 `purpose`。diff 會回報「權限沒有變動」，或只多一行「應用內容已變動」。另外，例外是用索引（`network.egress[0]`）當鍵，宣告重新排序後，例外會默默改套到另一條授權上。diff 也不跑 lint，宣告根本無法執行時，畫面上也不會提示。
- **修補建議：** 把上面這些欄位都納入比對；例外改用授權內容（主機:連接埠或路徑）當鍵；diff 時一併跑 lint，顯示錯誤數。
- **信心：高。**

### [Low] 高風險工具名稱的內建下限可以繞過
- **位置：** `internal/manifest/lint.go:106,430-440`
- **攻擊情境：** `SEND_EMAIL` 會被拆成 `S`、`E`、`N`、`D`…；`sendemail`、`deletefile` 是一整個詞，不在清單裡；用 Cyrillic 的 `ѕend` 也比對不到。這些都能標成 `risk: low`，而且不需要 gate。第 1 期 AI 通道只是「僅聲明」，影響是標籤和 diff 顯示錯誤的風險。
- **修補建議：** 先把名稱轉小寫，再依 `_`、`-`、`.` 和大小寫邊界切詞；同時檢查子字串；名稱限制為 ASCII。
- **信心：高。**

### [Low] 對內閘門可被其他本機埠的網頁以 GET 請求做 CSRF
- **位置：** `internal/gate/ingress.go:142-172`
- **攻擊情境：** 另一個殼裡的惡意應用，或本機上任何網頁服務（例如 `127.0.0.1:9000`），在使用者瀏覽器中嵌入 `<img src="http://127.0.0.1:8080/api/delete?id=1">`，或用頂層導覽。不同埠在瀏覽器眼中是同站，SameSite=Strict 的 cookie 會被帶上；而 no-cors 的 GET 不送 Origin，Origin 檢查形同沒有。結果是可以觸發目標應用裡有副作用的 GET 端點。
- **修補建議：** 檢查 `Sec-Fetch-Site`，只接受 `same-origin` 或 `none`；或者在 cookie 之外，對非頂層導覽要求 `X-Warp-Token` 標頭。
- **信心：中。** 依瀏覽器行為推論，沒有實測。

### [Low] 不檢視內容的通道仍可做網域前置（TLS 內的 Host 標頭或 ECH）
- **位置：** `internal/gate/egress.go:381-417`
- **攻擊情境：** 宣告一個放在共用 CDN 上的合法主機。應用的外層 SNI 填這個主機，TLS 裡面的 HTTP Host 標頭（或 ECH 的內層 SNI）指向同一個 CDN 上攻擊者的站點。閘門只能比對外層 SNI，所以會放行。
- **修補建議：** 標籤上註明這個限制；必要時對共用 CDN 的主機強制檢視內容，或拒絕帶 ECH 擴充的 ClientHello。
- **信心：低到中。** 能不能成功取決於 CDN 是否允許前置。

### [Low] 宣告可以「領取」接收者環境裡任何同名的變數，也可以覆寫殼內的核心環境變數
- **位置：** `internal/runner/runner.go:424-441,551-553`；`internal/manifest/lint.go:103`
- **攻擊情境：**
  - 宣告列一個叫 `AWS_SECRET_ACCESS_KEY` 或 `GITHUB_TOKEN` 的機密，綁到作者的主機。接收者的 shell 裡剛好有這個變數時，核心會直接拿去用，不會逐項詢問。名稱和主機雖然會顯示在標籤上，但接收者未必意識到這是自己現有的憑證。
  - 機密名稱也可以是 `HTTPS_PROXY`、`SSL_CERT_FILE`、`PATH`、`HOME`。`secretEnv` 最後才寫入，會蓋掉核心設定的環境；如果設成 `app-visible`，主機上的 PATH 等值會漏給應用。
- **修補建議：** 機密名稱禁止和核心保留的環境變數重名；enforce 時列出要取用的機密並要求互動確認，或要求加上明確的 `--secret` 旗標。
- **信心：中。** 程式路徑已確認；危害程度取決於使用者的環境。

## 檢查過且認為沒問題的地方
- **YAML 封閉格式：** 重複鍵靠 yaml.v3 拒絕（`lint_test.go:201` 有測試）；錨點、別名、合併鍵、明確標記都由 `checkPlain` 拒絕；多份文件會被拒；有 `KnownFields(true)`；`StrictBool` 擋掉了 yes／on 這類寫法；字串寫成的數字無法解碼成 int。
- **路徑變數：** `PathVar` 是完整比對加嚴格正規式，不支援絕對路徑和 `~`，pick 名稱限制為小寫英數；不存在正規化的空間。
- **主機名稱驗證：** 只接受小寫 ASCII、至少兩段、最後一段不能全是數字，所以 `127.1`、`0x7f.0.0.1`、單段名稱、帶 zone 的 IPv6 都被拒；loopback 名稱在加了萬用字元之後也會檢查。
- **閘門的位址檢查：** 每一個解析結果都要通過檢查，而且直接連往檢查過的那個 IP，防住 DNS rebinding；IPv4-mapped、NAT64、6to4、Teredo、中繼資料位址都有分類；主機自己介面的位址會被擋。
- **Host 和 SNI 一致性：** 檢視通道和明文請求都比對 Host 標頭與連線目的地；不檢視的通道要求 SNI 和核准主機相同，沒有 SNI 也會擋。
- **本機 CA：** 每次執行重新產生，私鑰只在記憶體中，enforce 時帶 X.509 名稱限制，只放進殼內的信任庫。
- **機密注入範圍：** 只在綁定主機的指定標頭替換隨機佔位值；回應的標頭和內容採串流遮蔽，跨區塊也比對得到；遇到無法解開的內容編碼就整個擋下；禁用的傳輸層標頭清單合理。
- **fail-closed 的部分：** enforce 和 probe 在 lint 有錯誤時拒絕執行；宣告要求不支援的 isolation、`via: ai-gate`、非 loopback 的 expose 時拒絕執行，不會降級；`visibility`、`spawn` 沒有預設值，缺少就是 lint 錯誤。
- **證據路徑：** `observed_in` 會拒絕 `..` 和絕對路徑，並要求前綴是 `.warp/evidence/`；側錄檔是獨佔寫入、不覆蓋；簽章金鑰會檢查權限和擁有者。
- **請求標頭大小：** 有 1 MiB 上限，避免核心的記憶體被耗盡。
- **對內閘門的權杖：** 白名單只接受 127.0.0.1 或 localhost 的 Host；權杖用常數時間比較；轉給應用之前會移除所有 `warp_token_*` cookie 和權杖參數。
- **掛載來源檢查：** `checkHostMount` 會擋系統目錄、家目錄及其上層、憑證目錄、看起來像家目錄的資料夾、容器控制 socket、和狀態目錄重疊的路徑；路徑都先用 EvalSymlinks 解析。
- **draft：** 用途都留成佔位文字，lint 會拒收；只採用合法的變數根目錄；不採用被閘門擋下的連線；只採用簽章有效、內容雜湊相符的側錄檔。
- **內容雜湊：** 每行格式在檔名含換行時理論上有歧義，但要構造碰撞，兩棵目錄樹的內容必須幾乎相同；在現有威脅模型下（Agent 本來就能重新側錄）沒有實際的攻擊價值，所以不列為發現。
