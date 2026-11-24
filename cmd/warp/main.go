// Command warp is the SecureAIWarp core: a deterministic, model-free
// enforcer for warp.yaml declarations.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/diff"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/draft"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/label"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/ledger"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/probe"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/runner"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/sandbox"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/state"
)

// Version of the core.
const Version = "0.1.0-mvp"

// Exit codes.
const (
	exitOK       = 0
	exitFail     = 1   // lint errors, probe penetration
	exitUsage    = 2   // usage error or not implemented
	exitInternal = 125 // the core itself failed (fail closed)
)

func main() {
	// Hidden entry points used inside the shell. They must be dispatched
	// before anything else.
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case sandbox.InitArg:
			sandbox.RunInit()
			return
		case sandbox.ExecArg:
			sandbox.RunExec(os.Args[2:])
			return
		case probe.AgentArg, probe.NestedArg, probe.SleepArg, probe.MemArg:
			os.Exit(probe.RunHidden(os.Args[1], os.Args[2:]))
		}
	}
	os.Exit(run(os.Args[1:]))
}

const usage = `SecureAIWarp 核心 warp ` + Version + `

用法：warp <指令> [選項]

  init                         建立 .warp/ 工作目錄
  record [選項] -- <指令>      側錄模式：在拋棄式殼內執行並記錄各通道行為（使用誘餌機密）
  draft [--from 目錄] [-o 檔]  由側錄紀錄產生宣告初稿
  lint [-f 宣告]               檢查宣告（硬性規則、軟性規則、證據）
  enforce [選項] [-- <指令>]   強制模式：只放行宣告內的行為
  probe [-f 宣告]              探測模式：在強制模式的殼內主動嘗試越界並回報
  label [-f 宣告] [--json]     由宣告產生權限標籤（終端機 + .warp/label.json）
  diff <舊宣告> <新宣告>       以人話列出兩版宣告的權限差異
  digest                       計算應用內容雜湊
  evidence replay [選項]       在本機重新執行每份證據的側錄指令，確認宣告的行為確實重現
  ledger verify|show           驗證或列出稽核帳本
  survey                       （尚未實作）靜態盤點
  seal                         （尚未實作）封籤

共用選項：-C <目錄> 應用根目錄（預設為目前目錄）；-f <檔案> 宣告檔（預設 .warp/warp.yaml）
record / enforce 選項：--pick 名稱=資料夾（可重複）
record 專用：--pick-rw 名稱=資料夾、--secret 名稱（可重複）
`

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

type common struct {
	fs       *flag.FlagSet
	dir      *string
	manifest *string
}

func newFlags(name string) *common {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	c := &common{fs: fs}
	c.dir = fs.String("C", ".", "應用根目錄")
	c.manifest = fs.String("f", "", "宣告檔（預設 <應用根目錄>/.warp/warp.yaml）")
	return c
}

func (c *common) appRoot() (string, error) {
	return runner.ResolveAppRoot(*c.dir)
}

func (c *common) manifestPath(root string) string {
	if *c.manifest != "" {
		p, _ := filepath.Abs(*c.manifest)
		return p
	}
	return filepath.Join(root, ".warp", "warp.yaml")
}

func errorf(format string, a ...any) int {
	fmt.Fprintf(os.Stderr, "warp：錯誤："+format+"\n", a...)
	return exitInternal
}

func run(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return exitUsage
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "-h", "--help", "help":
		fmt.Print(usage)
		return exitOK
	case "--version", "version":
		fmt.Printf("warp %s（SecureAIWarp 核心；不含任何模型）\n", Version)
		return exitOK
	case "init":
		return cmdInit(rest)
	case "lint":
		return cmdLint(rest)
	case "record", "enforce":
		return cmdRun(cmd, rest)
	case "probe":
		return cmdProbe(rest)
	case "label":
		return cmdLabel(rest)
	case "draft":
		return cmdDraft(rest)
	case "diff":
		return cmdDiff(rest)
	case "digest":
		return cmdDigest(rest)
	case "ledger":
		return cmdLedger(rest)
	case "evidence":
		return cmdEvidence(rest)
	case "survey":
		fmt.Fprintln(os.Stderr, "warp：survey（靜態盤點、相依與機密掃描）尚未實作，不在第 1 期範圍。請由 Agent 依 SKILL.md 手動盤點並寫入 .warp/survey.json。")
		return exitUsage
	case "seal":
		fmt.Fprintln(os.Stderr, "warp：seal（封籤與簽章）尚未實作，屬於第 2 期；目前無法產生 Warp Bundle。")
		return exitUsage
	}
	fmt.Fprintf(os.Stderr, "warp：未知的指令 %q\n\n%s", cmd, usage)
	return exitUsage
}

func cmdInit(args []string) int {
	c := newFlags("init")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	for _, d := range []string{"evidence", "reports", "patches"} {
		if err := os.MkdirAll(filepath.Join(root, ".warp", d), 0o755); err != nil {
			return errorf("%v", err)
		}
	}
	sr, _ := state.Root()
	fmt.Printf("已建立 %s\n", filepath.Join(root, ".warp"))
	fmt.Printf("核心狀態目錄（帳本、APP_DATA；永不掛入殼內）：%s\n", sr)
	fmt.Println("下一步：warp record -- <測試指令>，然後 warp draft --from .warp/evidence")
	return exitOK
}

func printFindings(w io.Writer, res *manifest.Result) {
	for _, f := range res.Findings {
		mark := "✖"
		if f.Level == manifest.LevelWarning {
			mark = "⚠"
		}
		path := f.Path
		if path != "" {
			path += "："
		}
		fmt.Fprintf(w, "  %s [%s] %s%s\n", mark, f.Rule, path, f.Message)
	}
}

func cmdLint(args []string) int {
	c := newFlags("lint")
	jsonOut := c.fs.Bool("json", false, "以 JSON 輸出")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	_, res, err := runner.LoadAndLint(root, c.manifestPath(root))
	if err != nil {
		fmt.Fprintf(os.Stderr, "warp：宣告無法解析：%v\n", err)
		return exitFail
	}
	if *jsonOut {
		b, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(b))
	} else {
		printFindings(os.Stdout, res)
		fmt.Printf("檢查結果：%d 個錯誤、%d 個警告；風險分數 %d（%s）\n", res.Errors(), res.Warnings(), res.Risk.Score, res.Risk.Level)
	}
	if res.Errors() > 0 {
		return exitFail
	}
	return exitOK
}

func parsePicks(list []string) (map[string]string, error) {
	out := map[string]string{}
	for _, p := range list {
		i := strings.IndexByte(p, '=')
		if i <= 0 || i == len(p)-1 {
			return nil, fmt.Errorf("--pick 格式應為 名稱=資料夾：%q", p)
		}
		out[p[:i]] = p[i+1:]
	}
	return out, nil
}

func splitDashDash(args []string) ([]string, []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func cmdRun(mode string, args []string) int {
	c := newFlags(mode)
	var picks, picksRW, secrets multiFlag
	c.fs.Var(&picks, "pick", "使用者選擇的資料夾：名稱=資料夾")
	if mode == "record" {
		c.fs.Var(&picksRW, "pick-rw", "側錄時可寫的資料夾：名稱=資料夾（請用合成資料）")
		c.fs.Var(&secrets, "secret", "側錄時以誘餌值提供的機密名稱")
	}
	flagArgs, command := splitDashDash(args)
	if err := c.fs.Parse(flagArgs); err != nil {
		return exitUsage
	}
	if c.fs.NArg() > 0 {
		fmt.Fprintln(os.Stderr, "warp：要執行的指令必須放在 -- 之後")
		return exitUsage
	}
	if mode == "record" && len(command) == 0 {
		fmt.Fprintln(os.Stderr, "warp：record 需要在 -- 之後提供要側錄的指令")
		return exitUsage
	}
	pm, err := parsePicks(picks)
	if err != nil {
		return errorf("%v", err)
	}
	rwm, err := parsePicks(picksRW)
	if err != nil {
		return errorf("%v", err)
	}
	rw := map[string]bool{}
	for k, v := range rwm {
		if _, dup := pm[k]; dup {
			return errorf("資料夾 %s 同時以 --pick 與 --pick-rw 指定", k)
		}
		pm[k] = v
		rw[k] = true
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	for _, sname := range secrets {
		if !envNameOK(sname) {
			return errorf("機密名稱 %q 必須是大寫環境變數名稱", sname)
		}
	}
	res, err := runner.Run(runner.Options{
		Mode: mode, AppRoot: root, ManifestPath: c.manifestPath(root), Command: command,
		Picks: pm, PicksRW: rw, SecretNames: secrets,
	})
	if err != nil {
		code := exitInternal
		if res != nil && res.ExitCode != 0 {
			code = res.ExitCode
		}
		fmt.Fprintf(os.Stderr, "warp：拒絕執行或執行失敗：%v\n", err)
		return code
	}
	return res.ExitCode
}

func envNameOK(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i, r := range s {
		if !(r == '_' || (r >= 'A' && r <= 'Z') || (i > 0 && r >= '0' && r <= '9')) {
			return false
		}
	}
	return true
}

func cmdProbe(args []string) int {
	c := newFlags("probe")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	rep, err := runner.Probe(runner.Options{Mode: runner.ModeProbe, AppRoot: root, ManifestPath: c.manifestPath(root)})
	if err != nil {
		return errorf("探測無法執行：%v", err)
	}
	probe.Print(os.Stdout, rep)
	if !rep.AllBlocked() {
		return exitFail
	}
	return exitOK
}

func cmdLabel(args []string) int {
	c := newFlags("label")
	jsonOut := c.fs.Bool("json", false, "只輸出 JSON")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	l, res, err := runner.LoadAndLint(root, c.manifestPath(root))
	if err != nil {
		return errorf("%v", err)
	}
	lb := label.Build(l, res, root)
	b, _ := json.MarshalIndent(lb, "", "  ")
	if err := os.MkdirAll(filepath.Join(root, ".warp"), 0o755); err == nil {
		_ = os.WriteFile(filepath.Join(root, ".warp", "label.json"), append(b, '\n'), 0o644)
	}
	if *jsonOut {
		fmt.Println(string(b))
	} else {
		fmt.Print(label.Render(lb))
		if res.Errors() > 0 {
			fmt.Printf("⚠ 宣告有 %d 個檢查錯誤，此標籤對應的宣告目前無法在強制模式執行。\n", res.Errors())
		}
	}
	if res.Errors() > 0 {
		return exitFail
	}
	return exitOK
}

func cmdDraft(args []string) int {
	c := newFlags("draft")
	from := c.fs.String("from", "", "側錄紀錄目錄（預設 .warp/evidence）")
	out := c.fs.String("o", "", "輸出檔（預設 .warp/warp.yaml；已存在時寫到 .warp/warp.draft.yaml）")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	dir := *from
	if dir == "" {
		dir = filepath.Join(root, ".warp", "evidence")
	} else if !filepath.IsAbs(dir) {
		dir = filepath.Join(root, dir)
	}
	key, err := state.TraceKey()
	if err != nil {
		return errorf("%v", err)
	}
	d, err := draft.FromDir(root, dir, key)
	if err != nil {
		return errorf("%v", err)
	}
	target := *out
	if target == "" {
		target = filepath.Join(root, ".warp", "warp.yaml")
		if _, err := os.Stat(target); err == nil {
			target = filepath.Join(root, ".warp", "warp.draft.yaml")
		}
	}
	if err := os.WriteFile(target, d.YAML, 0o644); err != nil {
		return errorf("%v", err)
	}
	fmt.Printf("已產生宣告初稿：%s\n", target)
	for _, n := range d.Notes {
		fmt.Printf("  • %s\n", n)
	}
	fmt.Println("請逐條收緊並填寫每條授權的 purpose，再執行 warp lint。")
	return exitOK
}

func cmdDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "用法：warp diff <舊宣告> <新宣告>")
		return exitUsage
	}
	a, err := manifest.LoadFile(args[0])
	if err != nil {
		return errorf("%v", err)
	}
	b, err := manifest.LoadFile(args[1])
	if err != nil {
		return errorf("%v", err)
	}
	lines := diff.Compare(a.Manifest, b.Manifest)
	if len(lines) == 0 {
		fmt.Println("（權限沒有變動）")
	}
	for _, l := range lines {
		fmt.Println(l)
	}
	return exitOK
}

func cmdDigest(args []string) int {
	c := newFlags("digest")
	if err := c.fs.Parse(args); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	d, err := manifest.ComputeDigest(root)
	if err != nil {
		return errorf("%v", err)
	}
	fmt.Println(d)
	return exitOK
}

func cmdEvidence(args []string) int {
	if len(args) == 0 || args[0] != "replay" {
		fmt.Fprintln(os.Stderr, "用法：warp evidence replay [-C 目錄] [-f 宣告] [--pick 名稱=合成資料夾] [--timeout 60s]")
		return exitUsage
	}
	c := newFlags("evidence replay")
	var picks multiFlag
	c.fs.Var(&picks, "pick", "重放時使用的合成資料夾：名稱=資料夾（預設為核心產生的合成資料）")
	timeout := c.fs.Duration("timeout", 60*time.Second, "每個指令的時間上限")
	if err := c.fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	pm, err := parsePicks(picks)
	if err != nil {
		return errorf("%v", err)
	}
	fmt.Fprintln(os.Stderr, "warp：證據重放：以側錄模式重新執行每份證據記錄的指令（只用誘餌機密與合成資料，對外連線只允許宣告的目的地），")
	fmt.Fprintln(os.Stderr, "      並檢查每條授權的行為是否再次出現。側錄檔中除了指令以外的內容都不採信。")
	rep, err := runner.Replay(runner.ReplayOptions{AppRoot: root, ManifestPath: c.manifestPath(root), Picks: pm, Timeout: *timeout})
	if err != nil {
		return errorf("重放無法執行：%v", err)
	}
	runner.PrintReplay(os.Stdout, rep)
	if !rep.AllReproduced() {
		fmt.Println("有授權的行為沒有重現：它的證據不能在這台機器上被確認。請檢查上面列出的指令，或要求作者補充證據。")
		return exitFail
	}
	fmt.Println("全部授權的行為都已由上面列出的指令重現。注意：這證明「這些指令會做出這些行為」，不證明這些指令就是應用的正常用法——請看指令本身。")
	return exitOK
}

func cmdLedger(args []string) int {
	if len(args) == 0 || (args[0] != "verify" && args[0] != "show") {
		fmt.Fprintln(os.Stderr, "用法：warp ledger verify|show [-C 目錄] [--run 執行編號] [--expect 筆數:雜湊]")
		return exitUsage
	}
	sub := args[0]
	c := newFlags("ledger")
	runID := c.fs.String("run", "", "只顯示此執行編號")
	onlyDeny := c.fs.Bool("denied", false, "只顯示被阻擋的項目")
	expect := c.fs.String("expect", "", "verify：另外比對先前抄下的尾端值（格式：筆數:雜湊）")
	if err := c.fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	root, err := c.appRoot()
	if err != nil {
		return errorf("%v", err)
	}
	name := filepath.Base(root)
	if l, err := manifest.LoadFile(c.manifestPath(root)); err == nil {
		name = l.Manifest.App.Name
	}
	dir, err := state.AppDir(root, name)
	if err != nil {
		return errorf("%v", err)
	}
	path := filepath.Join(dir, "ledger.jsonl")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		fmt.Printf("尚無稽核帳本（%s）\n", path)
		return exitOK
	}
	if sub == "verify" {
		r, err := ledger.Verify(path)
		if err != nil {
			fmt.Printf("✖ 帳本驗證失敗：%v\n", err)
			return exitFail
		}
		if *expect != "" {
			var seq uint64
			var hash string
			if n, _ := fmt.Sscanf(strings.Replace(*expect, ":", " ", 1), "%d %s", &seq, &hash); n != 2 {
				fmt.Fprintln(os.Stderr, "warp：--expect 的格式為 筆數:雜湊")
				return exitUsage
			}
			if got := r.HashAt(seq); got != hash {
				fmt.Printf("✖ 帳本與先前抄下的尾端值不符：第 %d 筆的雜湊為 %q，預期 %s（帳本被截斷或改寫）\n", seq, got, hash)
				return exitFail
			}
			fmt.Printf("✔ 第 %d 筆與先前抄下的尾端值一致\n", seq)
		}
		fmt.Printf("✔ 帳本雜湊鏈完整，尾端與錨點一致：%d 筆（放行 %d、阻擋 %d）\n  %s\n", r.Entries, r.Allow, r.Deny, path)
		fmt.Printf("  尾端：第 %d 筆，雜湊 %s\n", r.Head.Seq, r.Head.Hash)
		fmt.Println("  ※ 帳本沒有秘密金鑰：同一個作業系統使用者可以把帳本與錨點一起改寫。若要事後發現這種改寫，請把上面的尾端值抄到別處保存，日後比對同一筆的雜湊。")
		return exitOK
	}
	entries, err := ledger.ReadAll(path)
	if err != nil {
		return errorf("%v", err)
	}
	counts := map[string]int{}
	for _, e := range entries {
		if *runID != "" && e.Run != *runID {
			continue
		}
		if *onlyDeny && e.Decision != "deny" {
			continue
		}
		counts[e.Channel+"/"+e.Decision]++
		fmt.Printf("%5d %s %-7s %-7s %-8s %-5s %s %s\n", e.Seq, e.Time, e.Mode, e.Channel, e.Action, e.Decision, e.Target, e.Detail)
	}
	var keys []string
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	fmt.Print("摘要：")
	for _, k := range keys {
		fmt.Printf(" %s=%d", k, counts[k])
	}
	fmt.Println()
	return exitOK
}
