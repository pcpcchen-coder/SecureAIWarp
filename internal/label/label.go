// Package label renders the permission label. Every fact field (paths,
// hosts, ports, limits) comes only from the manifest; purposes are shown as
// the author's (unverified) statements; coverage and verification are facts
// about this core and its reports.
package label

import (
	"fmt"
	"strings"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
)

// Version of the label format.
const Version = "0.1"

// Line is one "can" entry.
type Line struct {
	Channel string `json:"channel"`
	Icon    string `json:"icon"`
	Verb    string `json:"verb"`
	Object  string `json:"object"`
	Purpose string `json:"purpose,omitempty"` // author statement, unverified
}

// Coverage is the protection level of one channel.
type Coverage struct {
	Channel string `json:"channel"`
	Name    string `json:"name"`
	Level   string `json:"level"` // enforced|monitored|declared|none|unused
	Note    string `json:"note,omitempty"`
}

// Verification summarises reports that match the current manifest.
type Verification struct {
	LintErrors     int    `json:"lint_errors"`
	ProbeBlocked   int    `json:"probe_blocked"`
	ProbeTotal     int    `json:"probe_total"`
	ProbeNotImpl   int    `json:"probe_not_implemented"`
	ProbeCurrent   bool   `json:"probe_current"`
	EnforceCurrent bool   `json:"enforce_current"`
	EnforceExit    int    `json:"enforce_exit_code"`
	EnforceCommand string `json:"enforce_command,omitempty"`
	// RunIdentity and Resources describe the most recent current probe (or
	// enforce) run: which OS identity the core ran as and how each resource
	// limit was actually enforced on this machine.
	RunIdentity string                 `json:"run_identity,omitempty"`
	Resources   []report.ResourceLimit `json:"resources,omitempty"`
}

// Label is the machine-readable label (label.json).
type Label struct {
	LabelVersion   string               `json:"label_version"`
	ManifestSHA256 string               `json:"manifest_sha256"`
	App            manifest.App         `json:"app"`
	Isolation      string               `json:"isolation"`
	Risk           manifest.Risk        `json:"risk"`
	Can            []Line               `json:"can"`
	Cannot         []string             `json:"cannot"`
	Attention      []manifest.Attention `json:"attention"`
	Coverage       []Coverage           `json:"coverage"`
	Verification   Verification         `json:"verification"`
	TrustLevel     string               `json:"trust_level"`
	DeniedByDesign []manifest.Denied    `json:"denied_by_design,omitempty"`
	Notes          []string             `json:"notes"`
}

var kindNames = map[string]string{"cli": "命令列工具", "desktop": "桌面程式", "local-web": "本機網頁應用",
	"hosted": "代管服務", "mcp-server": "MCP 伺服器", "agent": "自主 Agent", "job": "排程工作"}
var isoNames = map[string]string{"process": "程序沙箱", "container": "容器", "microvm": "微型虛擬機", "wasm": "WebAssembly"}

// Build produces the label from a loaded manifest, its lint result and the
// reports in appRoot.
func Build(l *manifest.Loaded, res *manifest.Result, appRoot string) *Label {
	m := l.Manifest
	lb := &Label{LabelVersion: Version, ManifestSHA256: l.SHA256, App: m.App, Isolation: m.Runtime.Isolation,
		Risk: res.Risk, Attention: res.Attention, DeniedByDesign: m.DeniedByDesign}
	if lb.Attention == nil {
		lb.Attention = []manifest.Attention{}
	}
	for _, f := range m.Files {
		kind, pick, _ := manifest.PathVar(f.Path)
		verb := "讀取"
		if f.Mode == "rw" {
			verb = "讀寫"
		}
		obj := f.Path
		switch kind {
		case "APP_DATA":
			obj = "自己的資料目錄"
		case "APP_CACHE":
			obj = "自己的快取目錄"
		case "USER_PICK":
			obj = fmt.Sprintf("你選定的一個資料夾（%s）", pick)
		}
		lb.Can = append(lb.Can, Line{"files", "📁", verb, obj, f.Purpose})
	}
	lan := false
	for _, e := range m.Network.Egress {
		obj := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if e.LAN {
			obj += "（內部網路）"
			lan = true
		}
		if e.Limits != nil && e.Limits.UploadPerDay != "" {
			obj += "，每日上傳 ≤ " + e.Limits.UploadPerDay
		}
		lb.Can = append(lb.Can, Line{"egress", "🌐", "連線", obj, e.Purpose})
	}
	visible := false
	for _, s := range m.Secrets {
		obj := fmt.Sprintf("%s，只會送往 %s（工具本身看不到金鑰）", s.Name, s.Bind.Host)
		if s.Visibility == "app-visible" {
			obj = fmt.Sprintf("%s（工具可直接看到金鑰）", s.Name)
			visible = true
		}
		lb.Can = append(lb.Can, Line{"secrets", "🔑", "使用", obj, s.Purpose})
	}
	if m.AI != nil && m.AI.Budget != nil {
		lb.Can = append(lb.Can, Line{"ai", "🤖", "AI", fmt.Sprintf("每日上限 %g 美元（僅聲明，尚未強制）", m.AI.Budget.DailyUSD), ""})
	}
	for _, in := range m.Network.Ingress {
		lb.Can = append(lb.Can, Line{"ingress", "🚪", "開放", fmt.Sprintf("%d 埠，僅本機，需一次性權杖", in.Listen), in.Purpose})
	}
	if m.Runtime.Spawn == "any" {
		lb.Can = append(lb.Can, Line{"process", "⚙", "執行", "任意指令", ""})
	}

	lb.Cannot = []string{"存取其他檔案（包含家目錄與憑證目錄）", "連到其他網站或其他連接埠", "連到主機本機與雲端中繼資料位址"}
	if !lan {
		lb.Cannot = append(lb.Cannot, "連到你的內部網路")
	}
	if len(m.Secrets) > 0 && !visible {
		lb.Cannot = append(lb.Cannot, "看到金鑰的真值")
	}
	lb.Cannot = append(lb.Cannot, "被其他電腦連入", "在主程式結束後於背景常駐")

	cov := func(ch, name, level, note string) { lb.Coverage = append(lb.Coverage, Coverage{ch, name, level, note}) }
	cov("files", "檔案", "enforced", "合成檔案系統；只有宣告的路徑存在")
	cov("process", "程序", "declared", "")
	cov("egress", "對外", "enforced", "唯一出口是核心代理；主機與連接埠白名單；解析後檢查位址")
	cov("ingress", "對內", "enforced", "只在主機 127.0.0.1 以權杖開放")
	if visible {
		cov("secrets", "機密", "monitored", "有 app-visible 機密：工具持有真值，只能限制它可連往的主機")
	} else {
		cov("secrets", "機密", "enforced", "工具只拿到佔位值；真值由閘門注入綁定主機")
	}
	if m.AI != nil {
		cov("ai", "AI", "declared", "AI 閘門尚未實作（第 2 期）")
	} else {
		cov("ai", "AI", "unused", "")
	}
	if m.Data != nil {
		cov("data", "資料", "declared", "資料閘門尚未實作（第 2 期）")
	} else {
		cov("data", "資料", "unused", "")
	}

	v := &lb.Verification
	v.LintErrors = res.Errors()
	digest, _ := manifest.ComputeDigest(appRoot)
	if p := report.LoadProbe(appRoot); p != nil && p.ManifestSHA256 == l.SHA256 && p.AppDigest == digest {
		v.ProbeCurrent = true
		v.ProbeBlocked, v.ProbeTotal, v.ProbeNotImpl = p.Counts()
		v.RunIdentity, v.Resources = p.Identity, p.Resources
	}
	if e := report.LoadEnforce(appRoot); e != nil && e.ManifestSHA256 == l.SHA256 && e.AppDigest == digest {
		v.EnforceCurrent = true
		v.EnforceExit = e.ExitCode
		v.EnforceCommand = strings.Join(e.Command, " ")
		if v.Resources == nil {
			v.RunIdentity, v.Resources = e.Identity, e.Resources
		}
	}
	for i := range lb.Coverage {
		if lb.Coverage[i].Channel == "process" {
			lb.Coverage[i].Note = "可執行的程式不受限制（spawn 僅聲明）；" + resourceNote(v.Resources)
		}
	}
	switch {
	case v.LintErrors > 0:
		lb.TrustLevel = "未達 L1"
	case v.ProbeCurrent && v.ProbeTotal > 0 && v.ProbeBlocked == v.ProbeTotal && v.EnforceCurrent && v.EnforceExit == 0:
		lb.TrustLevel = "L2"
	default:
		lb.TrustLevel = "L1"
	}
	lb.Notes = []string{
		"風險分數只用於比較與排序，不是絕對的安全評級。",
		"用途文字由作者或其 Agent 撰寫，未經驗證；主機、路徑、額度等事實欄位由核心從宣告產生並強制執行。",
		"殼限制的是爆炸半徑，不保證工具在允許範圍內的行為正確。",
	}
	return lb
}

var resourceNames = map[string]string{"memory": "記憶體", "pids": "程序數", "disk": "磁碟", "cpu": "CPU"}
var scopeNames = map[string]string{report.ScopeShell: "整個殼", report.ScopeProcess: "只限單一程序，殼的總量未受限",
	report.ScopeFile: "只限單一檔案，總量未受限", report.ScopeNone: "未強制"}

// resourceNote states how each resource limit actually held in the last
// current run. Without such a run nothing is claimed.
func resourceNote(rs []report.ResourceLimit) string {
	if len(rs) == 0 {
		return "資源上限尚未在此機器上以此版宣告執行過，實際效果未知"
	}
	var parts []string
	for _, r := range rs {
		parts = append(parts, fmt.Sprintf("%s %s %s（%s）", orRaw(resourceNames, r.Resource), r.Limit, orRaw(scopeNames, r.Scope), r.Mechanism))
	}
	return "資源上限：" + strings.Join(parts, "、")
}

// DegradedResources lists memory/pids limits that did not bound the whole shell.
func DegradedResources(rs []report.ResourceLimit) []report.ResourceLimit {
	var out []report.ResourceLimit
	for _, r := range rs {
		if (r.Resource == "memory" || r.Resource == "pids") && r.Scope != report.ScopeShell {
			out = append(out, r)
		}
	}
	return out
}

var levelIcon = map[string]string{"enforced": "🟢", "monitored": "🟡", "declared": "🟠", "none": "⚪", "unused": "－"}
var levelName = map[string]string{"enforced": "強制", "monitored": "監看", "declared": "僅聲明", "none": "無覆蓋", "unused": "未使用"}
var trustNames = map[string]string{"L1": "L1 已包覆", "L2": "L2 已驗證", "未達 L1": "未達 L1（宣告未通過檢查）"}

const inner = 66

// Render draws the terminal label.
func Render(lb *Label) string {
	var b strings.Builder
	hr := func(l, r string) { b.WriteString(l + strings.Repeat("─", inner+2) + r + "\n") }
	row := func(s string) {
		for _, line := range wrap(s, inner) {
			b.WriteString("│ " + line + strings.Repeat(" ", inner-width(line)) + " │\n")
		}
	}
	name := lb.App.DisplayName
	if name == "" {
		name = lb.App.Name
	}
	hr("┌", "┐")
	left := fmt.Sprintf("%s  v%s", name, lb.App.Version)
	right := fmt.Sprintf("風險等級：%s (%d)", lb.Risk.Level, lb.Risk.Score)
	row(left + strings.Repeat(" ", max(1, inner-width(left)-width(right))) + right)
	row(fmt.Sprintf("型態：%s　　隔離：%s", orRaw(kindNames, lb.App.Kind), orRaw(isoNames, lb.Isolation)))
	hr("├", "┤")
	row("這個工具可以")
	if len(lb.Can) == 0 {
		row("  （沒有任何授權）")
	}
	for _, c := range lb.Can {
		s := fmt.Sprintf("  %s %s　%s", c.Icon, c.Verb, c.Object)
		if c.Purpose != "" {
			s += "　— " + c.Purpose
		}
		row(s)
	}
	hr("├", "┤")
	row("這個工具不可以")
	for _, c := range lb.Cannot {
		row("  ✖ " + c)
	}
	hr("├", "┤")
	row("需要你特別注意")
	if len(lb.Attention) == 0 {
		row("  （無例外）")
	}
	for _, a := range lb.Attention {
		st := "已列入例外"
		if !a.Excepted {
			st = "尚未核可"
		}
		row(fmt.Sprintf("  ⚠ %s（%s）", a.Text, st))
	}
	hr("├", "┤")
	var cov []string
	for _, c := range lb.Coverage {
		cov = append(cov, c.Name+levelIcon[c.Level])
	}
	row("保護程度　" + strings.Join(cov, " "))
	for _, c := range lb.Coverage {
		if c.Level == "declared" || c.Level == "monitored" {
			row(fmt.Sprintf("　　%s%s：%s", c.Name, levelName[c.Level], c.Note))
		}
	}
	v := lb.Verification
	probe := "探針：尚未針對此版宣告執行"
	if v.ProbeCurrent {
		probe = fmt.Sprintf("探針 %d/%d 被擋下", v.ProbeBlocked, v.ProbeTotal)
		if v.ProbeNotImpl > 0 {
			probe += fmt.Sprintf("（另 %d 項尚未實作）", v.ProbeNotImpl)
		}
	}
	enf := "強制模式：尚未執行"
	if v.EnforceCurrent {
		if v.EnforceExit == 0 {
			enf = "強制模式執行通過"
		} else {
			enf = fmt.Sprintf("強制模式執行失敗（結束碼 %d）", v.EnforceExit)
		}
	}
	for _, r := range DegradedResources(v.Resources) {
		row(fmt.Sprintf("　　⚠ %s上限在此機器上%s（%s）", orRaw(resourceNames, r.Resource), orRaw(scopeNames, r.Scope), r.Mechanism))
	}
	row("驗證　　　" + probe + "｜" + enf)
	if v.RunIdentity != "" {
		row("執行身分　" + v.RunIdentity)
	}
	row("信任等級　" + orRaw(trustNames, lb.TrustLevel))
	if lb.App.AuthorNote != "" {
		row("作者說明　「" + lb.App.AuthorNote + "」← 未經驗證的自述")
	}
	hr("└", "┘")
	for _, n := range lb.Notes {
		b.WriteString("  ※ " + n + "\n")
	}
	return b.String()
}

func orRaw(m map[string]string, k string) string {
	if v, ok := m[k]; ok {
		return v
	}
	return k
}

// width returns the terminal display width of s.
func width(s string) int {
	w := 0
	for _, r := range s {
		w += runeWidth(r)
	}
	return w
}

func runeWidth(r rune) int {
	switch {
	case r == 0xFE0F || r == 0x200D || (r >= 0x300 && r <= 0x36F):
		return 0
	case r >= 0x1100 && r <= 0x115F, r >= 0x2E80 && r <= 0xA4CF, r >= 0xAC00 && r <= 0xD7A3,
		r >= 0xF900 && r <= 0xFAFF, r >= 0xFE30 && r <= 0xFE4F, r >= 0xFF00 && r <= 0xFF60,
		r >= 0xFFE0 && r <= 0xFFE6, r >= 0x1F300 && r <= 0x1FAFF, r >= 0x20000 && r <= 0x3FFFD:
		return 2
	}
	return 1
}

// wrap splits s into lines of at most w display columns, indenting
// continuation lines.
func wrap(s string, w int) []string {
	if width(s) <= w {
		return []string{s}
	}
	var lines []string
	var cur strings.Builder
	cw := 0
	for _, r := range s {
		rw := runeWidth(r)
		if cw+rw > w {
			lines = append(lines, cur.String())
			cur.Reset()
			cur.WriteString("      ")
			cw = 6
		}
		cur.WriteRune(r)
		cw += rw
	}
	if cur.Len() > 0 {
		lines = append(lines, cur.String())
	}
	return lines
}
