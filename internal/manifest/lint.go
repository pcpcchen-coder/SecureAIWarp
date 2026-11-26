package manifest

import (
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/evidence"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/netpolicy"
)

// Finding levels.
const (
	LevelError   = "error"
	LevelWarning = "warning"
)

// Finding is one lint result.
type Finding struct {
	Level   string `json:"level"`
	Rule    string `json:"rule"`
	Path    string `json:"path,omitempty"`
	Message string `json:"message"`
}

// Attention is a soft-rule deviation shown on the label.
type Attention struct {
	Rule     string `json:"rule"`
	Grant    string `json:"grant"`
	Text     string `json:"text"`
	Excepted bool   `json:"excepted"`
}

// Result is the full lint output.
type Result struct {
	Findings  []Finding   `json:"findings"`
	Attention []Attention `json:"attention"`
	Risk      Risk        `json:"risk"`
}

// Errors counts error findings.
func (r *Result) Errors() int {
	n := 0
	for _, f := range r.Findings {
		if f.Level == LevelError {
			n++
		}
	}
	return n
}

// Warnings counts warning findings.
func (r *Result) Warnings() int { return len(r.Findings) - r.Errors() }

// Options configure lint.
type Options struct {
	AppRoot  string // absolute app root; evidence paths are relative to it
	TraceKey []byte // key to verify traces
	// SkipDigest skips the content digest check (only for unit tests).
	SkipDigest bool
}

// Soft rules (can become exceptions).
const (
	SoftSecretAppVisible = "secret-app-visible"
	SoftEgressSubdomain  = "egress-subdomain-wildcard"
	SoftPickWritable     = "pick-writable"
	SoftSpawnAny         = "spawn-any"
	SoftEgressLAN        = "egress-lan"
	SoftEgressManyHosts  = "egress-many-hosts"
)

// SoftRules lists all soft rule identifiers.
var SoftRules = []string{SoftSecretAppVisible, SoftEgressSubdomain, SoftPickWritable, SoftSpawnAny, SoftEgressLAN, SoftEgressManyHosts}

// MaxEgressHosts is the soft threshold for the number of egress entries.
const MaxEgressHosts = 10

// ReservedShellPort is the port of the egress gate inside the shell.
const ReservedShellPort = 3128

type linter struct {
	m   *Manifest
	opt Options
	res *Result
}

func (l *linter) add(level, rule, path, format string, args ...any) {
	l.res.Findings = append(l.res.Findings, Finding{Level: level, Rule: rule, Path: path, Message: fmt.Sprintf(format, args...)})
}
func (l *linter) errf(rule, path, format string, args ...any) {
	l.add(LevelError, rule, path, format, args...)
}
func (l *linter) warnf(rule, path, format string, args ...any) {
	l.add(LevelWarning, rule, path, format, args...)
}

var (
	appNameRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	digestRe    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	envNameRe   = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)
	headerRe    = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)
	placeholder = regexp.MustCompile(`(?i)待填寫|todo|tbd|fixme`)
	toolWordRe  = regexp.MustCompile(`[A-Za-z][a-z0-9]*|[0-9]+`)
)

// Header names that must never be targets of secret injection.
var forbiddenHeaders = map[string]bool{
	"host": true, "content-length": true, "transfer-encoding": true, "connection": true,
	"proxy-authorization": true, "proxy-connection": true, "te": true, "trailer": true,
	"upgrade": true, "keep-alive": true, "cookie": false,
}

// HighRiskVerbs is the core's built-in floor for tool risk.
var HighRiskVerbs = []string{"send", "email", "mail", "sms", "pay", "payment", "charge", "transfer",
	"refund", "purchase", "order", "delete", "remove", "rm", "erase", "drop", "destroy", "exec",
	"execute", "shell", "command", "cmd", "run", "spawn", "kill", "deploy", "publish", "post",
	"write", "upload", "wire", "withdraw", "sudo", "install"}

// Lint checks a manifest. It is deterministic and never consults a model.
func Lint(m *Manifest, opt Options) *Result {
	l := &linter{m: m, opt: opt, res: &Result{}}
	l.checkTop()
	l.checkFiles()
	l.checkEgress()
	l.checkIngress()
	l.checkSecrets()
	l.checkAI()
	l.checkData()
	l.checkExceptions()
	l.checkEvidence()
	l.checkDigest()
	l.res.Risk = ComputeRisk(m, l.res)
	sort.SliceStable(l.res.Findings, func(i, j int) bool {
		return l.res.Findings[i].Level == LevelError && l.res.Findings[j].Level != LevelError
	})
	return l.res
}

func (l *linter) purpose(path, p string) {
	if strings.TrimSpace(p) == "" {
		l.errf("grant-purpose", path, "每條授權都必須有 purpose（一句人話用途）")
	} else if placeholder.MatchString(p) {
		l.errf("grant-purpose", path, "purpose 仍是待填寫的佔位文字：%q", p)
	}
}

func (l *linter) checkTop() {
	m := l.m
	if m.Warp != FormatVersion {
		l.errf("format", "warp", "warp 必須是 %q（目前為 %q）", FormatVersion, m.Warp)
	}
	if !appNameRe.MatchString(m.App.Name) {
		l.errf("format", "app.name", "app.name 必須是小寫英數字、- 或 _（1–64 字元）")
	}
	if strings.TrimSpace(m.App.Version) == "" {
		l.errf("format", "app.version", "app.version 必填")
	}
	if !oneOf(m.App.Kind, Kinds) {
		l.errf("format", "app.kind", "app.kind 必須是 %s 之一", strings.Join(Kinds, " | "))
	}
	if len(m.App.Entry) == 0 || m.App.Entry[0] == "" {
		l.errf("format", "app.entry", "app.entry 必須是非空的指令陣列")
	}
	// Placeholders in app.entry are expanded by the core at run time; they
	// must name paths that enforce mode will actually mount.
	declared := map[string]bool{}
	for _, f := range m.Files {
		declared[f.Path] = true
	}
	for _, v := range ArgVars(m.App.Entry) {
		_, _, ok := PathVar(v)
		switch {
		case !ok:
			l.errf("entry-var", "app.entry", "%s 不是有效的佔位字（USER_PICK 的%s）", v, PickNameRule)
		case !declared[v]:
			l.errf("entry-var", "app.entry", "app.entry 使用了 %s，但 files 中沒有宣告它；強制模式不會掛載未宣告的路徑", v)
		}
	}
	if !digestRe.MatchString(m.App.Digest) {
		l.errf("app-digest", "app.digest", "app.digest 必須是 sha256:<64 位十六進位>")
	}
	r := m.Runtime
	if !oneOf(r.Isolation, Isolations) {
		l.errf("format", "runtime.isolation", "runtime.isolation 必須是 %s 之一", strings.Join(Isolations, " | "))
	} else if r.Isolation != "process" {
		l.warnf("unsupported", "runtime.isolation", "此核心目前只實作 process 隔離；要求 %s 時強制模式會拒絕執行（不會降級）", r.Isolation)
	}
	if !oneOf(r.Spawn, SpawnModes) {
		l.errf("format", "runtime.spawn", "runtime.spawn 必須是 %s 之一", strings.Join(SpawnModes, " | "))
	}
	if r.Spawn == "any" {
		l.soft(SoftSpawnAny, "runtime.spawn", "可執行任意指令")
	}
	if r.Background {
		l.warnf("unsupported", "runtime.background", "background: true 尚未支援：主程式結束時殼內所有程序都會被終止")
	}
	if r.Resources.Memory != "" {
		if _, err := ParseSize(r.Resources.Memory); err != nil {
			l.errf("format", "runtime.resources.memory", "記憶體上限格式錯誤：%v", err)
		}
	}
	if r.Resources.Disk != "" {
		if _, err := ParseSize(r.Resources.Disk); err != nil {
			l.errf("format", "runtime.resources.disk", "磁碟上限格式錯誤：%v", err)
		}
	}
	if r.Resources.Pids < 0 || r.Resources.CPU < 0 {
		l.errf("format", "runtime.resources", "資源上限不可為負數")
	}
	if r.Resources.Memory == "" || r.Resources.Pids == 0 || r.Resources.Disk == "" {
		l.warnf("resources-default", "runtime.resources", "部分資源上限未設定，將使用核心預設值（記憶體 %s、程序數 %d、磁碟 %s）", DefaultMemory, DefaultPids, DefaultDisk)
	}
	for i, d := range m.DeniedByDesign {
		if strings.TrimSpace(d.Behavior) == "" || strings.TrimSpace(d.Reason) == "" {
			l.errf("format", fmt.Sprintf("denied_by_design[%d]", i), "denied_by_design 需要 behavior 與 reason")
		}
	}
}

// Default resource limits.
const (
	DefaultMemory = "1Gi"
	DefaultPids   = 256
	DefaultDisk   = "1Gi"
)

func (l *linter) soft(rule, grant, text string) {
	excepted := false
	for _, e := range l.m.Exceptions {
		if e.Rule == rule && e.Grant == grant {
			excepted = true
		}
	}
	l.res.Attention = append(l.res.Attention, Attention{Rule: rule, Grant: grant, Text: text, Excepted: excepted})
	if !excepted {
		l.warnf(rule, grant, "軟性規則：%s——需要人工核可並列入 exceptions", text)
	}
}

func (l *linter) checkFiles() {
	seen := map[string]bool{}
	for i, f := range l.m.Files {
		p := GrantRef(GrantFile, i)
		kind, pick, ok := PathVar(f.Path)
		if !ok {
			if filepath.IsAbs(f.Path) || strings.HasPrefix(f.Path, "~") {
				l.errf("files-absolute", p, "第一期只支援變數路徑（${APP_DATA}、${APP_CACHE}、${USER_PICK:名稱}）；絕對路徑 %q 不會被掛載", f.Path)
			} else {
				l.errf("format", p, "無效的路徑 %q", f.Path)
			}
		}
		if seen[f.Path] {
			l.errf("format", p, "重複的檔案授權 %q", f.Path)
		}
		seen[f.Path] = true
		if !oneOf(f.Mode, FileModes) {
			l.errf("format", p, "mode 必須是 ro 或 rw")
		}
		if kind == "USER_PICK" && f.Mode == "rw" {
			l.soft(SoftPickWritable, p, fmt.Sprintf("可修改你選定資料夾（%s）中的檔案", pick))
		}
		l.purpose(p, f.Purpose)
	}
}

func (l *linter) checkEgress() {
	seen := map[string]bool{}
	for i, e := range l.m.Network.Egress {
		p := GrantRef(GrantEgress, i)
		host := e.Host
		key := fmt.Sprintf("%s:%d", host, e.Port)
		if seen[key] {
			l.errf("format", p, "重複的對外連線 %s", key)
		}
		seen[key] = true
		if e.Port < 1 || e.Port > 65535 {
			l.errf("format", p, "port 必須介於 1 與 65535")
		}
		if e.Via != "" && !oneOf(e.Via, EgressVias) {
			l.errf("format", p, "via 只能是 ai-gate")
		}
		if e.Via == "ai-gate" {
			l.warnf("unsupported", p, "AI 閘門尚未實作；含 via: ai-gate 的宣告在強制模式下會被拒絕執行")
		}
		if e.Limits != nil && e.Limits.UploadPerDay != "" {
			if _, err := ParseSize(e.Limits.UploadPerDay); err != nil {
				l.errf("format", p, "upload_per_day 格式錯誤：%v", err)
			}
		}
		l.purpose(p, e.Purpose)
		l.checkEgressHost(p, e)
	}
	if n := len(l.m.Network.Egress); n > MaxEgressHosts {
		l.soft(SoftEgressManyHosts, "network.egress", fmt.Sprintf("連線對象較多（%d 個）", n))
	}
}

func (l *linter) checkEgressHost(p string, e Egress) {
	h := e.Host
	if h == "" {
		l.errf("format", p, "host 必填")
		return
	}
	if strings.Contains(h, "/") {
		l.errf("egress-global-wildcard", p, "不接受網段（CIDR）%q", h)
		return
	}
	if strings.Contains(h, "*") {
		if !strings.HasPrefix(h, "*.") || strings.Contains(h[2:], "*") {
			l.errf("egress-global-wildcard", p, "對外連線不得使用全域萬用字元：%q", h)
			return
		}
		base := h[2:]
		if !netpolicy.ValidHostname(base) || strings.Count(base, ".") < 1 {
			l.errf("egress-global-wildcard", p, "萬用字元的範圍過大（等於全域）：%q", h)
			return
		}
		if netpolicy.IsLoopbackName(base) {
			l.errf("egress-loopback", p, "不得連往主機本機：%q", h)
			return
		}
		l.soft(SoftEgressSubdomain, p, fmt.Sprintf("可連到 %s 的任何主機", h))
		if e.LAN {
			l.soft(SoftEgressLAN, p, fmt.Sprintf("可連到你的內部網路（%s）", h))
		}
		return
	}
	if netpolicy.IsMetadataName(h) {
		l.errf("egress-metadata", p, "不得連往雲端中繼資料位址：%q", h)
		return
	}
	if netpolicy.IsLoopbackName(h) {
		l.errf("egress-loopback", p, "不得連往主機本機：%q", h)
		return
	}
	if ip, ok := netpolicy.ParseIPLiteral(h); ok {
		switch netpolicy.Classify(ip) {
		case netpolicy.Metadata, netpolicy.LinkLocal:
			l.errf("egress-metadata", p, "不得連往雲端中繼資料或連結本地位址：%q", h)
		case netpolicy.Loopback, netpolicy.Unspecified:
			l.errf("egress-loopback", p, "不得連往主機本機：%q", h)
		case netpolicy.Multicast, netpolicy.Reserved:
			l.errf("egress-reserved", p, "不得連往保留或群播位址：%q", h)
		case netpolicy.Private:
			if !e.LAN {
				l.errf("egress-lan", p, "%q 是區域網路位址，必須標示 lan: true 並經人工核可例外", h)
			}
		case netpolicy.Public:
			if e.LAN {
				l.errf("format", p, "%q 不是區域網路位址，不應標示 lan: true", h)
			}
		}
		if e.LAN {
			l.soft(SoftEgressLAN, p, fmt.Sprintf("可連到你的內部網路（%s）", h))
		}
		return
	}
	if !netpolicy.ValidHostname(h) {
		l.errf("format", p, "無效的主機名稱 %q（須為小寫、完整網域名稱）", h)
		return
	}
	if e.LAN {
		l.soft(SoftEgressLAN, p, fmt.Sprintf("可連到你的內部網路（%s）", h))
	}
}

func (l *linter) checkIngress() {
	seen := map[int]bool{}
	for i, in := range l.m.Network.Ingress {
		p := GrantRef(GrantIngress, i)
		if in.Listen < 1 || in.Listen > 65535 {
			l.errf("format", p, "listen 必須介於 1 與 65535")
		}
		if in.Listen == ReservedShellPort {
			l.errf("format", p, "連接埠 %d 保留給殼內的對外閘門", ReservedShellPort)
		}
		if seen[in.Listen] {
			l.errf("format", p, "重複的對內連線 %d", in.Listen)
		}
		seen[in.Listen] = true
		if !oneOf(in.Expose, Exposures) {
			l.errf("format", p, "expose 必須是 loopback | lan | public")
		}
		if !oneOf(in.Auth, AuthModes) {
			l.errf("format", p, "auth 必須是 %s 之一", strings.Join(AuthModes, " | "))
		}
		if in.Expose != "loopback" && in.Expose != "" && in.Auth == "none" {
			l.errf("ingress-auth", p, "開放範圍超出本機時必須設定驗證方式")
		}
		if in.Expose == "lan" || in.Expose == "public" {
			l.errf("unsupported", p, "第一期只支援 expose: loopback")
		}
		if in.Expose == "loopback" && in.Auth != "local-token" {
			l.errf("unsupported", p, "expose: loopback 目前只支援 auth: local-token（核心一律加上一次性權杖）")
		}
		l.purpose(p, in.Purpose)
	}
}

func (l *linter) checkSecrets() {
	seen := map[string]bool{}
	for i, s := range l.m.Secrets {
		p := GrantRef(GrantSecret, i)
		if !envNameRe.MatchString(s.Name) {
			l.errf("format", p, "機密名稱必須是大寫環境變數名稱（例如 API_KEY）")
		}
		if seen[s.Name] {
			l.errf("format", p, "重複的機密 %s", s.Name)
		}
		seen[s.Name] = true
		if !oneOf(s.ProvidedBy, Providers) {
			l.errf("format", p, "provided_by 必須是 recipient 或 author")
		}
		if !oneOf(s.Visibility, Visibility) {
			l.errf("format", p, "visibility 必須是 gate-only 或 app-visible")
		}
		if s.Visibility == "app-visible" {
			l.soft(SoftSecretAppVisible, p, fmt.Sprintf("此工具可直接看到你的金鑰（%s）", s.Name))
		}
		bh := s.Bind.Host
		if strings.Contains(bh, "*") {
			l.errf("secret-bind", p, "機密只能綁定單一具體主機")
		} else {
			found := false
			for _, e := range l.m.Network.Egress {
				if e.Host == bh {
					found = true
				}
			}
			if !found {
				l.errf("secret-bind", p, "bind.host %q 必須同時列在 network.egress", bh)
			}
		}
		hd := strings.ToLower(s.Bind.Inject.Header)
		if !headerRe.MatchString(hd) || forbiddenHeaders[hd] {
			l.errf("secret-bind", p, "bind.inject.header %q 不是可注入的標頭", s.Bind.Inject.Header)
		}
		l.purpose(p, s.Purpose)
	}
}

func toolIsHighRiskName(name string) bool {
	for _, w := range toolWordRe.FindAllString(name, -1) {
		w = strings.ToLower(w)
		for _, v := range HighRiskVerbs {
			if w == v {
				return true
			}
		}
	}
	return false
}

func (l *linter) checkAI() {
	a := l.m.AI
	if a == nil {
		return
	}
	if len(a.Providers) > 0 || len(a.Tools) > 0 {
		if a.Budget == nil || a.Budget.DailyUSD <= 0 {
			l.errf("ai-budget", "ai.budget", "有 AI 呼叫就必須設定花費上限（ai.budget.daily_usd > 0）")
		}
	}
	for i, p := range a.Providers {
		found := false
		for _, e := range l.m.Network.Egress {
			if e.Host == p.Host {
				found = true
			}
		}
		if !found {
			l.errf("format", fmt.Sprintf("ai.providers[%d]", i), "AI 供應商 %q 必須同時列在 network.egress", p.Host)
		}
	}
	names := map[string]bool{}
	for i, t := range a.Tools {
		p := fmt.Sprintf("ai.tools[%d]", i)
		if t.Name == "" {
			l.errf("format", p, "工具名稱必填")
		}
		if names[t.Name] {
			l.errf("format", p, "重複的工具 %q", t.Name)
		}
		names[t.Name] = true
		if !oneOf(t.Risk, ToolRisks) {
			l.errf("format", p, "risk 必須是 low | medium | high")
		}
		if t.Gate != "" && !oneOf(t.Gate, ToolGates) {
			l.errf("format", p, "gate 只能是 consent")
		}
		if t.Risk == "high" && t.Gate == "" {
			l.errf("tool-gate", p, "高風險工具 %q 必須有 gate", t.Name)
		}
		if t.Risk != "high" && toolIsHighRiskName(t.Name) {
			l.errf("tool-risk-floor", p, "工具 %q 的名稱含有高風險動作，風險不得低於 high（核心內建下限）", t.Name)
		}
	}
}

func (l *linter) checkData() {
	d := l.m.Data
	if d == nil {
		return
	}
	classes := map[string]bool{}
	for i, c := range d.Classes {
		p := fmt.Sprintf("data.classes[%d]", i)
		if c.ID == "" {
			l.errf("format", p, "資料類別 id 必填")
		}
		classes[c.ID] = true
		if k, _, ok := ParseGrant(c.Source); !ok || k != GrantFile || !l.m.GrantExists(c.Source) {
			l.errf("format", p, "source %q 必須指向存在的 files[i]", c.Source)
		}
	}
	for i, f := range d.Flows {
		p := fmt.Sprintf("data.flows[%d]", i)
		if !classes[f.Class] {
			l.errf("format", p, "未定義的資料類別 %q", f.Class)
		}
		for _, to := range f.To {
			if k, _, ok := ParseGrant(to); !ok || k != GrantEgress || !l.m.GrantExists(to) {
				l.errf("format", p, "去向 %q 必須指向存在的 network.egress[i]", to)
			}
		}
		l.purpose(p, f.Purpose)
	}
	if d.Retention != nil {
		if _, _, ok := PathVar(d.Retention.Location); !ok {
			l.errf("format", "data.retention.location", "留存位置必須是變數路徑")
		}
		if d.Retention.Days < 0 {
			l.errf("format", "data.retention.days", "留存天數不可為負數")
		}
	}
}

func (l *linter) checkExceptions() {
	for i, e := range l.m.Exceptions {
		p := fmt.Sprintf("exceptions[%d]", i)
		if !oneOf(e.Rule, SoftRules) {
			l.errf("exception", p, "例外只能針對軟性規則（%s）；硬性規則不可覆寫", strings.Join(SoftRules, ", "))
		}
		if e.Grant != "network.egress" && e.Grant != "runtime.spawn" && !l.m.GrantExists(e.Grant) {
			l.errf("exception", p, "例外指向不存在的授權 %q", e.Grant)
		}
		if strings.TrimSpace(e.Reason) == "" || strings.TrimSpace(e.ApprovedBy) == "" || strings.TrimSpace(e.ApprovedAt) == "" {
			l.errf("exception", p, "例外必須有 reason、approved_by、approved_at")
		}
	}
	if len(l.m.Exceptions) > 0 {
		l.warnf("exception-unsigned", "exceptions", "例外的簽核紀錄尚未經同意代理簽章驗證（第 2 期）；請自行確認 approved_by 為真人")
	}
}

func (l *linter) checkEvidence() {
	byGrant := map[string][]Evidence{}
	for i, ev := range l.m.Evidence {
		p := fmt.Sprintf("evidence[%d]", i)
		if !l.m.GrantExists(ev.Grant) {
			l.errf("grant-evidence", p, "evidence 指向不存在的授權 %q", ev.Grant)
			continue
		}
		if strings.TrimSpace(ev.TriggeredBy) == "" {
			l.errf("grant-evidence", p, "evidence 必須有 triggered_by")
		}
		byGrant[ev.Grant] = append(byGrant[ev.Grant], ev)
	}
	cache := map[string]*evidence.Trace{}
	for _, g := range l.m.AllGrants() {
		evs := byGrant[g]
		if len(evs) == 0 {
			l.errf("grant-evidence", g, "此授權沒有側錄證據；沒有證據的權限不給")
			continue
		}
		for _, ev := range evs {
			t, err := l.loadTrace(ev.ObservedIn, cache)
			if err != nil {
				l.errf("grant-evidence", g, "證據 %s 無效：%v", ev.ObservedIn, err)
				continue
			}
			// The trace, not the agent, says which command produced the
			// behaviour: triggered_by must be a verbatim copy of it.
			if cmd := evidence.CommandString(t.Command); ev.TriggeredBy != cmd {
				l.errf("evidence-command", g, "證據 %s 的 triggered_by %q 與側錄檔中核心實際執行的指令不符（實際為 %q）；triggered_by 只能照抄核心記錄的指令", ev.ObservedIn, ev.TriggeredBy, cmd)
			}
			// Evidence only counts for the app content it was recorded on.
			if t.AppDigest != l.m.App.Digest {
				l.errf("evidence-stale", g, "證據 %s 側錄時的應用內容雜湊（%s）與宣告的 app.digest 不同；應用內容變動後必須重新側錄", ev.ObservedIn, orNone(t.AppDigest))
			}
			if why := EvidenceMatches(l.m, g, t); why != "" {
				l.errf("grant-evidence", g, "證據 %s 中沒有對應行為：%s", ev.ObservedIn, why)
			}
		}
	}
}

func (l *linter) loadTrace(rel string, cache map[string]*evidence.Trace) (*evidence.Trace, error) {
	if t, ok := cache[rel]; ok {
		if t == nil {
			return nil, fmt.Errorf("無法載入")
		}
		return t, nil
	}
	if l.opt.AppRoot == "" || l.opt.TraceKey == nil {
		return nil, fmt.Errorf("未提供應用根目錄或簽章金鑰，無法驗證")
	}
	if filepath.IsAbs(rel) || strings.Contains(rel, "..") {
		return nil, fmt.Errorf("observed_in 必須是應用根目錄下 .warp/evidence/ 的相對路徑")
	}
	clean := filepath.Clean(rel)
	if !strings.HasPrefix(filepath.ToSlash(clean), ".warp/evidence/") {
		return nil, fmt.Errorf("observed_in 必須位於 .warp/evidence/")
	}
	t, err := evidence.Load(filepath.Join(l.opt.AppRoot, clean), l.opt.TraceKey)
	cache[rel] = t
	return t, err
}

func orNone(s string) string {
	if s == "" {
		return "（無）"
	}
	return s
}

// EvidenceMatches reports why trace t does not show the behaviour of grant
// g of manifest m ("" if it does). Lint and evidence replay share it.
func EvidenceMatches(m *Manifest, g string, t *evidence.Trace) string {
	kind, idx, _ := ParseGrant(g)
	switch kind {
	case GrantFile:
		f := m.Files[idx]
		needWrite := f.Mode == "rw"
		if !t.HasFile(f.Path, needWrite) {
			if needWrite && t.HasFile(f.Path, false) {
				return fmt.Sprintf("只觀察到讀取 %s，沒有寫入；請改為 ro", f.Path)
			}
			return fmt.Sprintf("沒有觀察到對 %s 的存取", f.Path)
		}
	case GrantEgress:
		e := m.Network.Egress[idx]
		if !t.HasEgress(e.Host, e.Port) {
			return fmt.Sprintf("沒有觀察到連往 %s:%d", e.Host, e.Port)
		}
	case GrantIngress:
		in := m.Network.Ingress[idx]
		if !t.HasIngress(in.Listen) {
			return fmt.Sprintf("沒有觀察到監聽 %d", in.Listen)
		}
	case GrantSecret:
		s := m.Secrets[idx]
		if !t.HasSecret(s.Name, s.Bind.Host, s.Bind.Inject.Header) {
			return fmt.Sprintf("沒有觀察到 %s 經由標頭 %s 送往 %s", s.Name, s.Bind.Inject.Header, s.Bind.Host)
		}
	}
	return ""
}

func (l *linter) checkDigest() {
	if l.opt.SkipDigest || l.opt.AppRoot == "" || !digestRe.MatchString(l.m.App.Digest) {
		return
	}
	d, err := ComputeDigest(l.opt.AppRoot)
	if err != nil {
		l.errf("app-digest", "app.digest", "無法計算內容雜湊：%v", err)
		return
	}
	if d != l.m.App.Digest {
		l.errf("app-digest", "app.digest", "內容雜湊與實際檔案不符（實際為 %s）；應用內容已變動，必須重新側錄與檢查", d)
	}
}
