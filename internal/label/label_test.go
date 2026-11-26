package label

import (
	"fmt"
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
)

func TestRenderAlignmentAndFacts(t *testing.T) {
	m := &manifest.Manifest{
		App:     manifest.App{Name: "demo", DisplayName: "發票小幫手", Version: "1.4.0", Kind: "local-web", AuthorNote: "協助整理發票"},
		Runtime: manifest.Runtime{Isolation: "process", Spawn: "none"},
		Files:   []manifest.FileGrant{{Path: "${USER_PICK:invoices}", Mode: "ro", Purpose: "讀取你選定的發票資料夾，這段用途文字刻意寫得很長很長很長很長很長很長以測試換行"}},
		Network: manifest.Network{Egress: []manifest.Egress{{Host: "api.anthropic.com", Port: 443, Purpose: "分析發票內容"}}},
		Secrets: []manifest.Secret{{Name: "ANTHROPIC_API_KEY", Visibility: "gate-only", Bind: manifest.SecretBind{Host: "api.anthropic.com"}}},
		Evidence: []manifest.Evidence{
			{Grant: "files[0]", ObservedIn: ".warp/evidence/trace-0001.json", TriggeredBy: "python3 app.py scan"},
			{Grant: "secrets[0]", ObservedIn: ".warp/evidence/trace-0002.json", TriggeredBy: "python3 app.py scan"},
			{Grant: "network.egress[0]", ObservedIn: ".warp/evidence/trace-0003.json", TriggeredBy: "python3 -c 'import urllib.request; urllib.request.urlopen(\"https://api.anthropic.com/v1/messages\")'"},
		},
	}
	l := &manifest.Loaded{Manifest: m, SHA256: "x"}
	lb := Build(l, &manifest.Result{Risk: manifest.Risk{Score: 18, Level: "低"}}, t.TempDir())
	if len(lb.Evidence) != 2 || len(lb.Evidence[0].Grants) != 2 || len(lb.Evidence[0].Traces) != 2 {
		t.Errorf("evidence sources must be grouped by command: %+v", lb.Evidence)
	}
	out := Render(lb)
	w := -1
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "│") && !strings.HasPrefix(line, "┌") && !strings.HasPrefix(line, "├") && !strings.HasPrefix(line, "└") {
			continue
		}
		if w == -1 {
			w = width(line)
		} else if width(line) != w {
			t.Errorf("misaligned line (%d vs %d): %q", width(line), w, line)
		}
	}
	for _, want := range []string{"api.anthropic.com:443", "你選定的一個資料夾（invoices）", "看到金鑰的真值", "（無例外）", "未經驗證的自述", "L1 已包覆",
		"授權依據", "$ python3 app.py scan", "→ 讀取你選定的一個資料夾（invoices）、使用 ANTHROPIC_API_KEY", "$ python3 -c 'import urllib.request;"} {
		if !strings.Contains(out, want) {
			t.Errorf("label missing %q:\n%s", want, out)
		}
	}
	for _, c := range lb.Cannot {
		if strings.Contains(c, "執行其他程式") {
			t.Errorf("label must not claim spawn is blocked (not enforced): %q", c)
		}
	}
}

// TestResourceCoverageIsHonest: the label states how each resource limit
// actually held in the last current run, warns when a memory or process
// limit did not bound the whole shell, and claims nothing without a run.
func TestResourceCoverageIsHonest(t *testing.T) {
	m := &manifest.Manifest{App: manifest.App{Name: "demo", Version: "1"}, Runtime: manifest.Runtime{Isolation: "process", Spawn: "none"}}
	l := &manifest.Loaded{Manifest: m, SHA256: "x"}
	dir := t.TempDir()
	note := func(lb *Label) string {
		for _, c := range lb.Coverage {
			if c.Channel == "process" {
				return c.Note
			}
		}
		return ""
	}
	lb := Build(l, &manifest.Result{}, dir)
	if n := note(lb); !strings.Contains(n, "實際效果未知") {
		t.Errorf("without a run the label must not claim any limit: %q", n)
	}
	digest, _ := manifest.ComputeDigest(dir)
	for _, c := range []struct {
		scope string
		warn  bool
	}{{report.ScopeProcess, true}, {report.ScopeNone, true}, {report.ScopeShell, false}} {
		p := &report.Probe{ManifestSHA256: "x", AppDigest: digest, Identity: "uid=1000", Items: []report.ProbeItem{{ID: "a", Status: report.Blocked}},
			Resources: []report.ResourceLimit{{Resource: "memory", Limit: "512Mi", Scope: c.scope, Mechanism: "M"},
				{Resource: "pids", Limit: "64", Scope: report.ScopeShell, Mechanism: "P"}}}
		if err := report.WriteProbe(dir, p); err != nil {
			t.Fatal(err)
		}
		lb := Build(l, &manifest.Result{}, dir)
		out := Render(lb)
		if got := strings.Contains(out, "⚠ 記憶體上限在此機器上"); got != c.warn {
			t.Errorf("scope %s: warning shown=%v, want %v\n%s", c.scope, got, c.warn, out)
		}
		if strings.Contains(out, "⚠ 程序數上限") {
			t.Errorf("pids held for the whole shell; no warning expected")
		}
		if !strings.Contains(note(lb), scopeNames[c.scope]) || !strings.Contains(out, "執行身分　uid=1000") {
			t.Errorf("scope %s: coverage note %q", c.scope, note(lb))
		}
	}
}

// TestEnforceLineStatesFacts: the label states which command the last
// enforce run executed, its exit code and time, and never calls it a pass;
// an L2 label says which runs it is based on.
func TestEnforceLineStatesFacts(t *testing.T) {
	m := &manifest.Manifest{App: manifest.App{Name: "demo", Version: "1"}, Runtime: manifest.Runtime{Isolation: "process", Spawn: "none"}}
	l := &manifest.Loaded{Manifest: m, SHA256: "x"}
	dir := t.TempDir()
	digest, _ := manifest.ComputeDigest(dir)
	report.WriteProbe(dir, &report.Probe{ManifestSHA256: "x", AppDigest: digest, Items: []report.ProbeItem{{ID: "a", Status: report.Blocked}}})
	for _, code := range []int{0, 130} {
		report.WriteEnforce(dir, &report.Enforce{ManifestSHA256: "x", AppDigest: digest, Command: []string{"python3", "-m", "pytest", "-k", "a or b"},
			ExitCode: code, Denied: 2, Time: "2026-11-26T01:02:03Z"})
		lb := Build(l, &manifest.Result{}, dir)
		out := Render(lb)
		for _, want := range []string{"最後一次強制執行", "$ python3 -m pytest -k 'a or b'", fmt.Sprintf("結束碼 %d", code), "2026-11-26T01:02:03Z", "不是功能驗證結果"} {
			if !strings.Contains(out, want) {
				t.Errorf("exit %d: label missing %q:\n%s", code, want, out)
			}
		}
		if strings.Contains(out, "通過") || strings.Contains(out, "失敗") {
			t.Errorf("exit %d: the label must state facts, not pass/fail:\n%s", code, out)
		}
		if lb.Verification.EnforceTime != "2026-11-26T01:02:03Z" || lb.Verification.EnforceCommand != "python3 -m pytest -k 'a or b'" {
			t.Errorf("label.json: %+v", lb.Verification)
		}
		wantL2 := code == 0
		if (lb.TrustLevel == "L2") != wantL2 || strings.Contains(out, "依據：") != wantL2 {
			t.Errorf("exit %d: trust %s\n%s", code, lb.TrustLevel, out)
		}
	}
}
