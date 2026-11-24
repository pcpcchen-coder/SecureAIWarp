package label

import (
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

func TestRenderAlignmentAndFacts(t *testing.T) {
	m := &manifest.Manifest{
		App:     manifest.App{Name: "demo", DisplayName: "發票小幫手", Version: "1.4.0", Kind: "local-web", AuthorNote: "協助整理發票"},
		Runtime: manifest.Runtime{Isolation: "process", Spawn: "none"},
		Files:   []manifest.FileGrant{{Path: "${USER_PICK:invoices}", Mode: "ro", Purpose: "讀取你選定的發票資料夾，這段用途文字刻意寫得很長很長很長很長很長很長以測試換行"}},
		Network: manifest.Network{Egress: []manifest.Egress{{Host: "api.anthropic.com", Port: 443, Purpose: "分析發票內容"}}},
		Secrets: []manifest.Secret{{Name: "ANTHROPIC_API_KEY", Visibility: "gate-only", Bind: manifest.SecretBind{Host: "api.anthropic.com"}}},
	}
	l := &manifest.Loaded{Manifest: m, SHA256: "x"}
	lb := Build(l, &manifest.Result{Risk: manifest.Risk{Score: 18, Level: "低"}}, t.TempDir())
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
	for _, want := range []string{"api.anthropic.com:443", "你選定的一個資料夾（invoices）", "看到金鑰的真值", "（無例外）", "未經驗證的自述", "L1 已包覆"} {
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
