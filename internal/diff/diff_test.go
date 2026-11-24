package diff

import (
	"strings"
	"testing"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

func TestCompare(t *testing.T) {
	a := &manifest.Manifest{Files: []manifest.FileGrant{{Path: "${USER_PICK:exports}", Mode: "ro", Purpose: "匯出"}},
		AI: &manifest.AI{Budget: &manifest.AIBudget{DailyUSD: 5}}}
	b := &manifest.Manifest{Network: manifest.Network{Egress: []manifest.Egress{{Host: "api.stripe.com", Port: 443, Purpose: "建立付款連結"}}},
		AI: &manifest.AI{Budget: &manifest.AIBudget{DailyUSD: 20}, Tools: []manifest.AITool{{Name: "create_payment", Risk: "high", Gate: "consent"}}}}
	out := strings.Join(Compare(a, b), "\n")
	for _, want := range []string{"＋ 新增對外連線：api.stripe.com:443（用途：建立付款連結）", "＋ 新增AI 工具：create_payment（風險 high，每次需你同意）",
		"－ 移除檔案存取：${USER_PICK:exports}", "～ 每日 AI 花費上限：5 美元 → 20 美元", "風險等級："} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in:\n%s", want, out)
		}
	}
	if len(Compare(a, a)) != 0 {
		t.Error("identical manifests must produce no output")
	}
}
