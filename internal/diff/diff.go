// Package diff compares two manifests and describes permission changes in
// plain language. Unchanged permissions are not shown.
package diff

import (
	"fmt"
	"sort"
	"strings"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/manifest"
)

func fileDesc(f manifest.FileGrant) string {
	m := "唯讀"
	if f.Mode == "rw" {
		m = "讀寫"
	}
	return fmt.Sprintf("%s（%s）", f.Path, m)
}

type item struct {
	key, desc, purpose string
}

func diffSets(kind string, a, b []item) []string {
	am, bm := map[string]item{}, map[string]item{}
	for _, x := range a {
		am[x.key] = x
	}
	for _, x := range b {
		bm[x.key] = x
	}
	var out []string
	for _, x := range b {
		if old, ok := am[x.key]; !ok {
			out = append(out, fmt.Sprintf("＋ 新增%s：%s（用途：%s）", kind, x.desc, x.purpose))
		} else if old.desc != x.desc {
			out = append(out, fmt.Sprintf("～ 變更%s：%s → %s", kind, old.desc, x.desc))
		}
	}
	for _, x := range a {
		if _, ok := bm[x.key]; !ok {
			out = append(out, fmt.Sprintf("－ 移除%s：%s", kind, x.desc))
		}
	}
	return out
}

func files(m *manifest.Manifest) (out []item) {
	for _, f := range m.Files {
		out = append(out, item{f.Path, fileDesc(f), f.Purpose})
	}
	return
}

func egress(m *manifest.Manifest) (out []item) {
	for _, e := range m.Network.Egress {
		d := fmt.Sprintf("%s:%d", e.Host, e.Port)
		if e.LAN {
			d += "（區域網路）"
		}
		if e.Limits != nil && e.Limits.UploadPerDay != "" {
			d += "，每日上傳上限 " + e.Limits.UploadPerDay
		}
		out = append(out, item{fmt.Sprintf("%s:%d", e.Host, e.Port), d, e.Purpose})
	}
	return
}

func ingress(m *manifest.Manifest) (out []item) {
	for _, in := range m.Network.Ingress {
		out = append(out, item{fmt.Sprint(in.Listen), fmt.Sprintf("%d 埠（%s，%s）", in.Listen, in.Expose, in.Auth), in.Purpose})
	}
	return
}

func secrets(m *manifest.Manifest) (out []item) {
	for _, s := range m.Secrets {
		v := "工具看不到真值"
		if s.Visibility == "app-visible" {
			v = "工具可直接看到真值"
		}
		out = append(out, item{s.Name, fmt.Sprintf("%s → %s 的 %s 標頭（%s）", s.Name, s.Bind.Host, s.Bind.Inject.Header, v), s.Purpose})
	}
	return
}

func tools(m *manifest.Manifest) (out []item) {
	if m.AI == nil {
		return
	}
	for _, t := range m.AI.Tools {
		d := t.Name + "（風險 " + t.Risk
		if t.Gate == "consent" {
			d += "，每次需你同意"
		}
		out = append(out, item{t.Name, d + "）", "—"})
	}
	return
}

// Compare lists human-readable changes from a to b.
func Compare(a, b *manifest.Manifest) []string {
	var out []string
	out = append(out, diffSets("檔案存取", files(a), files(b))...)
	out = append(out, diffSets("對外連線", egress(a), egress(b))...)
	out = append(out, diffSets("對內連線", ingress(a), ingress(b))...)
	out = append(out, diffSets("機密", secrets(a), secrets(b))...)
	out = append(out, diffSets("AI 工具", tools(a), tools(b))...)
	budget := func(m *manifest.Manifest) string {
		if m.AI == nil || m.AI.Budget == nil {
			return "未設定"
		}
		return fmt.Sprintf("%g 美元", m.AI.Budget.DailyUSD)
	}
	if ba, bb := budget(a), budget(b); ba != bb {
		out = append(out, fmt.Sprintf("～ 每日 AI 花費上限：%s → %s", ba, bb))
	}
	if a.Runtime.Spawn != b.Runtime.Spawn {
		out = append(out, fmt.Sprintf("～ 執行其他程式：%s → %s", a.Runtime.Spawn, b.Runtime.Spawn))
	}
	if a.Runtime.Isolation != b.Runtime.Isolation {
		out = append(out, fmt.Sprintf("～ 隔離等級：%s → %s", a.Runtime.Isolation, b.Runtime.Isolation))
	}
	ra, rb := a.Runtime.Resources, b.Runtime.Resources
	if ra != rb {
		out = append(out, fmt.Sprintf("～ 資源上限：記憶體 %s→%s、程序數 %d→%d、磁碟 %s→%s", orDash(ra.Memory), orDash(rb.Memory), ra.Pids, rb.Pids, orDash(ra.Disk), orDash(rb.Disk)))
	}
	ex := func(m *manifest.Manifest) (out []item) {
		for _, e := range m.Exceptions {
			out = append(out, item{e.Rule + "|" + e.Grant, e.Rule + " @ " + e.Grant, e.Reason})
		}
		return
	}
	out = append(out, diffSets("例外", ex(a), ex(b))...)
	if a.App.Digest != b.App.Digest {
		out = append(out, "～ 應用內容已變動（內容雜湊不同）")
	}
	if len(out) == 0 {
		return nil
	}
	sa := manifest.ComputeRisk(a, nil)
	sb := manifest.ComputeRisk(b, nil)
	if sa.Level != sb.Level || sa.Score != sb.Score {
		out = append(out, fmt.Sprintf("風險等級：%s (%d) → %s (%d)", sa.Level, sa.Score, sb.Level, sb.Score))
	}
	sort.SliceStable(out, func(i, j int) bool { return rank(out[i]) < rank(out[j]) })
	return out
}

func rank(s string) int {
	switch {
	case strings.HasPrefix(s, "＋"):
		return 0
	case strings.HasPrefix(s, "～"):
		return 1
	case strings.HasPrefix(s, "－"):
		return 2
	}
	return 3
}

func orDash(s string) string {
	if s == "" {
		return "—"
	}
	return s
}
