// Package probe contains the deterministic probe suite. The agent part runs
// inside an enforce-mode shell with exactly the app's identity and tries to
// cross every boundary; the host part (in the runner) verifies the effects
// from outside. Every implemented probe must end up "blocked".
package probe

import (
	"fmt"
	"io"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
)

// Hidden argv[1] values dispatched by main.
const (
	AgentArg  = "__probe"
	NestedArg = "__probe-nested"
	SleepArg  = "__probe-sleep"
	MemArg    = "__probe-mem"
)

// Args is written by the runner into the shell's APP_DATA.
type Args struct {
	ReadPaths        []string `json:"read_paths"`
	WritePaths       []string `json:"write_paths"`
	DeletePaths      []string `json:"delete_paths"`
	ListDirs         []string `json:"list_dirs"`
	ProxyAddr        string   `json:"proxy_addr"`
	ProxyDenyTargets []string `json:"proxy_deny_targets"`
	ProxyDenyURLs    []string `json:"proxy_deny_urls"`
	DirectTargets    []string `json:"direct_targets"`
	DNSNames         []string `json:"dns_names"`
	SecretEnv        []string `json:"secret_env"`
	CanaryHashes     []string `json:"canary_hashes"`
	IngressPorts     []int    `json:"ingress_ports"`
	ReadyFile        string   `json:"ready_file"`
	DoneFile         string   `json:"done_file"`
	MemLimit         int64    `json:"mem_limit"`
	PidsLimit        int      `json:"pids_limit"`
	DiskLimit        int64    `json:"disk_limit"`
	DataDir          string   `json:"data_dir"`
	ResultFile       string   `json:"result_file"`
	Self             string   `json:"self"`
	IngressMarker    string   `json:"ingress_marker"`
}

var statusText = map[string]string{
	report.Blocked:        "已阻擋",
	report.Penetrated:     "穿透！",
	report.Error:          "錯誤",
	report.NotImplemented: "尚未實作",
}

// Print renders a probe report.
func Print(w io.Writer, r *report.Probe) {
	cat := ""
	for _, it := range r.Items {
		if it.Category != cat {
			cat = it.Category
			fmt.Fprintf(w, "【%s】\n", cat)
		}
		mark := "✔"
		switch it.Status {
		case report.Penetrated:
			mark = "✖"
		case report.Error:
			mark = "!"
		case report.NotImplemented:
			mark = "…"
		}
		fmt.Fprintf(w, "  %s %-8s %s", mark, statusText[it.Status], it.Name)
		if it.Detail != "" {
			fmt.Fprintf(w, "（%s）", it.Detail)
		}
		fmt.Fprintln(w)
	}
	b, t, n := r.Counts()
	fmt.Fprintf(w, "探針結果：%d/%d 被擋下", b, t)
	if n > 0 {
		fmt.Fprintf(w, "；另有 %d 項屬於尚未實作的閘門，未計入", n)
	}
	fmt.Fprintln(w)
	if r.AllBlocked() {
		fmt.Fprintln(w, "全部已實作的探針都被擋下。")
	} else {
		fmt.Fprintln(w, "有探針未被擋下或執行錯誤：請勿交付，先修正宣告；若宣告看起來正確仍穿透，這是核心的問題。")
	}
}
