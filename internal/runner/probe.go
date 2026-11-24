package runner

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/pcpcchen-coder/SecureAIWarp/internal/gate"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/ledger"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/netpolicy"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/probe"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/report"
	"github.com/pcpcchen-coder/SecureAIWarp/internal/state"
)

// CoreVersion is recorded in probe reports.
var CoreVersion = "0.1.0-mvp"

func gateTarget(hostport string) string {
	h, p, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return netpolicy.NormalizeHost(h) + ":" + p
}

// Probe runs the deterministic probe suite inside an enforce-mode shell
// built from the manifest, then verifies the effects from the host.
func Probe(opt Options) (*report.Probe, error) {
	if opt.Stdout == nil {
		opt.Stdout = os.Stdout
	}
	if opt.Stderr == nil {
		opt.Stderr = os.Stderr
	}
	opt.Mode = ModeProbe
	s, err := prepare(opt)
	if err != nil {
		return nil, err
	}
	defer s.close()
	s.extraBin = true

	// Decoys on the host, outside the shell.
	decoyDir, err := s.tempDir("warp-probe-decoy-")
	if err != nil {
		return nil, err
	}
	decoyKey := filepath.Join(decoyDir, ".ssh", "id_rsa")
	decoyAWS := filepath.Join(decoyDir, ".aws", "credentials")
	decoyContent := "-----BEGIN OPENSSH PRIVATE KEY-----\nwarp-decoy-" + randHex(16) + "\n-----END OPENSSH PRIVATE KEY-----\n"
	os.MkdirAll(filepath.Dir(decoyKey), 0o700)
	os.MkdirAll(filepath.Dir(decoyAWS), 0o700)
	if err := os.WriteFile(decoyKey, []byte(decoyContent), 0o600); err != nil {
		return nil, err
	}
	os.WriteFile(decoyAWS, []byte("[default]\naws_secret_access_key = warp-decoy\n"), 0o600)
	home, _ := os.UserHomeDir()
	sr, _ := state.Root()

	marker := "warp-probe-ingress-" + randHex(8)
	a := &probe.Args{
		ReadPaths: []string{decoyKey, decoyAWS, filepath.Join(home, ".ssh", "id_rsa"), filepath.Join(home, ".ssh", "id_ed25519"),
			filepath.Join(home, ".aws", "credentials"), "/etc/shadow", filepath.Join(s.appState, "ledger.jsonl"),
			filepath.Join(sr, "trace.key"), "/app/.warp/warp.yaml", filepath.Join(s.appRoot, ".warp", "warp.yaml")},
		WritePaths: []string{filepath.Join(decoyDir, "written-by-probe"), filepath.Join(home, "warp-probe-write"),
			"/etc/warp-probe", "/usr/warp-probe", "/warp-probe", "/app/warp-probe", filepath.Join(s.appRoot, "warp-probe-host"),
			filepath.Join(sr, "warp-probe")},
		DeletePaths: []string{decoyKey, filepath.Join(s.appRoot, ".warp", "warp.yaml")},
		ListDirs:    []string{home, decoyDir, sr},
		ProxyAddr:   ProxyAddr,
		ProxyDenyTargets: []string{"undeclared.warp-probe.example:443", "exfil-" + randHex(12) + ".warp-probe.example:443",
			"127.0.0.1:22", "localhost:80", "[::1]:80", "10.0.0.1:80", "192.168.1.1:80", "172.16.0.1:80",
			"100.64.0.1:80", "169.254.169.254:80", "metadata.google.internal:80", "[fd00:ec2::254]:80",
			"100.100.100.200:80", "0.0.0.0:80", "[::ffff:127.0.0.1]:80", "127.0.0.1:" + strconv.Itoa(3128)},
		ProxyDenyURLs: []string{"http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:3128/", "http://undeclared.warp-probe.example/"},
		DirectTargets: []string{"1.1.1.1:443", "8.8.8.8:53", "[2606:4700:4700::1111]:443"},
		DNSNames:      []string{"example.com", "warp-probe-" + randHex(6) + ".example.org"},
		ReadyFile:     ShellData + "/.probe-ready",
		DoneFile:      ShellData + "/.probe-done",
		DataDir:       ShellData,
		ResultFile:    ShellData + "/.probe-results.json",
		Self:          ShellBin,
		IngressMarker: marker,
	}
	for ip := range netpolicy.HostAddrs() {
		if ip.IsLoopback() {
			continue
		}
		hp := net.JoinHostPort(ip.String(), "22")
		a.ProxyDenyTargets = append(a.ProxyDenyTargets, hp)
		a.DirectTargets = append(a.DirectTargets, hp)
	}
	// Declared hosts on an undeclared port.
	for _, e := range s.m.Network.Egress {
		if strings.Contains(e.Host, "*") {
			continue
		}
		port := 22
		if e.Port == 22 {
			port = 23
		}
		a.ProxyDenyTargets = append(a.ProxyDenyTargets, net.JoinHostPort(e.Host, strconv.Itoa(port)))
	}
	for _, in := range s.m.Network.Ingress {
		a.IngressPorts = append(a.IngressPorts, in.Listen)
	}
	s.command = []string{ShellBin, probe.AgentArg, ShellData + "/.probe-args.json"}
	if err := s.plan(); err != nil {
		return nil, err
	}
	for _, b := range s.secrets {
		a.SecretEnv = append(a.SecretEnv, b.Name)
		sum := sha256.Sum256([]byte(b.Real))
		a.CanaryHashes = append(a.CanaryHashes, hex.EncodeToString(sum[:]))
	}
	res := s.resources()
	a.MemLimit, a.PidsLimit, a.DiskLimit = res.mem, res.pids, res.disk
	dataHost := s.hostDir(ShellData)
	ab, _ := json.Marshal(a)
	if err := os.WriteFile(filepath.Join(dataHost, ".probe-args.json"), ab, 0o600); err != nil {
		return nil, err
	}

	existedBefore := map[string]bool{}
	for _, p := range a.WritePaths {
		if _, err := os.Lstat(p); err == nil {
			existedBefore[p] = true
		}
	}
	fmt.Fprintln(s.opt.Stderr, "warp：探測模式：在強制模式的殼內主動嘗試越界……")
	if err := s.start(); err != nil {
		return nil, err
	}
	var hostItems []report.ProbeItem
	add := func(id, cat, name, status, detail string) {
		hostItems = append(hostItems, report.ProbeItem{ID: id, Category: cat, Name: name, Status: status, Detail: detail})
	}
	// Host-side ingress checks while the agent's listeners are up.
	if len(a.IngressPorts) > 0 {
		ready := filepath.Join(dataHost, ".probe-ready")
		deadline := time.Now().Add(30 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		for _, ig := range s.ingress {
			s.ingressChecks(ig, marker, add)
		}
		os.WriteFile(filepath.Join(dataHost, ".probe-done"), []byte("done"), 0o600)
	}
	out, ferr := s.finish()
	if ferr != nil {
		return nil, ferr
	}
	rep := &report.Probe{Core: CoreVersion, ManifestSHA256: s.loaded.SHA256, AppDigest: s.digest, RunID: s.runID,
		Identity: report.CurrentIdentity(), Resources: s.resLimits}
	rb, err := os.ReadFile(filepath.Join(dataHost, ".probe-results.json"))
	var items []report.ProbeItem
	if err != nil || json.Unmarshal(rb, &items) != nil {
		items = []report.ProbeItem{{ID: "agent", Category: "探針", Name: "殼內探針代理", Status: report.Error,
			Detail: fmt.Sprintf("沒有產生結果（結束碼 %d）", out.ExitCode)}}
	}
	// Network probes count as blocked only if the gate also logged a deny.
	denied := map[string]bool{}
	for _, e := range out.Denied {
		if e.Channel == "egress" {
			denied[e.Target] = true
		}
	}
	for i, it := range items {
		if it.Status != report.Blocked {
			continue
		}
		var tgt string
		switch {
		case strings.HasPrefix(it.ID, "net.connect:"):
			tgt = gateTarget(strings.TrimPrefix(it.ID, "net.connect:"))
		case strings.HasPrefix(it.ID, "net.http:"):
			u := strings.TrimPrefix(strings.TrimPrefix(it.ID, "net.http:"), "http://")
			hostport := strings.SplitN(u, "/", 2)[0]
			if !strings.Contains(hostport, ":") {
				hostport += ":80"
			}
			tgt = gateTarget(hostport)
		default:
			continue
		}
		if !denied[tgt] {
			items[i].Status = report.Error
			items[i].Detail += "；但帳本中沒有對應的阻擋紀錄（" + tgt + "）"
		}
	}
	// A resource probe only shows what it tested: with a per-process limit a
	// single process is stopped, but the shell as a whole is not bounded.
	for i, it := range items {
		for _, rl := range s.resLimits {
			if it.ID != "res."+rl.Resource {
				continue
			}
			switch rl.Scope {
			case report.ScopeProcess:
				items[i].Name += "（僅測單一程序）"
				items[i].Detail += "；注意：此上限以 " + rl.Mechanism + " 對每個程序個別套用，整個殼的總量未受限"
			case report.ScopeFile:
				items[i].Name += "（僅測單一檔案）"
				items[i].Detail += "；注意：此上限以 " + rl.Mechanism + " 對單一檔案套用，總寫入量未受限"
			}
		}
	}
	// Host-side file checks.
	if b, err := os.ReadFile(decoyKey); err != nil || string(b) != decoyContent {
		add("host.decoy-intact", "檔案", "殼外的誘餌憑證檔維持原狀", report.Penetrated, "誘餌檔被刪除或修改")
	} else {
		add("host.decoy-intact", "檔案", "殼外的誘餌憑證檔維持原狀", report.Blocked, "")
	}
	appeared := []string{}
	for _, p := range a.WritePaths {
		if _, err := os.Lstat(p); err == nil && !existedBefore[p] {
			appeared = append(appeared, p)
			os.Remove(p)
		}
	}
	add("host.no-writes", "檔案", "主機上沒有出現殼內寫入的檔案", blockedIf(len(appeared) == 0), strings.Join(appeared, ", "))
	if v, err := ledger.Verify(out.LedgerPath); err != nil {
		add("ledger.chain", "帳本", "稽核帳本雜湊鏈完整", report.Penetrated, err.Error())
	} else {
		add("ledger.chain", "帳本", "稽核帳本雜湊鏈完整", report.Blocked, fmt.Sprintf("%d 筆", v.Entries))
	}
	rep.Items = append(items, hostItems...)
	for _, it := range rep.Items {
		dec := map[string]string{report.Blocked: "deny", report.Penetrated: "allow"}[it.Status]
		if dec == "" {
			dec = "info"
		}
		s.led.Log("probe", it.ID, dec, it.Name, it.Status)
	}
	if err := report.WriteProbe(s.appRoot, rep); err != nil {
		return rep, err
	}
	return rep, nil
}

func (s *session) ingressChecks(ig *gate.Ingress, marker string, add func(id, cat, name, status, detail string)) {
	base := fmt.Sprintf("http://127.0.0.1:%d/", ig.HostPort)
	client := &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	get := func(url string, hdr map[string]string, host string) (int, string, error) {
		req, _ := http.NewRequest("GET", url, nil)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", err
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return resp.StatusCode, string(b), nil
	}
	p := strconv.Itoa(ig.InnerPort)
	st, body, err := get(base, nil, "")
	add("ingress.no-token:"+p, "對內", "不帶權杖從主機連入 "+p+" 埠", blockedIf(err == nil && st == 401 && !strings.Contains(body, marker)), fmt.Sprintf("HTTP %d %v", st, errOrNil(err)))
	st, body, err = get(base, map[string]string{gate.TokenHeader: "wrong-" + randHex(8)}, "")
	add("ingress.bad-token:"+p, "對內", "以錯誤權杖連入 "+p+" 埠", blockedIf(err == nil && st == 401 && !strings.Contains(body, marker)), fmt.Sprintf("HTTP %d %v", st, errOrNil(err)))
	st, body, err = get(base, map[string]string{gate.TokenHeader: ig.Token}, "attacker.example:"+strconv.Itoa(ig.HostPort))
	add("ingress.rebind-host:"+p, "對內", "以偽造的 Host 標頭（DNS rebinding）連入 "+p+" 埠", blockedIf(err == nil && st == 403 && !strings.Contains(body, marker)), fmt.Sprintf("HTTP %d %v", st, errOrNil(err)))
	st, body, err = get(base, map[string]string{gate.TokenHeader: ig.Token}, "")
	ctl := report.Blocked
	detail := "正確權杖可正常連入（對照組）"
	if err != nil || st != 200 || !strings.Contains(body, marker) {
		ctl = report.Error
		detail = fmt.Sprintf("對照組失敗：HTTP %d %v", st, errOrNil(err))
	}
	add("ingress.control:"+p, "對內", "對內閘門對照組（正確權杖）", ctl, detail)
	if ig.HostPort != ig.InnerPort {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+p, 2*time.Second)
		reached := false
		if err == nil {
			fmt.Fprintf(c, "GET / HTTP/1.0\r\n\r\n")
			c.SetReadDeadline(time.Now().Add(2 * time.Second))
			b, _ := io.ReadAll(io.LimitReader(c, 4096))
			reached = strings.Contains(string(b), marker)
			c.Close()
		}
		add("ingress.direct:"+p, "對內", "不經閘門直接連到殼內的 "+p+" 埠", blockedIf(!reached), "")
	}
}

func blockedIf(ok bool) string {
	if ok {
		return report.Blocked
	}
	return report.Penetrated
}

func errOrNil(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
